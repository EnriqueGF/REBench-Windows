"""Create and inspect a real x64 Windows minidump of a pointer truncation fault."""

from __future__ import annotations

import re
import struct
import subprocess

try:
    from .build_hard import ROOT, HERE, symbol_rva, vs_environment
except ImportError:
    from build_hard import ROOT, HERE, symbol_rva, vs_environment

COOKIE = 0xA5C39E7D51B20F46
SEED = 0x39B74A1ED5C2608F
MASK = (1 << 64) - 1


def parse_dump(path):
    raw = path.read_bytes()
    if len(raw) < 32 or raw[:4] != b"MDMP":
        raise RuntimeError("No minidump header")
    streams, directory = struct.unpack_from("<II", raw, 8)
    records = {}
    for i in range(streams):
        kind, size, rva = struct.unpack_from("<III", raw, directory + 12 * i)
        if rva + size > len(raw):
            raise RuntimeError("Truncated minidump stream")
        records[kind] = (rva, size)
    if 6 not in records or 4 not in records or 3 not in records:
        raise RuntimeError("Expected exception, module and thread streams")
    exception = records[6][0]
    code = struct.unpack_from("<I", raw, exception + 8)[0]
    address = struct.unpack_from("<Q", raw, exception + 24)[0]
    parameter_count = struct.unpack_from("<I", raw, exception + 32)[0]
    access, fault = struct.unpack_from("<QQ", raw, exception + 40)
    modules = records[4][0]
    count = struct.unpack_from("<I", raw, modules)[0]
    module_base = None
    for index in range(count):
        position = modules + 4 + 108 * index
        base, size = struct.unpack_from("<QI", raw, position)
        if base <= address < base + size:
            module_base = base
            break
    if code != 0xC0000005 or parameter_count < 2 or module_base is None:
        raise RuntimeError("Unexpected exception record")
    return {"raw": raw, "code": code, "address": address, "rva": address - module_base,
            "access": access, "fault": fault, "module_base": module_base,
            "thread_count": struct.unpack_from("<I", raw, records[3][0])[0]}


def build_dump():
    env, compiler = vs_environment()
    exe = ROOT / "public" / "artifacts" / "hard_dump" / "dump_probe.exe"
    dump = ROOT / "public" / "artifacts" / "hard_dump" / "fault.dmp"
    exe.parent.mkdir(parents=True, exist_ok=True)
    built = subprocess.run([str(compiler), "/nologo", "/O2", "/Ob0", "/GS-", "/MT",
                            f"/Fo{HERE / 'dump_probe.obj'}", f"/Fe{exe}",
                            str(HERE / "dump_probe.c"),
                            "/link", "/DEBUG:NONE", f"/MAP:{HERE / 'dump_probe.map'}"],
                           cwd=HERE, env=env, capture_output=True, text=True,
                           encoding="mbcs", errors="replace")
    if built.returncode:
        raise RuntimeError("Dump PE build failed: " + built.stdout[-2000:] + built.stderr[-2000:])
    run = subprocess.run([str(exe), str(dump)], capture_output=True, text=True, timeout=30)
    if run.returncode or "dump=1" not in run.stdout:
        raise RuntimeError("Could not capture dump: " + run.stdout + run.stderr)
    match = re.search(r"exception=([0-9A-Fa-f]+) address=([0-9A-Fa-f]+) fault=([0-9A-Fa-f]+) mode=(\d+) expected=([0-9A-Fa-f]+)", run.stdout)
    if not match:
        raise RuntimeError("Invalid capture summary: " + run.stdout)
    output_code, ip, fault, access, pointer = (int(value, 16 if index != 3 else 10)
                                               for index, value in enumerate(match.groups()))
    parsed = parse_dump(dump)
    if (parsed["code"], parsed["address"], parsed["fault"], parsed["access"]) != \
       (output_code, ip, fault, access):
        raise RuntimeError("Dump exception does not match capture summary")
    if access != 0 or pointer <= 0xFFFFFFFF or fault != (pointer & 0xFFFFFFFF) + 3:
        raise RuntimeError("Pointer truncation not observed")
    if struct.pack("<Q", pointer ^ COOKIE) not in parsed["raw"]:
        raise RuntimeError("Encoded pointer missing from dump memory")
    result = (((SEED ^ (3 * 17 + 3)) + (7 * 17 + 3) + 7) & MASK) ^ SEED
    fixed_exe = HERE / "hidden" / "dump_probe_fixed.exe"
    fixed_exe.parent.mkdir(parents=True, exist_ok=True)
    fixed_build = subprocess.run([str(compiler), "/nologo", "/O2", "/Ob0", "/GS-", "/MT",
                                  "/DFIXED_POINTER", "/DPRINT_RESULT",
                                  f"/Fo{HERE / 'dump_probe_fixed.obj'}", f"/Fe{fixed_exe}",
                                  str(HERE / "dump_probe.c"), "/link", "/DEBUG:NONE"],
                                 cwd=HERE, env=env, capture_output=True, text=True,
                                 encoding="mbcs", errors="replace")
    if fixed_build.returncode:
        raise RuntimeError("Fixed PE build failed: " + fixed_build.stdout[-1000:] + fixed_build.stderr[-1000:])
    fixed_run = subprocess.run([str(fixed_exe), str(HERE / "hidden" / "unused.dmp")],
                               capture_output=True, text=True, timeout=30)
    if fixed_run.returncode or fixed_run.stdout.strip() != f"result={result:016X}":
        raise RuntimeError("Fixed PE result mismatch: " + fixed_run.stdout + fixed_run.stderr)
    return {"exe": exe, "dump": dump, "exception_code": output_code,
            "fault_rva": parsed["rva"], "fault_address": fault,
            "allocation": pointer, "encoded": pointer ^ COOKIE, "cookie": COOKIE,
            "access": access, "resolve_rva": symbol_rva("dump_probe", "resolve_payload"),
            "consume_rva": symbol_rva("dump_probe", "consume_payload"),
            "dispatch_rva": symbol_rva("dump_probe", "dispatch_job"),
            "fixed_result": result, "thread_count": parsed["thread_count"]}


if __name__ == "__main__":
    info = build_dump()
    print("Built", info["dump"], "bytes", info["dump"].stat().st_size,
          "fault RVA", hex(info["fault_rva"]), "fault VA", hex(info["fault_address"]))
