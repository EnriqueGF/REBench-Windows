"""Build four PE64 versions with two one-byte conditional-branch defects."""

from __future__ import annotations

import random
import struct
import subprocess
import tempfile
from pathlib import Path

try:
    from .build_hard import ROOT, HERE, symbol_rva, vs_environment
except ImportError:
    from build_hard import ROOT, HERE, symbol_rva, vs_environment


def pe_text(path):
    raw = path.read_bytes()
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    if raw[:2] != b"MZ" or raw[pe:pe + 4] != b"PE\0\0":
        raise RuntimeError("Invalid PE")
    sections = pe + 24 + struct.unpack_from("<H", raw, pe + 20)[0]
    count = struct.unpack_from("<H", raw, pe + 6)[0]
    for i in range(count):
        offset = sections + 40 * i
        if raw[offset:offset + 8].rstrip(b"\0") == b".text":
            rva, size, pointer = struct.unpack_from("<III", raw, offset + 12)
            return raw, rva, pointer, raw[pointer:pointer + size]
    raise RuntimeError("No .text")


def vectors():
    pairs = [(x, y) for x in (0, 1, 0xFF, 0x100, 0x101)
             for y in (0, 1, 0x20, 0x21)]
    rng = random.Random(0x20271006)
    pairs += [(rng.randrange(0x120), rng.randrange(0x40)) for _ in range(18)]
    return pairs


def accepted(x, y):
    return x <= 0x100 and (y & 0x20) != 0 and ((x ^ y) & 1) == 0


def scan(code, pattern):
    hits = []
    for pos in range(len(code) - len(pattern) + 1):
        if all(byte is None or code[pos + i] == byte for i, byte in enumerate(pattern)):
            hits.append(pos)
            if len(hits) > 1:
                break
    return hits


def common_pattern(versions, site_name):
    for before in (6, 5, 4, 3, 2, 1, 0, 8, 10):
        for length in (20, 24, 28, 32, 40):
            samples = []
            for item in versions:
                _, text_rva, _, code = pe_text(item["exe"])
                start = item[site_name] - before - text_rva
                if start < 0 or start + length > len(code):
                    break
                samples.append(code[start:start + length])
            if len(samples) != 4:
                continue
            pattern = [sample[0] if all(row[index] == sample[0] for row in samples)
                       else None for index, sample in enumerate(zip(*samples))]
            if sum(x is not None for x in pattern) < 8:
                continue
            if all(scan(pe_text(item["exe"])[3], pattern) ==
                   [item[site_name] - before - pe_text(item["exe"])[1]]
                   for item in versions):
                return {"pattern": " ".join("??" if x is None else f"{x:02X}" for x in pattern),
                        "offset": before}
    raise RuntimeError("No stable unique patch signature for " + site_name)


def build_repair():
    env, compiler = vs_environment()
    assembler = compiler.with_name("ml64.exe")
    asm_obj = HERE / "repair_target.obj"
    result = subprocess.run([str(assembler), "/nologo", "/c", f"/Fo{asm_obj}",
                             str(HERE / "repair_target.asm")], cwd=HERE, env=env,
                            capture_output=True, text=True, encoding="mbcs", errors="replace")
    if result.returncode:
        raise RuntimeError("MASM failed: " + result.stdout[-1000:] + result.stderr[-1000:])
    versions = []
    for version in range(1, 5):
        stem = f"repair_v{version}"
        exe = (ROOT / "public" / "artifacts" / "hard_repair" / f"{stem}.exe"
               if version < 4 else HERE / "hidden" / f"{stem}.exe")
        exe.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run([str(compiler), "/nologo", "/O2", "/Ob0", "/MT",
                                 f"/DVARIANT={version}", f"/Fo{HERE / (stem + '.obj')}",
                                 f"/Fe{exe}", str(HERE / "repair_probe.c"), str(asm_obj),
                                 "/link", "/DEBUG:NONE", f"/MAP:{HERE / (stem + '.map')}"],
                                cwd=HERE, env=env, capture_output=True, text=True,
                                encoding="mbcs", errors="replace")
        if result.returncode:
            raise RuntimeError(f"Build v{version} failed: " + result.stdout[-1000:] + result.stderr[-1000:])
        item = {"version": version, "exe": exe,
                "len_rva": symbol_rva(stem, "bad_length_branch"),
                "flag_rva": symbol_rva(stem, "bad_flag_branch"),
                "function_rva": symbol_rva(stem, "check_record")}
        raw, text_rva, pointer, code = pe_text(exe)
        if code[item["len_rva"] - text_rva] != 0x73 or code[item["flag_rva"] - text_rva] != 0x75:
            raise RuntimeError("Unexpected JCC encoding")
        versions.append(item)
    if len({item["function_rva"] for item in versions}) < 3:
        raise RuntimeError("Versions did not vary code layout enough")
    for item in versions:
        raw, text_rva, pointer, _ = pe_text(item["exe"])
        patched = bytearray(raw)
        patched[pointer + item["len_rva"] - text_rva] = 0x77
        patched[pointer + item["flag_rva"] - text_rva] = 0x74
        with tempfile.TemporaryDirectory(prefix="rebench-repair-") as folder:
            fixed = Path(folder) / "fixed.exe"
            fixed.write_bytes(patched)
            wrong_count = 0
            for x, y in vectors():
                expected = "ACCEPT" if accepted(x, y) else "REJECT"
                good = subprocess.run([str(fixed), hex(x), hex(y)], capture_output=True, text=True)
                if good.returncode or good.stdout.strip() != expected:
                    raise RuntimeError(f"Patched v{item['version']} failed {x:#x},{y:#x}")
                broken = subprocess.run([str(item["exe"]), hex(x), hex(y)],
                                        capture_output=True, text=True)
                if broken.returncode or broken.stdout.strip() != expected:
                    wrong_count += 1
            if wrong_count < 3:
                raise RuntimeError("Broken build is not observably defective")
    length = common_pattern(versions, "len_rva")
    flag = common_pattern(versions, "flag_rva")
    length["byte"] = "77"
    flag["byte"] = "74"
    return {"versions": versions, "canonical": {"sites": {"length": length, "flag": flag}},
            "sample": [(hex(x), hex(y), "ACCEPT" if accepted(x, y) else "REJECT")
                       for x, y in vectors()[:8]]}


if __name__ == "__main__":
    info = build_repair()
    print("Built", [(v["version"], hex(v["len_rva"]), hex(v["flag_rva"]))
                    for v in info["versions"]], info["canonical"])
