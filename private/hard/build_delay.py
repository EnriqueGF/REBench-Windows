"""Build and parse a real MSVC delay-load PE64 with an unload table."""

from __future__ import annotations

import struct
import subprocess
from pathlib import Path

try:
    from .build_hard import ROOT, HERE, vs_environment
except ImportError:
    from build_hard import ROOT, HERE, vs_environment


def build_delay():
    env, compiler = vs_environment()
    source = HERE / "delay_probe.c"
    exe = ROOT / "public" / "artifacts" / "hard_delay" / "delay_probe.exe"
    exe.parent.mkdir(parents=True, exist_ok=True)
    command = [str(compiler), "/nologo", "/O2", "/MT", "/D_CRT_SECURE_NO_WARNINGS",
               f"/Fo{HERE / 'delay_probe.obj'}", f"/Fe{exe}", str(source),
               "/link", "/DEBUG:NONE", f"/MAP:{HERE / 'delay_probe.map'}",
               "/DELAYLOAD:USER32.dll", "/DELAY:UNLOAD", "delayimp.lib", "user32.lib"]
    built = subprocess.run(command, cwd=HERE, env=env, capture_output=True,
                           text=True, encoding="mbcs", errors="replace")
    if built.returncode:
        raise RuntimeError("Delay fixture compile failed: " + built.stdout[-2000:] + built.stderr[-2000:])
    process = subprocess.run([str(exe)], capture_output=True, text=True)
    if process.returncode or "unloaded=1" not in process.stdout:
        raise RuntimeError("Delay fixture did not load/unload/reload: " + process.stdout + process.stderr)

    raw = exe.read_bytes()
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    if raw[:2] != b"MZ" or raw[pe:pe + 4] != b"PE\0\0":
        raise RuntimeError("Invalid PE")
    optional = pe + 24
    image_base = struct.unpack_from("<Q", raw, optional + 24)[0]
    directory_rva, directory_size = struct.unpack_from("<II", raw, optional + 112 + 13 * 8)
    if not directory_rva or directory_size < 32:
        raise RuntimeError("Delay import directory missing")
    sections = optional + struct.unpack_from("<H", raw, pe + 20)[0]
    count = struct.unpack_from("<H", raw, pe + 6)[0]

    def at_rva(rva):
        for index in range(count):
            section = sections + index * 40
            virtual_size, va, raw_size, pointer = struct.unpack_from("<IIII", raw, section + 8)
            if va <= rva < va + min(virtual_size, raw_size):
                return pointer + rva - va
        raise RuntimeError(f"RVA {rva:#x} has no file backing")

    def cstring(offset):
        end = raw.index(b"\0", offset)
        return raw[offset:end].decode("ascii")

    descriptor = None
    descriptor_rva = None
    for index in range(directory_size // 32):
        current_rva = directory_rva + 32 * index
        fields = struct.unpack_from("<8I", raw, at_rva(current_rva))
        if fields == (0,) * 8:
            break
        if fields[0] == 1 and cstring(at_rva(fields[1])).casefold() == "user32.dll":
            descriptor, descriptor_rva = fields, current_rva
            break
    if descriptor is None:
        raise RuntimeError("USER32 delay descriptor missing")
    attrs, dll_name, phmod, iat, name_table, bound, unload, timestamp = descriptor
    if not unload or not iat or not name_table:
        raise RuntimeError("Expected IAT/INT/UIAT fields missing")
    first_name_rva = struct.unpack_from("<Q", raw, at_rva(name_table))[0]
    import_name = cstring(at_rva(first_name_rva) + 2)
    first_iat = struct.unpack_from("<Q", raw, at_rva(iat))[0]
    first_unload = struct.unpack_from("<Q", raw, at_rva(unload))[0]
    if first_iat != first_unload:
        raise RuntimeError("UIAT does not copy initial IAT")
    return {"exe": exe, "image_base": image_base, "directory_rva": directory_rva,
            "descriptor_rva": descriptor_rva, "attrs": attrs, "name_rva": dll_name,
            "phmod_rva": phmod, "iat_rva": iat, "int_rva": name_table,
            "bound_rva": bound, "unload_rva": unload, "unload_file_offset": at_rva(unload),
            "import_name": import_name, "first_iat": first_iat}


if __name__ == "__main__":
    info = build_delay()
    print("Built", info["exe"], "descriptor", hex(info["descriptor_rva"]),
          "IAT", hex(info["iat_rva"]), "UIAT", hex(info["unload_rva"]),
          "import", info["import_name"])
