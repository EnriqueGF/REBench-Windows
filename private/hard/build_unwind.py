"""Build a MASM PE64 with real .pdata/.xdata and inspect its unwind record."""

from __future__ import annotations

import struct
import subprocess

try:
    from .build_hard import ROOT, HERE, symbol_rva, vs_environment
except ImportError:
    from build_hard import ROOT, HERE, symbol_rva, vs_environment


def build_unwind():
    env, compiler = vs_environment()
    assembler = compiler.with_name("ml64.exe")
    asm_obj = HERE / "unwind_target.obj"
    assembled = subprocess.run([str(assembler), "/nologo", "/c", f"/Fo{asm_obj}",
                                str(HERE / "unwind_target.asm")], cwd=HERE, env=env,
                               capture_output=True, text=True, encoding="mbcs", errors="replace")
    if assembled.returncode:
        raise RuntimeError("MASM failed: " + assembled.stdout[-1500:] + assembled.stderr[-1500:])
    exe = ROOT / "public" / "artifacts" / "hard_unwind" / "unwind_probe.exe"
    exe.parent.mkdir(parents=True, exist_ok=True)
    c_obj = HERE / "unwind_probe.obj"
    compiled = subprocess.run([str(compiler), "/nologo", "/O2", "/MT",
                               f"/Fo{c_obj}", f"/Fe{exe}", str(HERE / "unwind_probe.c"), str(asm_obj),
                               "/link", "/DEBUG:NONE", f"/MAP:{HERE / 'unwind_probe.map'}"],
                              cwd=HERE, env=env, capture_output=True, text=True,
                              encoding="mbcs", errors="replace")
    if compiled.returncode:
        raise RuntimeError("Unwind fixture link failed: " + compiled.stdout[-1500:] + compiled.stderr[-1500:])
    run = subprocess.run([str(exe)], capture_output=True, text=True)
    wanted = ((0x1234 ^ 0x5678) + 0x0123456789ABCDEF) & ((1 << 64) - 1)
    if run.returncode or run.stdout.strip() != f"{wanted:016X}":
        raise RuntimeError("Unwind fixture executable failed")
    target_rva = symbol_rva("unwind_probe", "unwind_target")

    raw = exe.read_bytes()
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    if raw[:2] != b"MZ" or raw[pe:pe + 4] != b"PE\0\0":
        raise RuntimeError("Invalid PE")
    optional = pe + 24
    pdata_rva, pdata_size = struct.unpack_from("<II", raw, optional + 112 + 3 * 8)
    sections = optional + struct.unpack_from("<H", raw, pe + 20)[0]
    section_count = struct.unpack_from("<H", raw, pe + 6)[0]

    def at_rva(rva):
        for index in range(section_count):
            section = sections + index * 40
            virtual_size, va, raw_size, pointer = struct.unpack_from("<IIII", raw, section + 8)
            if va <= rva < va + min(virtual_size, raw_size):
                return pointer + rva - va
        raise RuntimeError(f"RVA {rva:#x} has no file backing")

    record = None
    for index in range(pdata_size // 12):
        begin, end, unwind_rva = struct.unpack_from("<III", raw, at_rva(pdata_rva + 12 * index))
        if begin == target_rva:
            record = (begin, end, unwind_rva)
            break
    if record is None:
        raise RuntimeError("RUNTIME_FUNCTION for MASM procedure missing")
    unwind_rva = record[2]
    location = at_rva(unwind_rva)
    header = raw[location:location + 4]
    version, flags = header[0] & 7, header[0] >> 3
    prolog_size, code_slots = header[1], header[2]
    frame_reg, frame_offset = header[3] & 0xF, header[3] >> 4
    if version != 1 or flags != 0 or frame_reg != 5 or frame_offset != 2:
        raise RuntimeError("Unexpected unwind frame header")
    codes = []
    for index in range(code_slots):
        code_offset, packed = struct.unpack_from("<BB", raw, location + 4 + 2 * index)
        codes.append((code_offset, packed & 0xF, packed >> 4))
    alloc_size = None
    for index, (_, operation, info) in enumerate(codes):
        if operation == 1 and info == 0:
            scaled = struct.unpack_from("<H", raw, location + 4 + 2 * (index + 1))[0]
            alloc_size = scaled * 8
        if operation == 2:
            alloc_size = info * 8 + 8
    if alloc_size != 0x88:
        raise RuntimeError(f"Unexpected allocation: {alloc_size}")
    return {"exe": exe, "target_rva": target_rva, "end_rva": record[1],
            "unwind_rva": unwind_rva, "prolog_size": prolog_size,
            "code_slots": code_slots, "frame_register": frame_reg,
            "frame_offset": frame_offset, "alloc_size": alloc_size,
            "codes": codes}


if __name__ == "__main__":
    info = build_unwind()
    print("Built", info["exe"], "target RVA", hex(info["target_rva"]),
          "unwind RVA", hex(info["unwind_rva"]), "codes", info["codes"])
