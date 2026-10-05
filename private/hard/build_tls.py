"""Build a Windows PE64 whose live transform depends on a TLS callback."""

from __future__ import annotations

import random
import struct
import subprocess
from pathlib import Path

try:
    from .build_hard import ROOT, HERE, compile_c, symbol_rva
except ImportError:
    from build_hard import ROOT, HERE, compile_c, symbol_rva

MASK = (1 << 64) - 1
SEED = 0xF1357AEA2E62A9C5
KEYS = [
    0x4CF5AD432745937F, 0xE97B1D0F83AC6B29,
    0xC13FA9A902A6328F, 0x7B4D3BE2A5ED7D63,
    0xD0ED6F7758FB31A9, 0x2B6D85FE993CE12D,
    0x8A6E52342D9AFC71, 0xF963B3D5C6A98E4B,
]
MULS = [0x9E3779B185EBCA87, 0xC2B2AE3D27D4EB4F,
        0xD6E8FEB86659FD93, 0xA24BAED4963EE407]
FINAL = 0x8CB92BA72F3D8DD7


def rol(value: int, bits: int) -> int:
    return ((value << bits) | (value >> (64 - bits))) & MASK


def ror(value: int, bits: int) -> int:
    return ((value >> bits) | (value << (64 - bits))) & MASK


def cipher_keys():
    state = SEED
    encrypted = []
    for index, key in enumerate(KEYS):
        state ^= (state << 13) & MASK
        state ^= state >> 7
        state ^= (state << 17) & MASK
        state = (rol(state, 11) * 0x94D049BB133111EB +
                 0xD1B54A32D192ED03 + index) & MASK
        encrypted.append(key ^ state)
    return encrypted


def reference(x: int, y: int) -> int:
    a = x ^ KEYS[0]
    b = (y + KEYS[1]) & MASK
    for index in range(8):
        u = ((a + rol(b, 11)) ^ KEYS[index]) & MASK
        yes = rol(u, 13)
        no = ror(u ^ KEYS[(index + 3) & 7], 17)
        a = yes if (u ^ x) & 0x200 else no
        b = ((b ^ a) * MULS[index & 3] + KEYS[(index + 5) & 7]) & MASK
    return (a ^ rol(b, 23) ^ ((x * y * FINAL) & MASK)) & MASK


def reference_program():
    return {"tables": {"keys": [hex(v) for v in KEYS], "muls": [hex(v) for v in MULS]},
            "steps": [
                {"dst": "r0", "op": "lookup", "table": "keys", "index": "0x0"},
                {"dst": "r0", "op": "xor", "a": "x", "b": "r0"},
                {"dst": "r1", "op": "lookup", "table": "keys", "index": "0x1"},
                {"dst": "r1", "op": "add", "a": "y", "b": "r1"},
                {"op": "loop", "count": 8, "body": [
                    {"dst": "r2", "op": "rol", "a": "r1", "bits": 11},
                    {"dst": "r2", "op": "add", "a": "r0", "b": "r2"},
                    {"dst": "r3", "op": "lookup", "table": "keys", "index": "i"},
                    {"dst": "r2", "op": "xor", "a": "r2", "b": "r3"},
                    {"dst": "r4", "op": "xor", "a": "r2", "b": "x"},
                    {"dst": "r4", "op": "and", "a": "r4", "b": "0x200"},
                    {"dst": "r5", "op": "rol", "a": "r2", "bits": 13},
                    {"dst": "r6", "op": "add", "a": "i", "b": "0x3"},
                    {"dst": "r6", "op": "lookup", "table": "keys", "index": "r6"},
                    {"dst": "r6", "op": "xor", "a": "r2", "b": "r6"},
                    {"dst": "r6", "op": "ror", "a": "r6", "bits": 17},
                    {"dst": "r0", "op": "sel", "cond": "r4", "a": "r5", "b": "r6"},
                    {"dst": "r1", "op": "xor", "a": "r1", "b": "r0"},
                    {"dst": "r7", "op": "lookup", "table": "muls", "index": "i"},
                    {"dst": "r1", "op": "mul", "a": "r1", "b": "r7"},
                    {"dst": "r8", "op": "add", "a": "i", "b": "0x5"},
                    {"dst": "r8", "op": "lookup", "table": "keys", "index": "r8"},
                    {"dst": "r1", "op": "add", "a": "r1", "b": "r8"},
                ]},
                {"dst": "r2", "op": "rol", "a": "r1", "bits": 23},
                {"dst": "r0", "op": "xor", "a": "r0", "b": "r2"},
                {"dst": "r3", "op": "mul", "a": "x", "b": "y"},
                {"dst": "r3", "op": "mul", "a": "r3", "b": hex(FINAL)},
                {"dst": "r0", "op": "xor", "a": "r0", "b": "r3"},
            ], "return": "r0"}


def pe_tls_callbacks(path: Path):
    raw = path.read_bytes()
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    if raw[:2] != b"MZ" or raw[pe:pe + 4] != b"PE\0\0":
        raise RuntimeError("Invalid PE")
    optional = pe + 24
    image_base = struct.unpack_from("<Q", raw, optional + 24)[0]
    tls_rva, tls_size = struct.unpack_from("<II", raw, optional + 112 + 9 * 8)
    if not tls_rva or tls_size < 40:
        raise RuntimeError("TLS directory missing")
    sections = optional + struct.unpack_from("<H", raw, pe + 20)[0]
    count = struct.unpack_from("<H", raw, pe + 6)[0]

    def at_rva(rva):
        for index in range(count):
            section = sections + index * 40
            virtual_size, va, raw_size, pointer = struct.unpack_from("<IIII", raw, section + 8)
            if va <= rva < va + max(virtual_size, raw_size):
                return pointer + rva - va
        raise RuntimeError(f"RVA {rva:#x} not mapped")

    directory = at_rva(tls_rva)
    callbacks_va = struct.unpack_from("<Q", raw, directory + 24)[0]
    callbacks_offset = at_rva(callbacks_va - image_base)
    values = []
    for index in range(16):
        value = struct.unpack_from("<Q", raw, callbacks_offset + index * 8)[0]
        if not value:
            break
        values.append(value - image_base)
    return values


def tls_case():
    encrypted = cipher_keys()
    header = HERE / "tls_payload.h"
    header.write_text("\n".join([
        "#pragma once", f"#define TLS_SEED 0x{SEED:016X}ULL",
        "static const uint64_t TLS_CIPHER[8] = {" + ",".join(f"0x{x:016X}ULL" for x in encrypted) + "};",
        "",
    ]), encoding="utf-8")
    exe = ROOT / "public" / "artifacts" / "hard_tls" / "tls_oracle.exe"
    compile_c(HERE / "tls_oracle.c", exe)
    callback_rva = symbol_rva("tls_oracle", "tls_init")
    function_rva = symbol_rva("tls_oracle", "mix_tls")
    if callback_rva not in pe_tls_callbacks(exe):
        raise RuntimeError("TLS callback not registered in PE directory")
    pairs = [(0, 0), (1, 2), (0x200, 0), (MASK, MASK),
             (0x0123456789ABCDEF, 0xFEDCBA9876543210)]
    rng = random.Random(0x20261005)
    pairs += [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(12)]
    for x, y in pairs:
        result = subprocess.run([str(exe), hex(x), hex(y)], capture_output=True, text=True)
        if result.returncode or int(result.stdout.strip(), 16) != reference(x, y):
            raise RuntimeError(f"TLS fixture mismatch for {x:#x},{y:#x}: {result.stdout!r}, {result.stderr!r}")
    if any(struct.pack("<Q", key) in exe.read_bytes() for key in KEYS):
        raise RuntimeError("Plaintext TLS key leaked in binary")
    return {"exe": exe, "program": reference_program(), "callback_rva": callback_rva,
            "function_rva": function_rva, "sample": reference(pairs[4][0], pairs[4][1]),
            "key0": KEYS[0], "seed": SEED}


if __name__ == "__main__":
    info = tls_case()
    print("Built", info["exe"], "TLS callback RVA", hex(info["callback_rva"]),
          "function RVA", hex(info["function_rva"]))
