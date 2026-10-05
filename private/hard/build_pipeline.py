"""Compile and describe a PE64 function-recovery challenge."""

from __future__ import annotations

import subprocess
from pathlib import Path

try:
    from .build_hard import ROOT, HERE, compile_c, symbol_rva
except ImportError:  # direct authoring invocation
    from build_hard import ROOT, HERE, compile_c, symbol_rva

MASK = (1 << 64) - 1
KEYS = [
    0xD6E8FEB86659FD93,
    0x9E3779B185EBCA87,
    0xA0761D6478BD642F,
    0xE7037ED1A0B428DB,
    0x8EBC6AF09C88C6E3,
    0xC2B2AE3D27D4EB4F,
]


def rol(value: int, count: int) -> int:
    return ((value << count) | (value >> (64 - count))) & MASK


def ror(value: int, count: int) -> int:
    return ((value >> count) | (value << (64 - count))) & MASK


def reference(x: int, y: int) -> int:
    a = rol(x ^ KEYS[0], 13)
    b = (y * KEYS[1] + KEYS[2]) & MASK
    v = (a + b) & MASK
    if (x ^ y) & 0x20:
        v = rol(v ^ KEYS[3], 17)
    else:
        v = ror((v + KEYS[4]) & MASK, 9)
    return (v ^ (((x + y) * KEYS[5]) & MASK)) & MASK


def reference_program():
    return {
        "steps": [
            {"dst": "r0", "op": "xor", "a": "x", "b": hex(KEYS[0])},
            {"dst": "r0", "op": "rol", "a": "r0", "bits": 13},
            {"dst": "r1", "op": "mul", "a": "y", "b": hex(KEYS[1])},
            {"dst": "r1", "op": "add", "a": "r1", "b": hex(KEYS[2])},
            {"dst": "r2", "op": "add", "a": "r0", "b": "r1"},
            {"dst": "r3", "op": "xor", "a": "x", "b": "y"},
            {"dst": "r3", "op": "and", "a": "r3", "b": "0x20"},
            {"dst": "r4", "op": "xor", "a": "r2", "b": hex(KEYS[3])},
            {"dst": "r4", "op": "rol", "a": "r4", "bits": 17},
            {"dst": "r5", "op": "add", "a": "r2", "b": hex(KEYS[4])},
            {"dst": "r5", "op": "ror", "a": "r5", "bits": 9},
            {"dst": "r6", "op": "sel", "cond": "r3", "a": "r4", "b": "r5"},
            {"dst": "r7", "op": "add", "a": "x", "b": "y"},
            {"dst": "r7", "op": "mul", "a": "r7", "b": hex(KEYS[5])},
            {"dst": "r8", "op": "xor", "a": "r6", "b": "r7"},
        ],
        "return": "r8",
    }


def pipeline_case():
    exe = ROOT / "public" / "artifacts" / "hard_pipeline" / "mix_oracle.exe"
    compile_c(HERE / "mix_oracle.c", exe)
    pairs = [(0, 0), (1, 2), (0x0123456789ABCDEF, 0xFEDCBA9876543210),
             (0xFFFFFFFFFFFFFFFF, 0x0), (0x20, 0)]
    for x, y in pairs:
        result = subprocess.run([str(exe), hex(x), hex(y)], capture_output=True, text=True)
        if result.returncode or int(result.stdout.strip(), 16) != reference(x, y):
            raise RuntimeError(f"Pipeline fixture mismatch for {x:#x},{y:#x}")
    return {"exe": exe, "program": reference_program(), "function_rva": symbol_rva("mix_oracle", "mix_payload"),
            "branch_mask": 0x20, "sample": reference(pairs[2][0], pairs[2][1])}


if __name__ == "__main__":
    info = pipeline_case()
    print("Built", info["exe"], "function RVA", hex(info["function_rva"]))
