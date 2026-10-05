"""Build a PE64 stream oracle with encrypted keys in a Windows RCDATA resource."""

from __future__ import annotations

import random
import re
import struct
import subprocess
from pathlib import Path

try:
    from .build_hard import ROOT, HERE, symbol_rva, vs_environment
except ImportError:
    from build_hard import ROOT, HERE, symbol_rva, vs_environment

MASK = (1 << 64) - 1
SEED = 0x8A3D3E9B1C64C291
KEYS = [random.Random(0x51EA2027 + i * 0x9E37).getrandbits(64) | 1 for i in range(16)]
FINAL = 0xD6E8FEB86659FD93


def rol(value, bits):
    return ((value << bits) | (value >> (64 - bits))) & MASK


def ror(value, bits):
    return ((value >> bits) | (value << (64 - bits))) & MASK


def encrypted_keys():
    state = SEED
    output = []
    for i, key in enumerate(KEYS):
        state = (rol(state ^ ((0xA24BAED4963EE407 + i * 0x9E3779B185EBCA87) & MASK), 9)
                 * 0xC2B2AE3D27D4EB4F + 0xD1B54A32D192ED03) & MASK
        output.append(key ^ state)
    return output


def reference(data: bytes) -> int:
    n = len(data)
    a = KEYS[0] ^ ((n * KEYS[1]) & MASK)
    b = (KEYS[2] + (n ^ KEYS[3])) & MASK
    for i, byte in enumerate(data):
        t = ((a + rol(b, 11)) ^ ((byte + KEYS[(i + 3) & 15]) & MASK)) & MASK
        t = (t * KEYS[(byte ^ i) & 15]) & MASK
        if (byte ^ i) & 4:
            a = rol(t ^ KEYS[(byte >> 4) & 15], 17)
        else:
            a = ror((t + KEYS[(i + byte) & 15]) & MASK, 13)
        b = ((b ^ a) * KEYS[(i + 7) & 15]
             + rol(byte ^ KEYS[(i + 1) & 15], 5)) & MASK
    return (a ^ rol(b, 29) ^ KEYS[n & 15] ^ ((n * FINAL) & MASK)) & MASK


def reference_program():
    return {"tables": {"k": [hex(v) for v in KEYS]}, "steps": [
        {"dst": "r0", "op": "lookup", "table": "k", "index": 0},
        {"dst": "r1", "op": "lookup", "table": "k", "index": 1},
        {"dst": "r1", "op": "mul", "a": "n", "b": "r1"},
        {"dst": "r0", "op": "xor", "a": "r0", "b": "r1"},
        {"dst": "r2", "op": "lookup", "table": "k", "index": 2},
        {"dst": "r3", "op": "lookup", "table": "k", "index": 3},
        {"dst": "r3", "op": "xor", "a": "n", "b": "r3"},
        {"dst": "r1", "op": "add", "a": "r2", "b": "r3"},
        {"op": "each", "body": [
            {"dst": "r2", "op": "rol", "a": "r1", "bits": 11},
            {"dst": "r2", "op": "add", "a": "r0", "b": "r2"},
            {"dst": "r3", "op": "add", "a": "i", "b": 3},
            {"dst": "r3", "op": "lookup", "table": "k", "index": "r3"},
            {"dst": "r4", "op": "add", "a": "byte", "b": "r3"},
            {"dst": "r2", "op": "xor", "a": "r2", "b": "r4"},
            {"dst": "r5", "op": "xor", "a": "byte", "b": "i"},
            {"dst": "r6", "op": "lookup", "table": "k", "index": "r5"},
            {"dst": "r2", "op": "mul", "a": "r2", "b": "r6"},
            {"dst": "r7", "op": "and", "a": "r5", "b": 4},
            {"dst": "r8", "op": "shr", "a": "byte", "bits": 4},
            {"dst": "r8", "op": "lookup", "table": "k", "index": "r8"},
            {"dst": "r9", "op": "xor", "a": "r2", "b": "r8"},
            {"dst": "r9", "op": "rol", "a": "r9", "bits": 17},
            {"dst": "r10", "op": "add", "a": "i", "b": "byte"},
            {"dst": "r10", "op": "lookup", "table": "k", "index": "r10"},
            {"dst": "r11", "op": "add", "a": "r2", "b": "r10"},
            {"dst": "r11", "op": "ror", "a": "r11", "bits": 13},
            {"dst": "r0", "op": "sel", "cond": "r7", "a": "r9", "b": "r11"},
            {"dst": "r1", "op": "xor", "a": "r1", "b": "r0"},
            {"dst": "r12", "op": "add", "a": "i", "b": 7},
            {"dst": "r12", "op": "lookup", "table": "k", "index": "r12"},
            {"dst": "r1", "op": "mul", "a": "r1", "b": "r12"},
            {"dst": "r13", "op": "add", "a": "i", "b": 1},
            {"dst": "r13", "op": "lookup", "table": "k", "index": "r13"},
            {"dst": "r14", "op": "xor", "a": "byte", "b": "r13"},
            {"dst": "r14", "op": "rol", "a": "r14", "bits": 5},
            {"dst": "r1", "op": "add", "a": "r1", "b": "r14"},
        ]},
        {"dst": "r2", "op": "rol", "a": "r1", "bits": 29},
        {"dst": "r0", "op": "xor", "a": "r0", "b": "r2"},
        {"dst": "r3", "op": "lookup", "table": "k", "index": "n"},
        {"dst": "r0", "op": "xor", "a": "r0", "b": "r3"},
        {"dst": "r4", "op": "mul", "a": "n", "b": hex(FINAL)},
        {"dst": "r0", "op": "xor", "a": "r0", "b": "r4"},
    ], "return": "r0"}


def build_stream():
    cipher = encrypted_keys()
    (HERE / "stream_key.bin").write_bytes(struct.pack("<16Q", *cipher))
    (HERE / "stream_decoy.bin").write_bytes(struct.pack("<16Q", *[x ^ 0xF0F0F0F0F0F0F0F0 for x in cipher]))
    (HERE / "stream_resources.rc").write_text('701 RCDATA "stream_key.bin"\n702 RCDATA "stream_decoy.bin"\n', encoding="ascii")
    (HERE / "stream_payload.h").write_text(f"#pragma once\n#define STREAM_SEED 0x{SEED:016X}ULL\n", encoding="ascii")
    env, compiler = vs_environment()
    sdk_root = Path(r"C:\Program Files (x86)\Windows Kits\10")
    sdk = sorted((sdk_root / "Include").glob("10.*"), reverse=True)[0].name
    rc = sdk_root / "bin" / sdk / "x64" / "rc.exe"
    res = HERE / "stream_resources.res"
    built = subprocess.run([str(rc), "/nologo", f"/fo{res}", str(HERE / "stream_resources.rc")],
                           cwd=HERE, env=env, capture_output=True, text=True,
                           encoding="mbcs", errors="replace")
    if built.returncode:
        raise RuntimeError("RC build failed: " + built.stdout[-1000:] + built.stderr[-1000:])
    exe = ROOT / "public" / "artifacts" / "hard_stream" / "stream_oracle.exe"
    exe.parent.mkdir(parents=True, exist_ok=True)
    obj = HERE / "stream_oracle.obj"
    built = subprocess.run([str(compiler), "/nologo", "/O2", "/Ob0", "/GS-", "/MT",
                            f"/Fo{obj}", f"/Fe{exe}", str(HERE / "stream_oracle.c"), str(res),
                            "/link", "/DEBUG:NONE", f"/MAP:{HERE / 'stream_oracle.map'}"],
                           cwd=HERE, env=env, capture_output=True, text=True,
                           encoding="mbcs", errors="replace")
    if built.returncode:
        raise RuntimeError("Stream PE build failed: " + built.stdout[-1500:] + built.stderr[-1500:])
    vectors = [b"", b"\x00", b"\xff", bytes(range(16)), bytes(range(96)), bytes([0xff] * 96)]
    rng = random.Random(0x20271005)
    vectors += [rng.randbytes(rng.randrange(97)) for _ in range(15)]
    for data in vectors:
        run = subprocess.run([str(exe), data.hex() or "-"], capture_output=True, text=True)
        if run.returncode or int(run.stdout.strip(), 16) != reference(data):
            raise RuntimeError(f"Stream fixture mismatch: {data.hex()}: {run.stdout!r} {run.stderr!r}")
    raw = exe.read_bytes()
    if any(struct.pack("<Q", key) in raw for key in KEYS):
        raise RuntimeError("Plaintext key leaked into PE")
    return {"exe": exe, "program": reference_program(),
            "function_rva": symbol_rva("stream_oracle", "stream_tag"),
            "resource_id": 701, "key0": KEYS[0],
            "empty": reference(b""), "sample": reference(bytes.fromhex("00112233445566778899AABBCCDDEEFF"))}


if __name__ == "__main__":
    info = build_stream()
    print("Built", info["exe"], "function", hex(info["function_rva"]))
