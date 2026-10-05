"""Build a PE64 whose TLS callback decodes an RCDATA keybank for two passes."""

from __future__ import annotations

import random
import struct
import subprocess
import sys
from pathlib import Path

try:
    from .build_hard import ROOT, HERE, symbol_rva, vs_environment
    from .build_tls import pe_tls_callbacks
except ImportError:
    from build_hard import ROOT, HERE, symbol_rva, vs_environment
    from build_tls import pe_tls_callbacks

MASK = (1 << 64) - 1
SEED = 0x6C8E9CF5702A41D3
KEYS = [random.Random(0x20271009 + i * 0x731).getrandbits(64) | 1 for i in range(16)]
FINAL = 0x8CB92BA72F3D8DD7


def rol(value, bits):
    return ((value << bits) | (value >> (64 - bits))) & MASK


def ror(value, bits):
    return ((value >> bits) | (value << (64 - bits))) & MASK


def encrypted_keys():
    state, result = SEED, []
    for i, key in enumerate(KEYS):
        state = (rol(state ^ ((0x79B5D06C8A4E3F21 + i * 0x9E3779B185EBCA87) & MASK), 7)
                 * 0xD6E8FEB86659FD93 + 0xA24BAED4963EE407) & MASK
        result.append(key ^ state)
    return result


def reference(data: bytes):
    n = len(data)
    a = KEYS[0] ^ ((n * KEYS[1]) & MASK)
    b = (KEYS[2] + (n ^ KEYS[3])) & MASK
    for i, byte in enumerate(data):
        t = ((a + rol(b, 7)) ^ (byte + KEYS[(i + 5) & 15])) & MASK
        t = t * KEYS[(i + byte) & 15] & MASK
        a = (rol(t ^ KEYS[(byte >> 4) & 15], 13) if (byte ^ i) & 1
             else ror((t + KEYS[(i + 3) & 15]) & MASK, 11))
        b = ((b ^ a) * KEYS[(i + 11) & 15] + byte) & MASK
    for i in range(n - 1, -1, -1):
        byte = data[i]
        z = ((b ^ ror(a, 9)) + KEYS[(i + byte) & 15]) & MASK
        b = (rol(z ^ KEYS[(i + 7) & 15], 17) if (byte ^ i) & 0x20
             else ror((z + KEYS[(byte >> 4) & 15]) & MASK, 19))
        a = (((a + b) * KEYS[(i + 1) & 15])
             ^ rol(byte + KEYS[(i + 2) & 15], 5)) & MASK
    return (a ^ rol(b, 29) ^ KEYS[n & 15] ^ ((n * FINAL) & MASK)) & MASK


def reference_program():
    def s(dst, op, **args):
        return {"dst": dst, "op": op, **args}
    def k(dst, index):
        return s(dst, "lookup", table="k", index=index)
    return {"tables": {"k": [hex(value) for value in KEYS]}, "steps": [
        k("r0", 0), k("r1", 1), s("r1", "mul", a="n", b="r1"),
        s("r0", "xor", a="r0", b="r1"), k("r1", 2), k("r2", 3),
        s("r2", "xor", a="n", b="r2"), s("r1", "add", a="r1", b="r2"),
        {"op": "each", "body": [
            s("r2", "rol", a="r1", bits=7), s("r2", "add", a="r0", b="r2"),
            s("r3", "add", a="i", b=5), k("r3", "r3"),
            s("r4", "add", a="byte", b="r3"), s("r2", "xor", a="r2", b="r4"),
            s("r3", "add", a="i", b="byte"), k("r3", "r3"),
            s("r2", "mul", a="r2", b="r3"),
            s("r4", "xor", a="byte", b="i"), s("r4", "and", a="r4", b=1),
            s("r5", "shr", a="byte", bits=4), k("r5", "r5"),
            s("r6", "xor", a="r2", b="r5"), s("r6", "rol", a="r6", bits=13),
            s("r5", "add", a="i", b=3), k("r5", "r5"),
            s("r7", "add", a="r2", b="r5"), s("r7", "ror", a="r7", bits=11),
            s("r0", "sel", cond="r4", a="r6", b="r7"),
            s("r3", "xor", a="r1", b="r0"),
            s("r5", "add", a="i", b=11), k("r5", "r5"),
            s("r1", "mul", a="r3", b="r5"), s("r1", "add", a="r1", b="byte"),
        ]},
        {"op": "each_reverse", "body": [
            s("r2", "ror", a="r0", bits=9), s("r2", "xor", a="r1", b="r2"),
            s("r3", "add", a="i", b="byte"), k("r3", "r3"),
            s("r2", "add", a="r2", b="r3"),
            s("r4", "xor", a="byte", b="i"), s("r4", "and", a="r4", b=0x20),
            s("r5", "add", a="i", b=7), k("r5", "r5"),
            s("r6", "xor", a="r2", b="r5"), s("r6", "rol", a="r6", bits=17),
            s("r5", "shr", a="byte", bits=4), k("r5", "r5"),
            s("r7", "add", a="r2", b="r5"), s("r7", "ror", a="r7", bits=19),
            s("r1", "sel", cond="r4", a="r6", b="r7"),
            s("r3", "add", a="r0", b="r1"),
            s("r5", "add", a="i", b=1), k("r5", "r5"),
            s("r3", "mul", a="r3", b="r5"),
            s("r5", "add", a="i", b=2), k("r5", "r5"),
            s("r5", "add", a="byte", b="r5"), s("r5", "rol", a="r5", bits=5),
            s("r0", "xor", a="r3", b="r5"),
        ]},
        s("r2", "rol", a="r1", bits=29), s("r0", "xor", a="r0", b="r2"),
        k("r2", "n"), s("r0", "xor", a="r0", b="r2"),
        s("r2", "mul", a="n", b=hex(FINAL)), s("r0", "xor", a="r0", b="r2"),
    ], "return": "r0"}


def build_stream2():
    cipher = encrypted_keys()
    (HERE / "stream2_key.bin").write_bytes(struct.pack("<16Q", *cipher))
    (HERE / "stream2_decoy.bin").write_bytes(struct.pack("<16Q", *[x ^ 0xA5A5A5A5A5A5A5A5 for x in cipher]))
    (HERE / "stream2_resources.rc").write_text('803 RCDATA "stream2_key.bin"\n804 RCDATA "stream2_decoy.bin"\n', encoding="ascii")
    (HERE / "stream2_payload.h").write_text(f"#pragma once\n#define STREAM2_SEED 0x{SEED:016X}ULL\n", encoding="ascii")
    env, compiler = vs_environment()
    sdk_root = Path(r"C:\Program Files (x86)\Windows Kits\10")
    sdk = sorted((sdk_root / "Include").glob("10.*"), reverse=True)[0].name
    rc = sdk_root / "bin" / sdk / "x64" / "rc.exe"
    res = HERE / "stream2_resources.res"
    built = subprocess.run([str(rc), "/nologo", f"/fo{res}", str(HERE / "stream2_resources.rc")],
                           cwd=HERE, env=env, capture_output=True, text=True,
                           encoding="mbcs", errors="replace")
    if built.returncode:
        raise RuntimeError("RC build failed: " + built.stdout[-1000:] + built.stderr[-1000:])
    exe = ROOT / "public" / "artifacts" / "hard_stream2" / "stream2_oracle.exe"
    exe.parent.mkdir(parents=True, exist_ok=True)
    built = subprocess.run([str(compiler), "/nologo", "/O2", "/Ob0", "/GS-", "/MT",
                            f"/Fo{HERE / 'stream2_oracle.obj'}", f"/Fe{exe}",
                            str(HERE / "stream2_oracle.c"), str(res),
                            "/link", "/DEBUG:NONE", f"/MAP:{HERE / 'stream2_oracle.map'}"],
                           cwd=HERE, env=env, capture_output=True, text=True,
                           encoding="mbcs", errors="replace")
    if built.returncode:
        raise RuntimeError("Stream2 PE build failed: " + built.stdout[-1500:] + built.stderr[-1500:])
    callback_rva = symbol_rva("stream2_oracle", "stream2_tls")
    if callback_rva not in pe_tls_callbacks(exe):
        raise RuntimeError("TLS callback not registered")
    vectors = [b"", b"\x00", b"\xff", bytes(range(16)), bytes(range(96)),
               bytes([0xff] * 96), bytes([0x55, 0xaa] * 48)]
    rng = random.Random(0x20271005)
    vectors += [rng.randbytes(rng.randrange(97)) for _ in range(18)]
    sys.path.insert(0, str(ROOT))
    from benchmark import eval_pipeline64
    program = reference_program()
    for data in vectors:
        run = subprocess.run([str(exe), data.hex() or "-"], capture_output=True, text=True)
        wanted = reference(data)
        if run.returncode or int(run.stdout.strip(), 16) != wanted:
            raise RuntimeError(f"Stream2 fixture mismatch: {data.hex()}: {run.stdout!r}")
        if eval_pipeline64(program, 0, 0, data) != wanted:
            raise RuntimeError("Stream2 DSL mismatch")
    raw = exe.read_bytes()
    if any(struct.pack("<Q", key) in raw for key in KEYS):
        raise RuntimeError("Plaintext key leaked")
    return {"exe": exe, "program": program, "callback_rva": callback_rva,
            "function_rva": symbol_rva("stream2_oracle", "two_pass_tag"),
            "resource_id": 803, "key0": KEYS[0],
            "empty": reference(b""),
            "sample": reference(bytes.fromhex("00112233445566778899AABBCCDDEEFF"))}


if __name__ == "__main__":
    info = build_stream2()
    print("Built", info["exe"], "TLS", hex(info["callback_rva"]))
