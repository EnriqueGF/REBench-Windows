"""Build deterministic, stripped Windows PE challenge artifacts and answer data."""

from __future__ import annotations

import os
import hashlib
import re
import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
PUBLIC = ROOT / "public" / "artifacts" / "hard_license"


def vs_environment() -> tuple[dict[str, str], Path]:
    base = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools")
    candidates = sorted((base / "VC" / "Tools" / "MSVC").glob("*/bin/Hostx64/x64/cl.exe"), reverse=True)
    sdk_root = Path(r"C:\Program Files (x86)\Windows Kits\10")
    sdk_versions = sorted((sdk_root / "Include").glob("10.*"), reverse=True)
    if not candidates or not sdk_versions:
        raise RuntimeError("MSVC Build Tools x64 are required to rebuild this authoring fixture")
    toolchain = candidates[0].parents[3]
    sdk = sdk_versions[0].name
    env = dict(os.environ)
    env["INCLUDE"] = os.pathsep.join(str(x) for x in [
        toolchain / "include", sdk_root / "Include" / sdk / "ucrt",
        sdk_root / "Include" / sdk / "shared", sdk_root / "Include" / sdk / "um",
        sdk_root / "Include" / sdk / "winrt",
    ])
    env["LIB"] = os.pathsep.join(str(x) for x in [
        toolchain / "lib" / "x64", sdk_root / "Lib" / sdk / "ucrt" / "x64",
        sdk_root / "Lib" / sdk / "um" / "x64",
    ])
    env["PATH"] = str(candidates[0].parent) + os.pathsep + env.get("PATH", "")
    return env, candidates[0]


def stream(seed: int, size: int):
    state = seed
    states = []
    masks = []
    for index in range(size):
        state ^= (0x9E3779B9 + index * 0x045D9F3B) & 0xFFFFFFFF
        state = ((state << 7) | (state >> 25)) & 0xFFFFFFFF
        state = (state * 0x7FEB352D + 0x846CA68B) & 0xFFFFFFFF
        states.append(state)
        masks.append((state >> 23) & 0xFF)
    return states, masks


def compile_c(source: Path, output: Path, defines: list[str] | None = None, map_stem: str | None = None):
    env, compiler = vs_environment()
    output.parent.mkdir(parents=True, exist_ok=True)
    stem = map_stem or source.stem
    obj = HERE / (stem + ".obj")
    command = [str(compiler), "/nologo", "/O2", "/Ob0", "/GS-", "/MT", "/D_CRT_SECURE_NO_WARNINGS",
               *(defines or []), f"/Fo{obj}", f"/Fe{output}", str(source), "/link", "/DEBUG:NONE",
               f"/MAP:{HERE / (stem + '.map')}"]
    proc = subprocess.run(command, cwd=HERE, env=env, capture_output=True, text=True, encoding="mbcs", errors="replace")
    if proc.returncode:
        raise RuntimeError(f"MSVC build failed: {proc.stdout[-1500:]} {proc.stderr[-1500:]}")


def symbol_rva(source_stem: str, symbol: str) -> int:
    listing = (HERE / (source_stem + ".map")).read_text(encoding="mbcs", errors="replace")
    match = re.search(r"\b" + re.escape(symbol) + r"\s+([0-9A-Fa-f]{16})\b", listing)
    if not match:
        raise RuntimeError(f"Missing map symbol: {symbol}")
    return int(match.group(1), 16) - 0x140000000


def license_case():
    real = b"N7K4C2R9Q5M8V3X6T1P0"
    retired = b"A1B2C3D4E5F6G7H8J9K0"
    assert len(real) == len(retired) == 20
    seed_real = 0xC43D8A17
    seed_retired = 0x7319BC05
    real_states, real_mask = stream(seed_real, len(real))
    _, retired_mask = stream(seed_retired, len(retired))
    real_cipher = bytes(x ^ y for x, y in zip(real, real_mask))
    retired_cipher = bytes(x ^ y for x, y in zip(retired, retired_mask))
    header = HERE / "license_payload.h"
    header.write_text("\n".join([
        "#pragma once", f"#define CODE_LENGTH {len(real)}",
        f"#define CURRENT_SEED 0x{seed_real:08X}u", f"#define RETIRED_SEED 0x{seed_retired:08X}u",
        "static const unsigned char current_cipher[CODE_LENGTH] = {" + ",".join(f"0x{x:02X}" for x in real_cipher) + "};",
        "static const unsigned char retired_cipher[CODE_LENGTH] = {" + ",".join(f"0x{x:02X}" for x in retired_cipher) + "};",
        "",
    ]), encoding="utf-8")
    PUBLIC.mkdir(parents=True, exist_ok=True)
    exe = PUBLIC / "license_probe.exe"
    compile_c(HERE / "license_probe.c", exe)
    good = subprocess.run([str(exe), real.decode()], capture_output=True, text=True)
    bad = subprocess.run([str(exe), retired.decode()], capture_output=True, text=True)
    legacy = subprocess.run([str(exe), "--retired", retired.decode()], capture_output=True, text=True)
    if (good.returncode, good.stdout.strip(), bad.returncode, legacy.returncode) != (0, "ACCEPT", 1, 0):
        raise RuntimeError("Compiled license fixture failed behavior checks")
    return {
        "real": real.decode(), "retired": retired.decode(), "seed": seed_real,
        "state_after_10": real_states[9], "cipher": real_cipher.hex(), "exe": exe,
        "decode_rva": symbol_rva("license_probe", "decode_current"),
    }


def rol8(value: int, amount: int) -> int:
    return ((value << amount) | (value >> (8 - amount))) & 0xFF


def vm_case():
    secret = b"Q8M4Z2N7R5T9V3X6"
    permutation = [7, 0, 12, 3, 15, 8, 1, 10, 5, 14, 2, 9, 6, 13, 4, 11]
    opcodes = []
    for index in permutation:
        xor = (index * 29 + 0xA7) & 0xFF
        rotate = index % 5 + 1
        add = (index * 17 + 0x35) & 0xFF
        target = (rol8(secret[index] ^ xor, rotate) + add) & 0xFF
        opcodes.extend([0x31, index, 0, 0xA4, xor, 0, 0x5B, rotate, 0,
                        0x79, add, 0, 0xC2, target, 0])
    opcodes.extend([0xF0, 0, 0])
    plain = bytes(opcodes)
    seed = 0x6D
    mask = seed
    encoded = bytearray()
    for value in plain:
        mask = (mask * 73 + 41) & 0xFF
        encoded.append(value ^ mask)
    header = HERE / "vm_payload.h"
    header.write_text("\n".join([
        "#pragma once", f"#define INPUT_LENGTH {len(secret)}", f"#define PROGRAM_LENGTH {len(plain)}",
        f"#define MASK_SEED 0x{seed:02X}u",
        "#define PROGRAM_BYTES {" + ",".join(f"0x{x:02X}" for x in encoded) + "}",
        "",
    ]), encoding="utf-8")
    target = ROOT / "public" / "artifacts" / "hard_vm" / "vm_guard.exe"
    compile_c(HERE / "vm_guard.c", target)
    good = subprocess.run([str(target), secret.decode()], capture_output=True, text=True)
    bad = subprocess.run([str(target), "A" * len(secret)], capture_output=True, text=True)
    if (good.returncode, good.stdout.strip(), bad.returncode) != (0, "ACCEPT", 1):
        raise RuntimeError("Compiled VM fixture failed behavior checks")
    return {"secret": secret.decode(), "mask_seed": seed, "permutation": permutation,
            "program_length": len(plain), "program_sha256": hashlib.sha256(plain).hexdigest(),
            "exe": target}


def pattern_case():
    targets = []
    output_dir = ROOT / "public" / "artifacts" / "hard_pattern"
    for version in (1, 2, 3, 4):
        output = (output_dir if version < 4 else HERE / "hidden") / f"layout_v{version}.exe"
        compile_c(HERE / "pattern_target.c", output, [f"/DVERSION={version}"], f"pattern_v{version}")
        process = subprocess.run([str(output), "0x12345678"], capture_output=True, text=True)
        if process.returncode or len(process.stdout.strip()) != 8:
            raise RuntimeError(f"Pattern fixture v{version} failed behavior check")
        targets.append({"version": version, "exe": output,
                        "target_rva": symbol_rva(f"pattern_v{version}", "inspect_mode"),
                        "decoy_rva": symbol_rva(f"pattern_v{version}", "audit_decoy"),
                        "output": process.stdout.strip()})
    if len({item["target_rva"] for item in targets}) < 2:
        raise RuntimeError("Version layouts did not move the target")
    pattern = "8B 81 A8 02 00 00 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? C1 C8 1D C3"
    tokens = [None if x == "??" else int(x, 16) for x in pattern.split()]
    for item in targets:
        raw = item["exe"].read_bytes()
        pe = struct.unpack_from("<I", raw, 0x3C)[0]
        sections = pe + 24 + struct.unpack_from("<H", raw, pe + 20)[0]
        text = None
        for section_index in range(struct.unpack_from("<H", raw, pe + 6)[0]):
            offset = sections + section_index * 40
            if raw[offset:offset + 8].rstrip(b"\0") == b".text":
                va, size, pointer = struct.unpack_from("<III", raw, offset + 12)
                text = (va, raw[pointer:pointer + size])
                break
        if text is None:
            raise RuntimeError("Missing .text in pattern fixture")
        va, code = text
        hits = [va + pos for pos in range(len(code) - len(tokens) + 1)
                if all(expected is None or code[pos + index] == expected for index, expected in enumerate(tokens))]
        if hits != [item["target_rva"]]:
            raise RuntimeError(f"Signature validation failed in v{item['version']}: {hits}")
    value = (0x12345678 ^ 0x76E2845D) + 0xE13B6709
    value &= 0xFFFFFFFF
    v3_target_result = ((value << 3) | (value >> 29)) & 0xFFFFFFFF
    return {"versions": targets[:3], "hidden": targets[3], "pattern": pattern,
            "v3_target_result": v3_target_result}


if __name__ == "__main__":
    for info in (license_case(), vm_case()):
        print("Built", info["exe"], "bytes", info["exe"].stat().st_size)
    for info in pattern_case()["versions"]:
        print("Built", info["exe"], "target RVA", hex(info["target_rva"]))
