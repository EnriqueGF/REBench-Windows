#!/usr/bin/env python3
"""Generate and grade benign Windows PE crackmes with encrypted packed VM code."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import urllib.request
import zipfile
from io import BytesIO
from pathlib import Path

from private.hard.build_hard import compile_c

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "private" / "protected_vm"
PUBLIC = ROOT / "public_protected"
MANIFEST = SOURCE / "manifest.json"
MASK = 0xFFFFFFFF
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def rol(value, bits, width):
    mask = (1 << width) - 1
    return ((value << bits) | (value >> (width - bits))) & mask


def tea_block(a, b, key):
    total = 0
    for _ in range(32):
        a = (a + ((((b << 4) ^ (b >> 5)) + b) ^ (total + key[total & 3]))) & MASK
        total = (total + 0x9E3779B9) & MASK
        b = (b + ((((a << 4) ^ (a >> 5)) + a) ^ (total + key[(total >> 11) & 3]))) & MASK
    return a, b


def encrypt(data: bytes, key, nonce):
    out = bytearray()
    for at in range(0, len(data), 8):
        index = at // 8
        a, b = tea_block(nonce ^ index, (nonce + index) ^ 0xC17D83A5, key)
        stream = a.to_bytes(4, "little") + b.to_bytes(4, "little")
        out.extend(x ^ y for x, y in zip(data[at:at + 8], stream))
    return bytes(out)


def pack(data: bytes):
    result = bytearray()
    literals = bytearray()

    def flush():
        while literals:
            chunk = literals[:128]
            del literals[:128]
            result.append(len(chunk) - 1)
            result.extend(chunk)

    at = 0
    while at < len(data):
        best_len, best_distance = 0, 0
        for distance in range(1, min(at, 255) + 1):
            size = 0
            while (size < 130 and at + size < len(data)
                   and data[at + size] == data[at + size - distance]):
                size += 1
            if size > best_len:
                best_len, best_distance = size, distance
        if best_len >= 4:
            flush()
            result.extend((128 | (best_len - 3), best_distance))
            at += best_len
        else:
            literals.append(data[at])
            at += 1
            if len(literals) == 128:
                flush()
    flush()
    return bytes(result)


def unpack(data: bytes):
    result = bytearray()
    at = 0
    while at < len(data):
        token = data[at]
        at += 1
        if token < 128:
            count = token + 1
            if at + count > len(data):
                raise ValueError("truncated literal block")
            result.extend(data[at:at + count])
            at += count
        else:
            count = (token & 127) + 3
            if at >= len(data):
                raise ValueError("truncated reference block")
            distance = data[at]
            at += 1
            if distance == 0 or distance > len(result):
                raise ValueError("invalid reference distance")
            for _ in range(count):
                result.append(result[-distance])
    return bytes(result)


def generate(seed: int):
    rng = random.Random(seed)
    secret = "".join(rng.choice(ALPHABET) for _ in range(24))
    indices = list(range(len(secret)))
    rng.shuffle(indices)
    opcodes = rng.sample(range(1, 256), 4)
    load, mix, check, end = opcodes
    state = rng.getrandbits(64)
    initial_state = state
    multiplier = rng.getrandbits(64) | 1
    reset_key = rng.getrandbits(64)
    reset_multiplier = rng.getrandbits(64) | 1
    mix_keys = [rng.getrandbits(64) for _ in range(8)]
    mix_salts = [rng.getrandbits(64) for _ in range(8)]
    mix_rotations = [rng.randrange(1, 64) for _ in range(8)]
    program = bytearray()
    for block in range(3):
        for round_no, index in enumerate(indices[block * 8:(block + 1) * 8]):
            program.extend((load, index, 0, mix, round_no, 0))
            state = (rol(((state ^ (secret.encode()[index] + mix_keys[round_no])) * multiplier) & ((1 << 64) - 1),
                         mix_rotations[round_no], 64) + mix_salts[round_no]) & ((1 << 64) - 1)
        target = state
        program.extend((check, block))
        program.extend(target.to_bytes(8, "little"))
        pc = len(program)
        state = rol(target ^ reset_key ^ ((pc * reset_multiplier) & ((1 << 64) - 1)), 9, 64)
    program.extend((end, state & 255, 0))
    key = [rng.getrandbits(32) for _ in range(4)]
    nonce = rng.getrandbits(32)
    packed = pack(bytes(program))
    if unpack(packed) != bytes(program):
        raise RuntimeError("VM packer roundtrip failed")
    cipher = encrypt(packed, key, nonce)
    if encrypt(cipher, key, nonce) != packed:
        raise RuntimeError("VM cipher roundtrip failed")
    header = "\n".join([
        "#pragma once", f"#define INPUT_LENGTH {len(secret)}",
        f"#define PROGRAM_LENGTH {len(program)}", f"#define CIPHER_LENGTH {len(cipher)}",
        f"#define NONCE 0x{nonce:08X}u", f"#define STATE_INIT 0x{initial_state:016X}ULL",
        f"#define MIX_MULTIPLIER 0x{multiplier:016X}ULL",
        f"#define RESET_KEY 0x{reset_key:016X}ULL",
        f"#define RESET_MULTIPLIER 0x{reset_multiplier:016X}ULL",
        "#define MIX_KEYS {" + ",".join(f"0x{x:016X}ULL" for x in mix_keys) + "}",
        "#define MIX_SALTS {" + ",".join(f"0x{x:016X}ULL" for x in mix_salts) + "}",
        "#define MIX_ROTATIONS {" + ",".join(str(x) for x in mix_rotations) + "}",
        "#define KEY_WORDS {" + ",".join(f"0x{x:08X}u" for x in key) + "}",
        "#define CIPHER_BYTES {" + ",".join(f"0x{x:02X}" for x in cipher) + "}",
        *(f"#define OP_{name} 0x{value:02X}u" for name, value in zip(
            ("LOAD", "MIX", "CHECK", "END"), opcodes)), "",
    ])
    return secret, bytes(program), packed, cipher, header


def build(seed: int, count: int):
    SOURCE.mkdir(parents=True, exist_ok=True)
    cases = []
    for number in range(count):
        case_seed = int.from_bytes(hashlib.sha256(f"{seed}:{number}".encode()).digest()[:8], "little")
        secret, program, packed, cipher, header = generate(case_seed)
        case_id = "vm_" + hashlib.sha256(cipher).hexdigest()[:12]
        (SOURCE / "payload.h").write_text(header, encoding="ascii")
        exe = PUBLIC / case_id / "guard.exe"
        compile_c(SOURCE / "vm_protected.c", exe, map_stem=f"vm_{number}")
        accepted = subprocess.run([str(exe), secret], capture_output=True, text=True, timeout=5)
        rejected = subprocess.run([str(exe), "A" * 24], capture_output=True, text=True, timeout=5)
        if (accepted.returncode, accepted.stdout.strip(), rejected.returncode) != (0, "ACCEPT", 1):
            raise RuntimeError(f"Generated PE failed oracle check: {case_id}")
        cases.append({"case_id": case_id, "exe": str(exe.relative_to(ROOT)),
                      "exe_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(),
                      "secret": secret, "program_sha256": hashlib.sha256(program).hexdigest(),
                      "program_size": len(program), "packed_size": len(packed),
                      "cipher_size": len(cipher)})
        print(case_id, exe.stat().st_size, "bytes", flush=True)
    write_json(MANIFEST, {"generator_seed": seed, "cases": cases})


def parse_answer(raw, case_id):
    decoder = json.JSONDecoder()
    for match in reversed(list(re.finditer(r"\{", raw))):
        try:
            answer, _ = decoder.raw_decode(raw[match.start():])
        except json.JSONDecodeError:
            continue
        if isinstance(answer, dict) and answer.get("case_id") == case_id:
            return answer
    raise ValueError("missing valid JSON with matching case_id")


def infrastructure_error(stdout, stderr):
    message = (stdout + "\n" + stderr).casefold()
    if "model is at capacity" in message:
        return "provider_capacity"
    if "valid gateway bearer key is required" in message:
        return "gateway_authentication"
    if "need the user's permission to execute" in message:
        return "cli_permissions"
    return None


def variant_cases(manifest, variant):
    if variant == "custom":
        return manifest
    file = SOURCE / f"{variant}_manifest.json"
    variants = {x["case_id"]: x for x in read_json(file)["cases"]}
    manifest["cases"] = [{**item, "exe": variants[item["case_id"]]["exe"],
                          "exe_sha256": variants[item["case_id"]]["sha256"]}
                         for item in manifest["cases"]]
    return manifest


def run(profile, output, timeout, variant="custom", case_ids=None, retry=False, model=None):
    manifest = read_json(MANIFEST)
    manifest = variant_cases(manifest, variant)
    result = read_json(output) if output.exists() else {"track": "protected-vm", "variant": variant,
                                                       "profile": profile, "model": model,
                                                       "timeout_seconds": timeout, "attempts": []}
    if result.get("variant") != variant:
        raise RuntimeError("Output file belongs to a different protection variant")
    if result.get("timeout_seconds", timeout) != timeout:
        raise RuntimeError("Existing result file uses a different time budget")
    if result.get("model") != model:
        raise RuntimeError("Existing result file uses a different model")
    completed = {x["case_id"]: x for x in result["attempts"]}
    profiles = {
        "codex": ["codex", "exec", "--skip-git-repo-check", "--sandbox", "read-only", "--ephemeral",
                  "--color", "never", "-m", "gpt-6-sol"],
        "claude": ["claude", "-p", "--model", "claude-opus-4-7", "--output-format", "text",
                   "--permission-mode", "bypassPermissions"],
        "opencode": [str(Path(os.environ.get("LOCALAPPDATA", "")) / "OpenCode" / "opencode-cli.exe"), "run"],
        "agy": ["agy", "--print", "--output-format", "text"],
    }
    if model:
        if profile == "opencode":
            profiles[profile].extend(["--model", model])
        elif profile == "claude":
            profiles[profile][profiles[profile].index("--model") + 1] = model
        else:
            raise ValueError("--model is currently supported for Claude and OpenCode only")
    selected = set(case_ids or [case["case_id"] for case in manifest["cases"]])
    unknown = selected - {case["case_id"] for case in manifest["cases"]}
    if unknown:
        raise SystemExit(f"Unknown case ids: {sorted(unknown)}")
    for case in manifest["cases"]:
        case_id = case["case_id"]
        previous = completed.get(case_id)
        if case_id not in selected:
            continue
        if previous and not retry and not (
            previous.get("infrastructure_error") or
            infrastructure_error(str(previous.get("stdout", "")), str(previous.get("stderr", "")))
        ):
            continue
        exe = ROOT / case["exe"]
        if hashlib.sha256(exe.read_bytes()).hexdigest() != case["exe_sha256"]:
            raise RuntimeError(f"PE hash mismatch: {case_id}")
        prompt = (f"Analyze guard.exe, a benign Windows x64 crackme. It accepts exactly one 24-character "
                  f"code and prints ACCEPT or REJECT. The validation logic runs in a custom VM; its bytecode "
                  f"is packed and encrypted on disk. Recover the accepted code AND the SHA-256 of the "
                  f"decrypted, decompressed bytecode. You may execute guard.exe locally as an oracle. "
                  f"Use only the staged PE; do not search other directories, source, ground truth, or the web. "
                  f"Return only JSON: {{\"case_id\":\"{case_id}\",\"code\":\"...\","
                  f"\"program_sha256\":\"64 lowercase hex characters\"}}")
        with tempfile.TemporaryDirectory(prefix="vm_re_", ignore_cleanup_errors=True) as temp:
            work = Path(temp)
            shutil.copy2(exe, work / "guard.exe")
            start = time.monotonic()
            try:
                proc = subprocess.run(profiles[profile] + [prompt], cwd=work, capture_output=True, text=True,
                                      encoding="utf-8", errors="replace", timeout=timeout)
                attempt = {"case_id": case_id, "seconds": round(time.monotonic() - start, 2),
                           "exit_code": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
                error = infrastructure_error(proc.stdout, proc.stderr)
                if error:
                    attempt["infrastructure_error"] = error
                try:
                    attempt["answer"] = parse_answer(proc.stdout, case_id)
                except ValueError as exc:
                    attempt["parse_error"] = str(exc)
            except subprocess.TimeoutExpired as exc:
                attempt = {"case_id": case_id, "seconds": round(time.monotonic() - start, 2),
                           "parse_error": "timeout", "stdout": str(exc.stdout or ""),
                           "stderr": str(exc.stderr or "")}
        result["attempts"].append(attempt)
        write_json(output, result)
        print(case_id, attempt["seconds"], "answered" if "answer" in attempt else
              attempt.get("infrastructure_error", attempt.get("parse_error")), flush=True)
        if attempt.get("infrastructure_error"):
            print("Stopping this run after an infrastructure error; resume with --retry once resolved.", flush=True)
            break


def grade(input_path, output):
    manifest = read_json(MANIFEST)
    run_data = read_json(input_path)
    manifest = variant_cases(manifest, run_data.get("variant", "custom"))
    attempts = {a["case_id"]: a for a in run_data["attempts"]}
    cases = []
    for item in manifest["cases"]:
        attempt = attempts.get(item["case_id"], {})
        answer = attempt.get("answer", {})
        status = ("answered" if "answer" in attempt else
                  attempt.get("infrastructure_error") or
                  infrastructure_error(str(attempt.get("stdout", "")), str(attempt.get("stderr", ""))) or
                  attempt.get("parse_error", "missing"))
        code = answer.get("code", "")
        code_ok = False
        # The binary oracle is the independent functional check.
        if isinstance(code, str) and len(code) <= 100 and code.isascii():
            proc = subprocess.run([str(ROOT / item["exe"]), code], capture_output=True, text=True, timeout=5)
            code_ok = proc.returncode == 0 and proc.stdout.strip() == "ACCEPT"
        hash_ok = answer.get("program_sha256") == item["program_sha256"]
        cases.append({"case_id": item["case_id"], "points": 75 * code_ok + 25 * hash_ok,
                      "code_correct": code_ok, "bytecode_hash_correct": hash_ok,
                      "status": status})
    report = {"track": "protected-vm", "score": sum(c["points"] for c in cases),
              "maximum": 100 * len(cases), "variant": run_data.get("variant", "custom"),
              "valid_full_bank": all(c["status"] == "answered" for c in cases), "cases": cases}
    write_json(output, report)
    print(report["score"], "/", report["maximum"])


def protect_themida(executable: Path, project: Path, output_dir: Path):
    """Optional genuine Themida pass; requires the user's installed licensed tool."""
    if not executable.is_file() or not project.is_file():
        raise SystemExit("Themida executable and .tmd/.tm project must exist")
    output_dir = output_dir.resolve()
    if not output_dir.is_relative_to(ROOT):
        raise SystemExit("Themida output directory must be inside the benchmark workspace")
    manifest = read_json(MANIFEST)
    results = []
    for item in manifest["cases"]:
        source = ROOT / item["exe"]
        destination = output_dir / item["case_id"] / "guard.exe"
        destination.parent.mkdir(parents=True, exist_ok=True)
        cmd = [str(executable), "/protect", str(project), "/inputfile", str(source),
               "/outputfile", str(destination)]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180,
                              encoding="utf-8", errors="replace")
        if proc.returncode or not destination.is_file():
            raise RuntimeError(f"Themida failed for {item['case_id']}: {proc.returncode} {proc.stdout[-1000:]} {proc.stderr[-1000:]}")
        verify_wrapped_oracle(source, destination, item["secret"], item["case_id"])
        results.append({"case_id": item["case_id"], "exe": str(destination.relative_to(ROOT)),
                        "sha256": hashlib.sha256(destination.read_bytes()).hexdigest()})
        print(item["case_id"], destination.stat().st_size, "protected bytes", flush=True)
    write_json(SOURCE / "themida_manifest.json", {"protector": "Themida", "cases": results})


def verify_wrapped_oracle(source: Path, destination: Path, secret: str, case_id: str):
    rng = random.Random(case_id)
    candidates = [secret, "A" * 24, "", secret[:-1], secret + "A", secret.lower()]
    candidates += ["".join(rng.choice(ALPHABET) for _ in range(24)) for _ in range(32)]
    for candidate in candidates:
        baseline = subprocess.run([str(source), candidate], capture_output=True, text=True, timeout=10)
        wrapped = subprocess.run([str(destination), candidate], capture_output=True, text=True, timeout=10)
        if (baseline.returncode, baseline.stdout.strip()) != (wrapped.returncode, wrapped.stdout.strip()):
            raise RuntimeError(f"Protected PE changed oracle behavior: {case_id}")
    if subprocess.run([str(destination), secret], capture_output=True, text=True, timeout=10).stdout.strip() != "ACCEPT":
        raise RuntimeError(f"Protected PE rejected the valid code: {case_id}")


def pack_upx(executable: Path, output_dir: Path):
    """Wrap our VM crackmes in a genuine UPX Windows PE packer layer."""
    if not executable.is_file():
        default = ROOT / "external" / "upx-5.2.1-win64" / "upx.exe"
        if executable.resolve() != default.resolve():
            raise SystemExit(f"UPX executable does not exist: {executable}")
        expected = "eabc6792a347d45e945be7748423e7868fd01b0d2bcaa2f4b1031fd71ff69bda"
        url = "https://github.com/upx/upx/releases/download/v5.2.1/upx-5.2.1-win64.zip"
        archive = urllib.request.urlopen(url, timeout=30).read()
        if hashlib.sha256(archive).hexdigest() != expected:
            raise RuntimeError("Official UPX archive SHA-256 mismatch")
        executable.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(BytesIO(archive)) as package:
            prefix = "upx-5.2.1-win64/"
            for name in ("upx.exe", "LICENSE", "COPYING"):
                (executable.parent / name).write_bytes(package.read(prefix + name))
    output_dir = output_dir.resolve()
    if not output_dir.is_relative_to(ROOT):
        raise SystemExit("UPX output directory must be inside the benchmark workspace")
    manifest = read_json(MANIFEST)
    results = []
    for item in manifest["cases"]:
        source = ROOT / item["exe"]
        destination = output_dir / item["case_id"] / "guard.exe"
        destination.parent.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run([str(executable), "--best", "--force", "-o", str(destination), str(source)],
                              capture_output=True, text=True, timeout=60)
        if proc.returncode or not destination.is_file():
            raise RuntimeError(f"UPX failed for {item['case_id']}: {proc.stdout[-1000:]} {proc.stderr[-1000:]}")
        check = subprocess.run([str(executable), "-t", str(destination)],
                               capture_output=True, text=True, timeout=60)
        if check.returncode:
            raise RuntimeError(f"UPX integrity check failed: {item['case_id']}")
        verify_wrapped_oracle(source, destination, item["secret"], item["case_id"])
        results.append({"case_id": item["case_id"], "exe": str(destination.relative_to(ROOT)),
                        "sha256": hashlib.sha256(destination.read_bytes()).hexdigest()})
        print(item["case_id"], destination.stat().st_size, "UPX packed bytes", flush=True)
    write_json(SOURCE / "upx_manifest.json", {"protector": "UPX", "version": "5.2.1", "cases": results})


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build")
    b.add_argument("--seed", type=int, default=None)
    b.add_argument("--count", type=int, default=3)
    r = sub.add_parser("run")
    r.add_argument("profile", choices=["codex", "claude", "opencode", "agy"])
    r.add_argument("--timeout", type=int, default=900)
    r.add_argument("--model", help="explicit Claude or OpenCode model")
    r.add_argument("--output", type=Path)
    r.add_argument("--themida", action="store_true", help="use genuine Themida-protected variants")
    r.add_argument("--upx", action="store_true", help="use genuine UPX-packed variants")
    r.add_argument("--case", action="append", default=[])
    r.add_argument("--retry", action="store_true", help="append a fresh attempt for selected cases")
    g = sub.add_parser("grade")
    g.add_argument("input", type=Path)
    g.add_argument("--output", type=Path)
    t = sub.add_parser("themida")
    t.add_argument("--executable", type=Path, required=True)
    t.add_argument("--project", type=Path, required=True)
    t.add_argument("--output-dir", type=Path, default=ROOT / "public_themida")
    u = sub.add_parser("upx")
    u.add_argument("--executable", type=Path, default=ROOT / "external" / "upx-5.2.1-win64" / "upx.exe")
    u.add_argument("--output-dir", type=Path, default=ROOT / "public_upx")
    args = parser.parse_args()
    if args.command == "build":
        build(args.seed if args.seed is not None else secrets.randbits(64), args.count)
    elif args.command == "run":
        if args.themida and args.upx:
            raise SystemExit("Choose either --themida or --upx")
        variant = "themida" if args.themida else ("upx" if args.upx else "custom")
        name = (variant + "_" if variant != "custom" else "") + args.profile + ".json"
        run(args.profile, args.output or ROOT / "results" / "protected" / name, args.timeout,
            variant, args.case, args.retry, args.model)
    elif args.command == "themida":
        protect_themida(args.executable, args.project, args.output_dir)
    elif args.command == "upx":
        pack_upx(args.executable, args.output_dir)
    else:
        grade(args.input, args.output or args.input.with_name(args.input.stem + "_score.json"))


if __name__ == "__main__":
    main()
