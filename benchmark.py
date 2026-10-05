#!/usr/bin/env python3
"""REBench-Windows: local, dependency-free reverse engineering benchmark."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
PUBLIC = ROOT / "public"
KEY = ROOT / "private" / "answer_key.json"
CASE_FILE = PUBLIC / "cases.json"
PROFILES = {
    "codex": ["codex", "exec", "--skip-git-repo-check", "--sandbox", "read-only", "--ephemeral", "--color", "never", "{prompt}"],
    "claude": ["claude", "-p", "{prompt}", "--output-format", "text"],
    "opencode": ["opencode", "run", "{prompt}"],
    "agy": ["agy", "--print", "{prompt}", "--output-format", "text", "--dangerously-skip-permissions"],
}
MASK64 = (1 << 64) - 1


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def cases():
    data = read_json(CASE_FILE)
    validate(data)
    return data


def validate(data):
    ids = set()
    for case in data["cases"]:
        cid = case["id"]
        if cid in ids:
            raise ValueError(f"Duplicate case: {cid}")
        ids.add(cid)
        qids = set()
        for q in case["questions"]:
            if q["id"] in qids:
                raise ValueError(f"Duplicate question: {cid}/{q['id']}")
            qids.add(q["id"])
            if q["type"] in ("single", "multi") and len(q["options"]) < 3:
                raise ValueError(f"Too few options: {cid}/{q['id']}")
        for rel in case["artifacts"]:
            path = (PUBLIC / rel).resolve()
            if not path.is_relative_to(PUBLIC.resolve()) or not path.is_file():
                raise ValueError(f"Missing or unsafe artifact: {rel}")


def select(data, names):
    selected = [c for c in data["cases"] if not names or c["id"] in names]
    missing = set(names or []) - {c["id"] for c in selected}
    if missing:
        raise SystemExit("Unknown case(s): " + ", ".join(sorted(missing)))
    return selected


def prompt_for(case):
    lines = [
        "Eres analista de ingeniería inversa. Resuelve el caso usando exclusivamente la evidencia adjunta.",
        "No presupongas datos que no aparecen. Devuelve SOLO un objeto JSON válido, sin Markdown.",
        'Formato: {"case_id":"ID","answers":{"q1":"A","q2":["A","C"],"q3":"0x1234"},"reasoning":"explicación breve con evidencia"}.',
        "En preguntas multi, devuelve una lista de letras. Para valores, usa el formato pedido.",
        f"\nCASO {case['id']}: {case['title']}",
        case["scenario"],
    ]
    if case.get("track") in {"expert", "research"}:
        lines.append("Herramientas disponibles: Python 3 con pefile y capstone, comandos locales y ejecución de los PE de prueba. "
                     "Puedes crear scripts en el directorio temporal. No necesitas IDA. Examina el binario antes de concluir que faltan datos.")
    for rel in case["artifacts"]:
        raw = (PUBLIC / rel).read_bytes()
        try:
            body = raw.decode("utf-8")
            lines.extend([f"\n--- ARTEFACTO {rel} ---", body])
        except UnicodeDecodeError:
            lines.extend([f"\n--- ARTEFACTO BINARIO {rel} ---", f"SHA256: {hashlib.sha256(raw).hexdigest()}", f"Bytes: {len(raw)}. Archivo disponible en el directorio del caso."])
    for q in case["questions"]:
        lines.append(f"\n{q['id']} [{q['type']}]: {q['prompt']}")
        if "options" in q:
            lines.extend(f"  {letter}. {value}" for letter, value in q["options"].items())
    return "\n".join(lines)


def extract_answer(raw, case_id):
    raw = raw.strip()
    candidates = [raw]
    candidates += re.findall(r"```(?:json)?\s*([\s\S]*?)```", raw, re.IGNORECASE)
    starts = [m.start() for m in re.finditer(r"\{", raw)]
    decoder = json.JSONDecoder()
    for start in reversed(starts):
        try:
            obj, _ = decoder.raw_decode(raw[start:])
            candidates.append(json.dumps(obj))
        except json.JSONDecodeError:
            continue
    for item in candidates:
        try:
            obj = json.loads(item)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and obj.get("case_id") == case_id and isinstance(obj.get("answers"), dict):
            return obj
    raise ValueError("No valid answer object found for " + case_id)


def normalize(value):
    if isinstance(value, str):
        return value.strip().casefold()
    return value


def correct(q, got, expected):
    if got is None:
        return False
    if q["type"] == "literal":
        return isinstance(got, str) and got.strip() == expected
    if q["type"] == "multi":
        if isinstance(got, str):
            got = re.findall(r"[A-Z]", got.upper())
        return isinstance(got, list) and {str(x).upper() for x in got} == set(expected)
    if q["type"] == "hex":
        try:
            return int(str(got).replace("`", "").strip(), 0) == int(str(expected), 0)
        except ValueError:
            return False
    return normalize(got) == normalize(expected)


def eval_pipeline64(program, x: int, y: int, data: bytes | None = None) -> int:
    """Run a bounded expression DSL; no submitted code is executed."""
    if not isinstance(program, dict) or not isinstance(program.get("steps"), list):
        raise ValueError("pipeline64 requires a steps list")
    steps = program["steps"]
    if not 1 <= len(steps) <= 64:
        raise ValueError("pipeline64 must have 1..64 top-level steps")
    if data is not None and (not isinstance(data, bytes) or len(data) > 96):
        raise ValueError("stream input must contain 0..96 bytes")
    registers = {"x": x & MASK64, "y": y & MASK64}
    if data is not None:
        registers["n"] = len(data)
    assigned = set()

    def constant(value):
        if type(value) is int and value.bit_length() <= 65:
            return value & MASK64
        if isinstance(value, str) and len(value) <= 30 and value.startswith(("0x", "0X", "-0x", "-0X")):
            return int(value, 0) & MASK64
        raise ValueError("invalid constant")

    source_tables = program.get("tables", {})
    if not isinstance(source_tables, dict) or len(source_tables) > 4:
        raise ValueError("invalid tables")
    tables = {}
    for name, values in source_tables.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,15}", name):
            raise ValueError("invalid table name")
        if not isinstance(values, list) or not 1 <= len(values) <= 16:
            raise ValueError("invalid table length")
        tables[name] = [constant(item) for item in values]

    def operand(value):
        if isinstance(value, str) and value in registers:
            return registers[value]
        return constant(value)

    executed = 0

    def run(sequence, nested=False):
        nonlocal executed
        if not isinstance(sequence, list) or len(sequence) > 64:
            raise ValueError("invalid step sequence")
        for step in sequence:
            if not isinstance(step, dict):
                raise ValueError("invalid step")
            op = step.get("op")
            if op == "loop":
                count, body = step.get("count"), step.get("body")
                if nested or type(count) is not int or not 1 <= count <= 16 or not isinstance(body, list) or not 1 <= len(body) <= 32:
                    raise ValueError("invalid loop")
                for index in range(count):
                    registers["i"] = index
                    run(body, True)
                registers.pop("i", None)
                continue
            if op in {"each", "each_reverse"}:
                body = step.get("body")
                if data is None or nested or not isinstance(body, list) or not 1 <= len(body) <= 32:
                    raise ValueError("invalid each loop")
                indexes = range(len(data)) if op == "each" else range(len(data) - 1, -1, -1)
                for index in indexes:
                    byte = data[index]
                    registers["i"] = index
                    registers["byte"] = byte
                    run(body, True)
                registers.pop("i", None)
                registers.pop("byte", None)
                continue
            executed += 1
            if executed > (8192 if data is not None else 256):
                raise ValueError("too many executed steps")
            dst = step.get("dst")
            if not isinstance(dst, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,15}", dst) or dst in {"x", "y", "n", "i", "byte"}:
                raise ValueError("invalid destination register")
            if op in {"add", "sub", "xor", "and", "or", "mul"}:
                a, b = operand(step.get("a")), operand(step.get("b"))
                value = {"add": lambda: a + b, "sub": lambda: a - b, "xor": lambda: a ^ b,
                         "and": lambda: a & b, "or": lambda: a | b, "mul": lambda: a * b}[op]()
            elif op in {"rol", "ror", "shl", "shr"}:
                a = operand(step.get("a"))
                bits = step.get("bits", step.get("b"))
                if type(bits) is not int or not 0 <= bits <= 63:
                    raise ValueError("bits must be an integer 0..63")
                if op == "rol":
                    value = (a << bits) | (a >> ((64 - bits) % 64))
                elif op == "ror":
                    value = (a >> bits) | (a << ((64 - bits) % 64))
                elif op == "shl":
                    value = a << bits
                else:
                    value = a >> bits
            elif op == "sel":
                value = operand(step.get("a")) if operand(step.get("cond")) != 0 else operand(step.get("b"))
            elif op == "not":
                value = ~operand(step.get("a"))
            elif op == "lookup":
                table = step.get("table")
                if table not in tables:
                    raise ValueError("unknown table")
                index = operand(step.get("index"))
                value = tables[table][index % len(tables[table])]
            else:
                raise ValueError("unknown operation")
            registers[dst] = value & MASK64
            assigned.add(dst)

    run(steps)
    result = program.get("return")
    if result not in assigned:
        raise ValueError("return must name an assigned register")
    return registers[result]


def pipeline64_points(got, expected, points: int) -> int:
    vectors = [(0, 0), (1, 0), (0, 1), (MASK64, 0), (0, MASK64),
               (MASK64, MASK64), (0x20, 0), (0, 0x20), (0x1F, 0), (0x20, 0x20)]
    generator = random.Random(0x5EED2026)
    vectors += [(generator.getrandbits(64), generator.getrandbits(64)) for _ in range(246)]
    try:
        matches = sum(eval_pipeline64(got, x, y) == eval_pipeline64(expected, x, y) for x, y in vectors)
    except (ValueError, TypeError, KeyError, OverflowError):
        return 0
    return round(points * matches / len(vectors))


def stream64_vectors():
    """Held-out lengths, byte classes and branch patterns for a stream transform."""
    vectors = [b"", b"\x00", b"\xff", bytes(range(16)), bytes(range(96)),
               bytes([0xff] * 96), bytes([0x55, 0xaa] * 48)]
    lengths = [0, 1, 2, 3, 4, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 95, 96]
    for length in lengths:
        vectors.extend([bytes(length), bytes([0xff] * length),
                        bytes((i * 37 + length) & 0xff for i in range(length))])
    generator = random.Random(0x51EA2027)
    vectors += [generator.randbytes(generator.randrange(97)) for _ in range(323)]
    return vectors


def stream64_points(got, expected, points: int) -> int:
    vectors = stream64_vectors()
    try:
        matches = sum(eval_pipeline64(got, 0, 0, data) == eval_pipeline64(expected, 0, 0, data)
                      for data in vectors)
    except (ValueError, TypeError, KeyError, OverflowError):
        return 0
    return round(points * matches / len(vectors))


def aob_points(got, expected, points: int) -> int:
    if isinstance(got, dict):
        got = got.get("pattern")
    if not isinstance(got, str):
        return 0
    tokens = got.strip().split()
    if not 8 <= len(tokens) <= 64:
        return 0
    try:
        signature = [None if token in {"?", "??"} else int(token, 16)
                     if re.fullmatch(r"[0-9A-Fa-f]{2}", token) else ValueError("bad token") for token in tokens]
    except (ValueError, TypeError):
        return 0
    if any(isinstance(item, ValueError) for item in signature):
        return 0
    if sum(item is not None for item in signature) < 8:
        return 0
    targets = expected.get("targets", []) if isinstance(expected, dict) else []
    if len(targets) != 4:
        return 0
    earned = 0
    for target in targets:
        path = (ROOT / target["path"]).resolve()
        if not path.is_relative_to(ROOT.resolve()) or not path.is_file():
            continue
        raw = path.read_bytes()
        try:
            pe = struct.unpack_from("<I", raw, 0x3C)[0]
            if raw[:2] != b"MZ" or raw[pe:pe + 4] != b"PE\0\0":
                continue
            sections = pe + 24 + struct.unpack_from("<H", raw, pe + 20)[0]
            count = struct.unpack_from("<H", raw, pe + 6)[0]
            text_section = None
            for section_index in range(count):
                offset = sections + section_index * 40
                if raw[offset:offset + 8].rstrip(b"\0") == b".text":
                    va, size, pointer = struct.unpack_from("<III", raw, offset + 12)
                    text_section = (va, raw[pointer:pointer + size])
                    break
            if text_section is None:
                continue
            va, code = text_section
            hits = []
            for pos in range(len(code) - len(signature) + 1):
                if all(byte is None or code[pos + index] == byte for index, byte in enumerate(signature)):
                    hits.append(va + pos)
                    if len(hits) == 2:
                        break
            if hits == [int(target["rva"], 0)]:
                earned += points // 4
        except (ValueError, IndexError, struct.error, KeyError):
            continue
    return earned


def patch_aob_points(got, expected, points: int) -> int:
    """Grade bounded branch-opcode patches across visible and held-out PE builds."""
    if points != 120 or not isinstance(got, dict) or not isinstance(expected, dict):
        return 0
    sites = got.get("sites")
    versions = expected.get("versions")
    if not isinstance(sites, dict) or set(sites) != {"length", "flag"} or not isinstance(versions, list) or len(versions) != 4:
        return 0
    prepared = {}
    for name in ("length", "flag"):
        site = sites[name]
        if not isinstance(site, dict) or not isinstance(site.get("pattern"), str):
            return 0
        tokens = site["pattern"].strip().split()
        if not 8 <= len(tokens) <= 64 or sum(token not in {"?", "??"} for token in tokens) < 8:
            return 0
        if any(token not in {"?", "??"} and not re.fullmatch(r"[0-9A-Fa-f]{2}", token) for token in tokens):
            return 0
        offset = site.get("offset")
        if type(offset) is not int or not 0 <= offset < len(tokens):
            return 0
        value = site.get("byte")
        if not isinstance(value, str) or not re.fullmatch(r"[0-9A-Fa-f]{2}", value):
            return 0
        patch_byte = int(value, 16)
        if patch_byte != {"length": 0x77, "flag": 0x74}[name]:
            return 0
        prepared[name] = ([None if token in {"?", "??"} else int(token, 16)
                           for token in tokens], offset, patch_byte)

    earned = 0
    for version in versions:
        try:
            path = (ROOT / version["path"]).resolve()
            if not path.is_relative_to(ROOT.resolve()) or not path.is_file():
                continue
            raw = path.read_bytes()
            pe = struct.unpack_from("<I", raw, 0x3C)[0]
            if raw[:2] != b"MZ" or raw[pe:pe + 4] != b"PE\0\0":
                continue
            sections = pe + 24 + struct.unpack_from("<H", raw, pe + 20)[0]
            count = struct.unpack_from("<H", raw, pe + 6)[0]
            text_section = None
            for section_index in range(count):
                section = sections + section_index * 40
                if raw[section:section + 8].rstrip(b"\0") == b".text":
                    rva, size, pointer = struct.unpack_from("<III", raw, section + 12)
                    text_section = (rva, pointer, raw[pointer:pointer + size])
                    break
            if text_section is None:
                continue
            rva, pointer, code = text_section
            correct_sites = set()
            for name, (signature, offset, patch_byte) in prepared.items():
                hits = []
                for pos in range(len(code) - len(signature) + 1):
                    if all(byte is None or code[pos + i] == byte for i, byte in enumerate(signature)):
                        hits.append(pos)
                        if len(hits) > 1:
                            break
                target = int(version[name + "_rva"], 0)
                expected_old = {"length": 0x73, "flag": 0x75}[name]
                if hits == [target - rva - offset] and code[target - rva] == expected_old:
                    earned += 10
                    correct_sites.add(name)
            if len(correct_sites) == 2:
                patched = bytearray(raw)
                for name, (_, _, patch_byte) in prepared.items():
                    patched[pointer + int(version[name + "_rva"], 0) - rva] = patch_byte
                with tempfile.TemporaryDirectory(prefix="rebench-verified-patch-") as folder:
                    fixed = Path(folder) / "fixed.exe"
                    fixed.write_bytes(patched)
                    if all((run := subprocess.run([str(fixed), test["x"], test["y"]],
                                                  capture_output=True, text=True, timeout=2)).returncode == 0
                           and run.stdout.strip() == test["output"]
                           for test in expected["tests"]):
                        earned += 10
        except (ValueError, IndexError, KeyError, struct.error, OSError, subprocess.TimeoutExpired):
            continue
    return earned


def grade(data, submissions, key):
    submitted_ids = [x.get("case_id") for x in submissions if isinstance(x, dict)]
    if len(submitted_ids) != len(set(submitted_ids)):
        raise ValueError("Duplicate case_id in submissions")
    answer_map = {x["case_id"]: x for x in submissions}
    rows = []
    for case in data:
        submitted = answer_map.get(case["id"], {})
        answers = submitted.get("answers", {})
        if not isinstance(answers, dict):
            answers = {}
        for q in case["questions"]:
            expected = key[case["id"]][q["id"]]["answer"]
            got = answers.get(q["id"])
            points = q.get("points", 1)
            if q["type"] == "pipeline64":
                earned = pipeline64_points(got, expected, points)
            elif q["type"] == "stream64":
                earned = stream64_points(got, expected, points)
            elif q["type"] == "stream2_64":
                earned = stream64_points(got, expected, points)
            elif q["type"] == "aob":
                earned = aob_points(got, expected, points)
            elif q["type"] == "patch_aob":
                earned = patch_aob_points(got, expected, points)
            else:
                earned = points if correct(q, got, expected) else 0
            rows.append({"case_id": case["id"], "question_id": q["id"], "category": case["category"],
                         "type": q["type"], "points": points, "earned": earned,
                         "submitted": got, "expected": expected})
    total = sum(row["points"] for row in rows)
    earned = sum(row["earned"] for row in rows)
    breakdown = {}
    tracks = {}
    case_tracks = {case["id"]: case.get("track", "foundations") for case in data}
    for row in rows:
        item = breakdown.setdefault(row["category"], {"earned": 0, "total": 0})
        item["earned"] += row["earned"]
        item["total"] += row["points"]
        track = tracks.setdefault(case_tracks[row["case_id"]], {"earned": 0, "total": 0})
        track["earned"] += row["earned"]
        track["total"] += row["points"]
    return {"earned": earned, "total": total, "percent": round(100 * earned / total, 2) if total else 0,
            "by_category": breakdown, "by_track": tracks, "rows": rows,
            "missing_cases": sorted(set(c["id"] for c in data) - set(answer_map))}


def load_submissions(path):
    raw = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".jsonl":
        return [json.loads(line) for line in raw.splitlines() if line.strip()]
    obj = json.loads(raw)
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict) and "submissions" in obj:
        return obj["submissions"]
    return [obj]


def command_list(profile, config, prompt):
    templates = config.get("profiles", {}).get(profile, PROFILES.get(profile))
    if not isinstance(templates, list) or not templates or not all(isinstance(x, str) for x in templates):
        raise SystemExit(f"Invalid or missing profile: {profile}")
    return [part.replace("{prompt}", prompt) for part in templates]


def run_case(case, profile, config, timeout):
    # Agents may create Windows-reserved names such as "nul"; cleanup must not
    # erase the result of a completed run or a timeout on Windows.
    with tempfile.TemporaryDirectory(prefix="rebench-", ignore_cleanup_errors=True) as tmp:
        work = Path(tmp)
        for rel in case["artifacts"]:
            dest = work / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(PUBLIC / rel, dest)
        prompt = prompt_for(case) + f"\n\nDirectorio de artefactos: {work}"
        cmd = command_list(profile, config, prompt)
        cmd[0] = shutil.which(cmd[0]) or cmd[0]
        if os.name == "nt" and profile == "opencode" and Path(cmd[0]).suffix.lower() in (".cmd", ".bat"):
            native = Path(os.environ.get("LOCALAPPDATA", "")) / "OpenCode" / "opencode-cli.exe"
            if native.is_file():
                cmd[0] = str(native)
        started = time.monotonic()
        try:
            proc = subprocess.run(cmd, cwd=work, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, shell=False)
            raw = proc.stdout
            entry = {"case_id": case["id"], "profile": profile, "exit_code": proc.returncode,
                     "seconds": round(time.monotonic() - started, 2), "raw_output": raw, "stderr": proc.stderr[-5000:]}
            try:
                entry["submission"] = extract_answer(raw, case["id"])
            except ValueError as exc:
                entry["parse_error"] = str(exc)
            return entry
        except subprocess.TimeoutExpired as exc:
            def decode_partial(value):
                if isinstance(value, bytes):
                    return value.decode("utf-8", errors="replace")
                return value or ""
            return {"case_id": case["id"], "profile": profile,
                    "seconds": round(time.monotonic() - started, 2), "parse_error": "timeout",
                    "raw_output": decode_partial(exc.stdout)[-5000:],
                    "stderr": decode_partial(exc.stderr)[-5000:]}
        except FileNotFoundError as exc:
            return {"case_id": case["id"], "profile": profile, "parse_error": str(exc)}


def main():
    parser = argparse.ArgumentParser(description="REBench-Windows")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="List cases")
    show = sub.add_parser("show", help="Show a public case prompt")
    show.add_argument("case_id")
    export = sub.add_parser("export", help="Export prompts to a directory")
    export.add_argument("directory", type=Path)
    export.add_argument("--case", action="append")
    run = sub.add_parser("run", help="Run an agent profile")
    run.add_argument("profile", choices=list(PROFILES))
    run.add_argument("--case", action="append")
    run.add_argument("--config", type=Path)
    run.add_argument("--timeout", type=int, default=300)
    run.add_argument("--jobs", type=int, default=1, help="Number of independent cases to run concurrently")
    run.add_argument("--output", type=Path, required=True)
    gr = sub.add_parser("grade", help="Grade JSON/JSONL responses against private key")
    gr.add_argument("input", type=Path)
    gr.add_argument("--output", type=Path)
    gr.add_argument("--reveal", action="store_true", help="Include correct answers in report")
    gr.add_argument("--case", action="append")
    check = sub.add_parser("validate", help="Validate public cases and private key")
    solutions = sub.add_parser("solutions", help="Show detailed solutions from private key")
    solutions.add_argument("--case", action="append")
    compare = sub.add_parser("compare", help="Compare two or more agent result files")
    compare.add_argument("inputs", nargs="+", type=Path)
    compare.add_argument("--output", type=Path)
    args = parser.parse_args()
    data = cases()
    if args.command == "list":
        for c in data["cases"]:
            print(f"{c['id']:18} {c.get('track', 'foundations'):12} {c['category']:16} {c['difficulty']:7} {len(c['questions'])} preguntas  {c['title']}")
    elif args.command == "show":
        print(prompt_for(select(data, [args.case_id])[0]))
    elif args.command == "export":
        for c in select(data, args.case):
            folder = args.directory / c["id"]
            folder.mkdir(parents=True, exist_ok=True)
            (folder / "prompt.txt").write_bytes(prompt_for(c).encode("utf-8"))
            for rel in c["artifacts"]:
                dest = folder / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(PUBLIC / rel, dest)
        print(f"Exported {len(select(data, args.case))} cases to {args.directory}")
    elif args.command == "run":
        if args.jobs < 1 or args.jobs > 8:
            raise SystemExit("--jobs must be between 1 and 8")
        config = read_json(args.config) if args.config else {}
        selected = select(data, args.case)
        results = {}
        started_at = datetime.now(timezone.utc).isoformat()
        def save():
            ordered = [results[c["id"]] for c in selected if c["id"] in results]
            write_json(args.output, {"benchmark_version": data["version"], "started_at": started_at,
                                     "profile": args.profile, "results": ordered,
                                     "submissions": [r["submission"] for r in ordered if "submission" in r]})
        if args.jobs == 1:
            for c in selected:
                print(f"Running {args.profile}: {c['id']}", flush=True)
                results[c["id"]] = run_case(c, args.profile, config, args.timeout)
                save()
        else:
            with ThreadPoolExecutor(max_workers=args.jobs) as pool:
                futures = {pool.submit(run_case, c, args.profile, config, args.timeout): c for c in selected}
                for future in as_completed(futures):
                    c = futures[future]
                    results[c["id"]] = future.result()
                    print(f"Finished {args.profile}: {c['id']} ({len(results)}/{len(selected)})", flush=True)
                    save()
        print(f"Saved {args.output}")
    elif args.command == "grade":
        if not KEY.is_file():
            raise SystemExit("Private key missing: " + str(KEY))
        report = grade(select(data, args.case), load_submissions(args.input), read_json(KEY))
        if not args.reveal:
            for row in report["rows"]:
                row.pop("expected")
        if args.output:
            write_json(args.output, report)
        print(f"Score: {report['earned']}/{report['total']} ({report['percent']}%)")
        for row in report["rows"]:
            print(f"{row['case_id']}/{row['question_id']}: {row['earned']}/{row['points']}")
    elif args.command == "validate":
        key = read_json(KEY)
        for c in data["cases"]:
            if {q["id"] for q in c["questions"]} != set(key.get(c["id"], {})):
                raise SystemExit(f"Key mismatch: {c['id']}")
            for q in c["questions"]:
                answer = key[c["id"]][q["id"]]["answer"]
                if q["type"] in ("single", "multi"):
                    letters = answer if isinstance(answer, list) else [answer]
                    if not set(letters) <= set(q["options"]):
                        raise SystemExit(f"Invalid option in key: {c['id']}/{q['id']}")
                elif q["type"] == "pipeline64":
                    try:
                        eval_pipeline64(answer, 0, 0)
                        eval_pipeline64(answer, MASK64, 0x20)
                    except (ValueError, TypeError, KeyError) as exc:
                        raise SystemExit(f"Invalid pipeline key in {c['id']}/{q['id']}: {exc}")
                elif q["type"] in ("stream64", "stream2_64"):
                    try:
                        eval_pipeline64(answer, 0, 0, b"")
                        eval_pipeline64(answer, 0, 0, bytes(range(96)))
                    except (ValueError, TypeError, KeyError) as exc:
                        raise SystemExit(f"Invalid stream key in {c['id']}/{q['id']}: {exc}")
                elif q["type"] == "aob":
                    if aob_points(key[c["id"]][q["id"]]["canonical_pattern"], answer, q["points"]) != q["points"]:
                        raise SystemExit(f"Invalid AOB key in {c['id']}/{q['id']}")
                elif q["type"] == "patch_aob":
                    if patch_aob_points(key[c["id"]][q["id"]]["canonical_patch"], answer, q["points"]) != q["points"]:
                        raise SystemExit(f"Invalid patch key in {c['id']}/{q['id']}")
        print(f"Validated {len(data['cases'])} cases and {sum(len(c['questions']) for c in data['cases'])} questions")
    elif args.command == "solutions":
        key = read_json(KEY)
        for c in select(data, args.case):
            print(f"\n{c['id']} — {c['title']}")
            for q in c["questions"]:
                solution = key[c["id"]][q["id"]]
                print(f"  {q['id']}: {solution['answer']} — {solution['resolution']}")
    elif args.command == "compare":
        key = read_json(KEY)
        comparison = []
        for path in args.inputs:
            payload = read_json(path)
            submissions = load_submissions(path)
            report = grade(data["cases"], submissions, key)
            runs = payload.get("results", []) if isinstance(payload, dict) else []
            comparison.append({"file": str(path), "profile": payload.get("profile", path.stem) if isinstance(payload, dict) else path.stem,
                               "earned": report["earned"], "total": report["total"], "percent": report["percent"],
                               "completed": len(submissions), "seconds": round(sum(x.get("seconds", 0) for x in runs), 2),
                               "by_category": report["by_category"]})
        comparison.sort(key=lambda x: (-x["earned"], x["seconds"]))
        for rank, entry in enumerate(comparison, 1):
            print(f"{rank}. {entry['profile']}: {entry['earned']}/{entry['total']} ({entry['percent']}%), "
                  f"{entry['completed']} casos, {entry['seconds']} s")
        if args.output:
            write_json(args.output, {"benchmark_version": data["version"], "ranking": comparison})


if __name__ == "__main__":
    main()
