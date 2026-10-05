"""Continue an OpenCode case that was stopped by a runner time limit."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import benchmark


def decoded(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("case_id")
    parser.add_argument("session_id")
    parser.add_argument("export_file", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--timeout", type=int, default=3600)
    args = parser.parse_args()
    case = benchmark.select(benchmark.cases(), [args.case_id])[0]
    session = json.loads(args.export_file.read_text(encoding="utf-8-sig"))
    first = next(part["text"] for part in session["messages"][0]["parts"] if part["type"] == "text")
    match = re.search(r"Directorio de artefactos: ([^\r\n\"}]+)", first)
    if not match:
        raise SystemExit("Original artifact path missing in session")
    work = Path(match.group(1).strip()).resolve()
    temp_root = Path(os.environ["TEMP"]).resolve()
    if not work.is_relative_to(temp_root) or not work.name.startswith("rebench-"):
        raise SystemExit("Unsafe original workspace: " + str(work))
    for rel in case["artifacts"]:
        dest = work / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(benchmark.PUBLIC / rel, dest)
    native = Path(os.environ["LOCALAPPDATA"]) / "OpenCode" / "opencode-cli.exe"
    cli = str(native) if native.is_file() else shutil.which("opencode")
    if not cli:
        raise SystemExit("OpenCode CLI missing")
    prompt = ("Continúa el análisis de este mismo caso desde la sesión actual. "
              "Los mismos artefactos están de nuevo disponibles en el directorio original. "
              "Entrega la respuesta final en el JSON solicitado por el enunciado, sin pistas adicionales.")
    start = time.monotonic()
    entry = {"case_id": case["id"], "profile": "opencode", "resumed_session": args.session_id}
    try:
        proc = subprocess.run([cli, "run", "-s", args.session_id, prompt], cwd=work,
                              capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=args.timeout, shell=False)
        entry.update(exit_code=proc.returncode, seconds=round(time.monotonic() - start, 2),
                     raw_output=proc.stdout, stderr=proc.stderr[-5000:])
        try:
            entry["submission"] = benchmark.extract_answer(proc.stdout, case["id"])
        except ValueError as exc:
            entry["parse_error"] = str(exc)
    except subprocess.TimeoutExpired as exc:
        entry.update(seconds=round(time.monotonic() - start, 2), parse_error="timeout",
                     raw_output=decoded(exc.stdout)[-5000:], stderr=decoded(exc.stderr)[-5000:])
    result = {"benchmark_version": benchmark.cases()["version"],
              "started_at": datetime.now(timezone.utc).isoformat(),
              "profile": "opencode", "results": [entry],
              "submissions": [entry["submission"]] if "submission" in entry else []}
    benchmark.write_json(args.output, result)
    print(args.case_id, "saved", args.output, "status", entry.get("parse_error", "submitted"), flush=True)


if __name__ == "__main__":
    main()
