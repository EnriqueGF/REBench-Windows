#!/usr/bin/env python3
"""Import a completed Claude background benchmark session for normal scoring."""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from protected_vm_bench import parse_answer, write_json


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("transcript", type=Path)
    parser.add_argument("--case", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--started-at-ms", type=int, required=True)
    parser.add_argument("--timeout", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    final = None
    for line in args.transcript.read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        if (event.get("type") != "assistant" or
                event.get("session_id") != args.session_id or
                event.get("sessionKind") != "bg"):
            continue
        message = event.get("message", {})
        if message.get("model") != args.model or message.get("stop_reason") != "end_turn":
            continue
        for block in message.get("content", []):
            if block.get("type") != "text":
                continue
            try:
                answer = parse_answer(block.get("text", ""), args.case)
            except ValueError:
                continue
            final = (event["timestamp"], block["text"], answer)
    if final is None:
        raise SystemExit("No final JSON answer for the requested case in transcript")

    finished = datetime.fromisoformat(final[0].replace("Z", "+00:00"))
    started = datetime.fromtimestamp(args.started_at_ms / 1000, tz=timezone.utc)
    elapsed = (finished - started).total_seconds()
    if not 0 <= elapsed <= args.timeout:
        raise SystemExit(f"Answer timestamp is outside the {args.timeout}s budget: {elapsed:.2f}s")
    attempt = {
        "case_id": args.case,
        "seconds": round(elapsed, 2),
        "exit_code": 0,
        "stdout": final[1],
        "stderr": "",
        "answer": final[2],
        "execution_mode": "claude_background",
        "session_id": args.session_id,
        "transcript_sha256": hashlib.sha256(args.transcript.read_bytes()).hexdigest(),
    }
    write_json(args.output, {
        "track": "protected-vm",
        "variant": "upx",
        "profile": "claude",
        "model": args.model,
        "timeout_seconds": args.timeout,
        "attempts": [attempt],
    })
    print(f"Imported {args.case}: {elapsed:.2f}s; {args.output}")


if __name__ == "__main__":
    main()
