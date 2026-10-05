"""Verify v9 prompts and artifacts before reusing scored responses in v10."""

import hashlib
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import benchmark


def digest(raw):
    return hashlib.sha256(raw).hexdigest()

MANIFEST = ROOT / "results" / "v9" / "v9_evidence_manifest.json"


def snapshot():
    expected = json.loads(MANIFEST.read_text(encoding="utf-8"))
    return {
        case["id"]: {
            "prompt_sha256": digest(benchmark.prompt_for(case).encode("utf-8")),
            "artifacts": {rel: digest((benchmark.PUBLIC / rel).read_bytes())
                          for rel in case["artifacts"]},
        }
        for case in benchmark.cases()["cases"] if case["id"] in expected
    }


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"restore", "verify"}:
        raise SystemExit("Usage: verify_reuse.py restore|verify")
    expected = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if sys.argv[1] == "restore":
        restored = set()
        for case_id, row in expected.items():
            for rel, wanted in row["artifacts"].items():
                target = (benchmark.PUBLIC / rel).resolve()
                if target in restored or digest(target.read_bytes()) == wanted:
                    continue
                source = (ROOT / "public_export" / case_id / rel).resolve()
                if not target.is_relative_to(benchmark.PUBLIC.resolve()) or not source.is_relative_to((ROOT / "public_export").resolve()):
                    raise SystemExit("Unsafe artifact path")
                if not source.is_file() or digest(source.read_bytes()) != wanted:
                    raise SystemExit("Frozen v9 artifact missing or changed: " + rel)
                shutil.copy2(source, target)
                restored.add(target)
        print("Restored", len(restored), "v9 artifacts")
    else:
        actual = snapshot()
        if actual != expected:
            changed = [cid for cid in expected.keys() | actual.keys() if actual.get(cid) != expected.get(cid)]
            raise SystemExit("Changed v9 evidence: " + ", ".join(sorted(changed)))
        print("Verified unchanged", len(actual), "v9 cases")
