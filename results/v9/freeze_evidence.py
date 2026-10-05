"""Record exact public evidence for reproducible v9 reruns."""

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import benchmark
from verify_reuse import digest

MANIFEST = Path(__file__).with_name("v9_evidence_manifest.json")


def snapshot():
    return {
        case["id"]: {
            "prompt_sha256": digest(benchmark.prompt_for(case).encode("utf-8")),
            "artifacts": {rel: digest((benchmark.PUBLIC / rel).read_bytes())
                          for rel in case["artifacts"]},
        }
        for case in benchmark.cases()["cases"]
    }


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"capture", "restore", "verify"}:
        raise SystemExit("Usage: freeze_evidence.py capture|restore|verify")
    actual = snapshot()
    if sys.argv[1] == "capture":
        if MANIFEST.exists():
            raise SystemExit("Manifest already exists")
        MANIFEST.write_text(json.dumps(actual, indent=2) + "\n", encoding="utf-8")
        print("Captured", len(actual), "v9 cases")
    elif sys.argv[1] == "restore":
        expected = json.loads(MANIFEST.read_text(encoding="utf-8"))
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
                    raise SystemExit("Frozen artifact missing or changed: " + rel)
                shutil.copy2(source, target)
                restored.add(target)
        print("Restored", len(restored), "frozen artifacts")
    else:
        expected = json.loads(MANIFEST.read_text(encoding="utf-8"))
        if actual != expected:
            changed = [case_id for case_id in expected.keys() | actual.keys()
                       if expected.get(case_id) != actual.get(case_id)]
            raise SystemExit("Changed v9 evidence: " + ", ".join(sorted(changed)))
        print("Verified", len(actual), "v9 cases")
