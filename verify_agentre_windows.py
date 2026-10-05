#!/usr/bin/env python3
"""Run upstream AgentRE V3 publication verification with POSIX ledger paths on Windows."""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent
UPSTREAM = ROOT / "external" / "AgentRE-Bench"
SPEC = importlib.util.spec_from_file_location("agentre_verify", UPSTREAM / "version3" / "verify.py")
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)


def verify_results_ledger_portable(run_manifest):
    ledger = verify.ROOT / run_manifest["publication"]["results_checksum_ledger"]
    verify.require(ledger.is_file(), "missing raw-results checksum ledger")
    verify.require(verify.sha256(ledger) == run_manifest["publication"]["results_checksum_ledger_sha256"],
                   "raw-results checksum-ledger mismatch")
    entries = {}
    for line in ledger.read_text(encoding="utf-8").splitlines():
        digest, relative_path = line.split("  ", 1)
        entries[relative_path] = digest
    expected = {path.relative_to(verify.ROOT).as_posix()
                for path in (verify.VERSION_DIR / "results").rglob("*") if path.is_file()}
    verify.require(set(entries) == expected, "raw-results checksum-ledger coverage mismatch")
    for relative_path, expected_hash in entries.items():
        verify.require(verify.sha256(verify.ROOT / relative_path) == expected_hash,
                       f"raw-results checksum mismatch: {relative_path}")


verify.verify_results_ledger = verify_results_ledger_portable

if __name__ == "__main__":
    raise SystemExit(verify.main())
