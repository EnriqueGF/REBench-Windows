#!/usr/bin/env python3
"""Run and score the two hard Windows RE tracks as a single 1300-point bank."""
from __future__ import annotations

import argparse
from pathlib import Path

import agentre_track
import protected_vm_bench

ROOT = Path(__file__).resolve().parent


def paths(profile):
    return (ROOT / "results" / "hard_suite" / "inputs" / f"{profile}_research.json",
            ROOT / "results" / "hard_suite" / "inputs" / f"{profile}_upx_vm.json")


def grade(profile):
    research_path, protected_path = paths(profile)
    if not research_path.is_file() or not protected_path.is_file():
        raise SystemExit("Both track result files are required before grading the hard suite")
    research_score = research_path.with_name(research_path.stem + "_score.json")
    protected_score = protected_path.with_name(protected_path.stem + "_score.json")
    agentre_track.grade(research_path, research_score)
    protected_vm_bench.grade(protected_path, protected_score)
    research = agentre_track.load_json(research_score)
    protected = protected_vm_bench.read_json(protected_score)
    research_run = agentre_track.load_json(research_path)
    protected_run = protected_vm_bench.read_json(protected_path)
    research_points = round(sum(case["score"] for case in research["cases"]) * 100, 4)
    research_maximum = 100 * len(research["cases"])
    protected_maximum = protected["maximum"]
    maximum = research_maximum + protected_maximum
    report = {
        "version": "11-experimental",
        "profile": profile,
        "research_timeout_seconds": research_run.get("timeout_seconds"),
        "vm_timeout_seconds": protected_run.get("timeout_seconds"),
        "score": round(research_points + protected["score"], 4),
        "maximum": maximum,
        "research_points": research_points,
        "research_maximum": research_maximum,
        "protected_points": protected["score"],
        "protected_maximum": protected_maximum,
        "answered_research": research["answered"],
        "answered_protected": sum(case["status"] == "answered" for case in protected["cases"]),
        "valid_full_bank": research["valid_full_bank"] and protected["valid_full_bank"],
        "ceiling_detected": research_points + protected["score"] >= 0.95 * maximum,
        "research_statuses": {case["case_id"]: case["status"] for case in research["cases"]},
        "protected_statuses": {case["case_id"]: case["status"] for case in protected["cases"]},
    }
    report["ranking_publishable"] = report["valid_full_bank"] and not report["ceiling_detected"]
    output = ROOT / "results" / "hard_suite" / f"{profile}_score.json"
    agentre_track.dump_json(output, report)
    print(f"{report['score']}/{maximum}; complete={report['valid_full_bank']}; {output}")


def main():
    parser = argparse.ArgumentParser(description="1300-point Windows RE hard suite")
    sub = parser.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run")
    r.add_argument("profile", choices=["codex", "claude", "opencode", "agy"])
    r.add_argument("--research-timeout", type=int, default=300)
    r.add_argument("--vm-timeout", type=int, default=300)
    r.add_argument("--model", help="explicit Claude or OpenCode model")
    g = sub.add_parser("grade")
    g.add_argument("profile", choices=["codex", "claude", "opencode", "agy"])
    args = parser.parse_args()
    if args.command == "run":
        research_path, protected_path = paths(args.profile)
        agentre_track.run(args.profile, [], research_path, args.research_timeout, model=args.model)
        attempts = agentre_track.load_json(research_path)["attempts"]
        if attempts and attempts[-1].get("infrastructure_error"):
            print("Research stage stopped by infrastructure; fix it and rerun before grading.")
            return
        protected_vm_bench.run(args.profile, protected_path, args.vm_timeout, "upx", model=args.model)
        attempts = protected_vm_bench.read_json(protected_path)["attempts"]
        if attempts and attempts[-1].get("infrastructure_error"):
            print("Protected VM stage stopped by infrastructure; fix it and rerun before grading.")
            return
    grade(args.profile)


if __name__ == "__main__":
    main()
