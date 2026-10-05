"""Combine unchanged foundation runs with the guided expert runs."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import benchmark

V2_EXPERT_IDS = {"hard_license", "hard_vm", "hard_pattern"}
CASES = [case for case in benchmark.cases()["cases"]
         if case.get("track") == "foundations" or case["id"] in V2_EXPERT_IDS]
KEY = benchmark.read_json(benchmark.KEY)
EXPERT_IDS = V2_EXPERT_IDS
FOUNDATION_IDS = {case["id"] for case in CASES if case.get("track") == "foundations"}
evidence = json.loads((HERE / "baseline_reuse_evidence.json").read_text(encoding="utf-8"))
assert len(evidence["checks"]) == len(FOUNDATION_IDS)
assert all(row["same_nonempty_prompt_lines"] and row["same_artifact_bytes"] for row in evidence["checks"])

SPECS = [
    ("codex", "gpt-6-sol", ["codex_guided.json"]),
    ("claude", "claude-opus-4-7", ["claude_license_guided.json", "claude_guided_rest.json"]),
    ("opencode", "explabs/glm-5.3-flash-abliterated", ["opencode_guided.json"]),
]
summary = []
reports = {}
for name, model, expert_files in SPECS:
    baseline = json.loads((ROOT / "results" / f"{name}.json").read_text(encoding="utf-8"))
    assert {x["case_id"] for x in baseline["submissions"]} == FOUNDATION_IDS
    expert_runs = [json.loads((HERE / filename).read_text(encoding="utf-8")) for filename in expert_files]
    expert_submissions = [s for run in expert_runs for s in run["submissions"]]
    assert {x["case_id"] for x in expert_submissions} == EXPERT_IDS, f"Missing expert cases for {name}"
    all_submissions = baseline["submissions"] + expert_submissions
    report = benchmark.grade(CASES, all_submissions, KEY)
    reports[name] = report
    expert_results = [result for run in expert_runs for result in run["results"]]
    assert len(expert_results) == len(EXPERT_IDS)
    entry = {
        "agent": name, "model": model, "cases": len(all_submissions), "score": report["earned"],
        "total": report["total"], "percent": report["percent"], "by_track": report["by_track"],
        "foundation_seconds": round(sum(r["seconds"] for r in baseline["results"]), 2),
        "expert_seconds": round(sum(r["seconds"] for r in expert_results), 2),
        "expert_parse_errors": [r["case_id"] for r in expert_results if "parse_error" in r],
        "misses": [{"case_id": r["case_id"], "question_id": r["question_id"],
                    "submitted": r["submitted"], "expected": r["expected"], "lost": r["points"]}
                   for r in report["rows"] if r["earned"] == 0],
    }
    summary.append(entry)
    benchmark.write_json(HERE / f"{name}_combined.json", {
        "benchmark_version": "2.0-guided", "profile": name, "model": model,
        "submissions": all_submissions, "results": baseline["results"] + expert_results,
    })
    benchmark.write_json(HERE / f"{name}_score.json", report)

summary.sort(key=lambda x: (-x["score"], x["expert_seconds"]))
benchmark.write_json(HERE / "summary.json", {"benchmark_version": "2.0-guided", "ranking": summary})

lines = [
    "# REBench-Windows v2 — resultados comparativos",
    "",
    "18 casos, 59 preguntas, 184 puntos. Los 3 casos expertos aportan 112 puntos.",
    "",
    "| Agente | Modelo | Fundamentos | Expertos | Total | Tiempo experto (suma por caso) |",
    "|---|---|---:|---:|---:|---:|",
]
for entry in summary:
    f = entry["by_track"]["foundations"]
    e = entry["by_track"]["expert"]
    lines.append(f"| {entry['agent'].capitalize()} | `{entry['model']}` | {f['earned']}/{f['total']} | "
                 f"{e['earned']}/{e['total']} | **{entry['score']}/{entry['total']}** ({entry['percent']}%) | {entry['expert_seconds']:.1f} |")

lines += ["", "## Casos expertos", "", "| Caso | Codex | Claude | OpenCode |", "|---|---:|---:|---:|"]
for case in CASES:
    if case["id"] not in EXPERT_IDS:
        continue
    cells = []
    for name, _, _ in SPECS:
        rows = [r for r in reports[name]["rows"] if r["case_id"] == case["id"]]
        cells.append(f"{sum(r['earned'] for r in rows)}/{sum(r['points'] for r in rows)}")
    lines.append(f"| {case['id']} | " + " | ".join(cells) + " |")

lines += ["", "## Errores", ""]
for entry in summary:
    if not entry["misses"]:
        lines.append(f"- **{entry['agent'].capitalize()}**: ningún punto perdido.")
    else:
        for miss in entry["misses"]:
            lines.append(f"- **{entry['agent'].capitalize()} {miss['case_id']}/{miss['question_id']}** "
                         f"(-{miss['lost']}): respondió `{miss['submitted']}`; esperado `{miss['expected']}`.")

lines += [
    "",
    "## Método y límites",
    "",
    "- Se reutilizaron las 15 respuestas de fundamentos de la primera tanda. "
    "[La comprobación](baseline_reuse_evidence.json) confirma que sus artefactos y el contenido de los prompts siguen iguales.",
    "- Los tres agentes recibieron el mismo prompt experto, con aviso de que Python, pefile, capstone y la ejecución local estaban disponibles. "
    "Codex tuvo escritura en el directorio temporal; Claude recibió permisos de Bash/Read/Write/Edit/Glob/Grep; OpenCode usó su agente predeterminado.",
    "- OpenCode ejecutó hasta dos casos simultáneos. Los segundos de la tabla son suma por caso, "
    "no tiempo de reloj comparable. El gateway GLM tuvo saturación temporal en las pruebas previas.",
    "- La puntuación de esta versión es automática y exacta. No asigna puntos a la explicación libre ni implica superioridad general fuera de este banco.",
    "",
    "## Evidencia",
    "",
    "- [Resumen JSON](summary.json), [configuración de modelos](models.json) y [banco público](../../public/cases.json).",
    "- Salidas completas: [Codex](codex_guided.json), [Claude licencia](claude_license_guided.json), "
    "[Claude VM y AOB](claude_guided_rest.json), [OpenCode](opencode_guided.json).",
    "- Puntuaciones por pregunta: [Codex](codex_score.json), [Claude](claude_score.json), [OpenCode](opencode_score.json).",
    "",
]
(HERE / "RESULTADOS.md").write_text("\n".join(lines), encoding="utf-8")
print(HERE / "RESULTADOS.md")
