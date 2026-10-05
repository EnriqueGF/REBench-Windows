"""Aggregate the v4 campaign without treating provider failures as model answers."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import benchmark

CASES = benchmark.cases()["cases"]
KEY = benchmark.read_json(benchmark.KEY)
CASE_IDS = {case["id"] for case in CASES}
BASELINE_IDS = {case["id"] for case in CASES if case.get("track") == "foundations"}
MODELS = {
    "codex": "gpt-6-sol",
    "claude": "claude-opus-4-7",
    "opencode": "explabs/glm-5.3-flash-abliterated",
}
FILES = {
    "codex": [ROOT / "results/codex.json", ROOT / "results/v2/codex_guided.json",
              ROOT / "results/v3/codex_pipeline.json", HERE / "codex_pattern_open.json"],
    "claude": [ROOT / "results/claude.json", ROOT / "results/v2/claude_license_guided.json",
               ROOT / "results/v2/claude_guided_rest.json", ROOT / "results/v3/claude_pipeline.json",
               HERE / "claude_pattern_open.json"],
    "opencode": [ROOT / "results/opencode.json", ROOT / "results/v2/opencode_guided.json",
                 ROOT / "results/v2/opencode_retry_license.json",
                 ROOT / "results/v2/opencode_retry_vm.json",
                 ROOT / "results/v2/opencode_retry_pattern.json",
                 ROOT / "results/v3/opencode_pipeline.json",
                 ROOT / "results/v3/opencode_pipeline_retry.json",
                 HERE / "opencode_pattern_open.json"],
}


def read_runs(paths):
    return [(path, json.loads(path.read_text(encoding="utf-8")))
            for path in paths if path.is_file()]


summary = []
reports = {}
for agent, paths in FILES.items():
    runs = read_runs(paths)
    submissions = {}
    attempts = []
    for path, run in runs:
        for item in run.get("results", []):
            if item["case_id"] in CASE_IDS:
                attempts.append({"case_id": item["case_id"], "file": str(path.relative_to(ROOT)),
                                 "seconds": item.get("seconds"), "exit_code": item.get("exit_code"),
                                 "parse_error": item.get("parse_error")})
        for submission in run.get("submissions", []):
            if submission["case_id"] in CASE_IDS:
                submissions[submission["case_id"]] = submission
    assert BASELINE_IDS.issubset(submissions), agent + ": missing baseline"
    report = benchmark.grade(CASES, list(submissions.values()), KEY)
    reports[agent] = report
    evaluated = {"foundations": 0, "expert": 0, "research": 0}
    for case in CASES:
        if case["id"] in submissions:
            evaluated[case["track"]] += sum(q["points"] for q in case["questions"])
    entry = {"agent": agent, "model": MODELS[agent], "score": report["earned"],
             "total": report["total"], "percent": report["percent"],
             "evaluated_points": sum(evaluated.values()), "evaluated_by_track": evaluated,
             "completed_cases": len(submissions), "total_cases": len(CASES),
             "by_track": report["by_track"], "missing_cases": report["missing_cases"],
             "attempts": attempts,
             "lost_points": [{"case_id": row["case_id"], "question_id": row["question_id"],
                              "points": row["points"], "submitted": row["submitted"],
                              "expected": row["expected"]}
                             for row in report["rows"] if row["earned"] < row["points"]
                             and row["case_id"] in submissions]}
    summary.append(entry)
    benchmark.write_json(HERE / f"{agent}_score.json", report)
    benchmark.write_json(HERE / f"{agent}_combined.json", {
        "benchmark_version": "4.0", "profile": agent, "model": MODELS[agent],
        "submissions": list(submissions.values()), "source_files": [str(p.relative_to(ROOT)) for p, _ in runs]})

summary.sort(key=lambda x: (-x["completed_cases"], -x["score"]))
benchmark.write_json(HERE / "summary.json", {"benchmark_version": "4.0", "ranking": summary})

lines = ["# REBench-Windows v4 — resultados", "",
         "20 casos, 68 preguntas, 309 puntos. Los denominadores de la tabla incluyen solo casos respondidos; la cobertura indica cuántos se terminaron.", "",
         "| Agente | Modelo | Fundamentos | Expertos | Investigación | Total | Casos respondidos |",
         "|---|---|---:|---:|---:|---:|---:|"]
for row in summary:
    tracks = ("foundations", "expert", "research")
    parts = [f"{row['by_track'][track]['earned']}/{row['evaluated_by_track'][track]}"
             if row["evaluated_by_track"][track] else "pendiente" for track in tracks]
    lines.append(f"| {row['agent'].capitalize()} | `{row['model']}` | " + " | ".join(parts) +
                 f" | **{row['score']}/{row['evaluated_points']}** | {row['completed_cases']}/{row['total_cases']} |")

lines += ["", "## Casos avanzados", "",
          "| Caso | Puntos | Codex | Claude | OpenCode |",
          "|---|---:|---:|---:|---:|"]
for case in CASES:
    if case.get("track") == "foundations":
        continue
    total = sum(q["points"] for q in case["questions"])
    cells = []
    for agent in MODELS:
        report = reports[agent]
        if case["id"] in report["missing_cases"]:
            cells.append("pendiente")
        else:
            earned = sum(r["earned"] for r in report["rows"] if r["case_id"] == case["id"])
            cells.append(f"{earned}/{total}")
    lines.append(f"| `{case['id']}` | {total} | " + " | ".join(cells) + " |")

lines += ["", "## Tiempo registrado por caso avanzado", "",
          "Suma de los intentos en segundos; OpenCode puede incluir el primer intento agotado y su continuación. Los casos simultáneos hacen que estas cifras no sean tiempo de reloj de la campaña.", "",
          "| Caso | Codex | Claude | OpenCode |", "|---|---:|---:|---:|"]
for case in CASES:
    if case.get("track") == "foundations":
        continue
    cells = []
    for agent in MODELS:
        entry = next(row for row in summary if row["agent"] == agent)
        seconds = sum(a["seconds"] or 0 for a in entry["attempts"] if a["case_id"] == case["id"])
        prefix = "≥" if case["id"] in entry["missing_cases"] and seconds else ""
        cells.append(f"{prefix}{seconds:.1f}" if seconds else "pendiente")
    lines.append(f"| `{case['id']}` | " + " | ".join(cells) + " |")

lines += ["", "## Incidencias y errores", ""]
for row in summary:
    errors = [a for a in row["attempts"] if a["parse_error"]]
    if errors:
        lines.append(f"- **{row['agent'].capitalize()}**, intentos sin respuesta: " +
                     ", ".join(f"`{a['case_id']}` ({a['parse_error']}, {a['seconds']} s)" for a in errors) + ".")
    if row["missing_cases"]:
        lines.append(f"- **{row['agent'].capitalize()}**, casos pendientes: " +
                     ", ".join(f"`{case_id}`" for case_id in row["missing_cases"]) + ".")
    if row["lost_points"]:
        lines.append(f"- **{row['agent'].capitalize()}**, respuestas incorrectas: " +
                     ", ".join(f"`{e['case_id']}/{e['question_id']}` (-{e['points']})" for e in row["lost_points"]) + ".")

lines += ["", "## Interpretación", "",
          "Codex y OpenCode empatan en precisión; Claude pierde dos puntos en `pe_reloc/q1`, donde respondió `0x40000000` (el delta de carga) en vez del QWORD ya relocacionado `0x180001234`. Los tres resolvieron los cinco casos avanzados.",
          "",
          "Este resultado muestra un techo de puntuación para los casos avanzados de esta versión. Los tiempos de OpenCode incluyen saturación del proveedor, reintentos y sesiones continuadas, por lo que no miden aisladamente la velocidad del modelo. La pequeña diferencia de precisión tampoco permite inferir superioridad general entre modelos."]

lines += ["", "## Método", "",
          "- Cada caso se ejecutó en una conversación y un directorio temporal nuevos. Los binarios y prompts públicos se copiaron allí; las claves privadas quedaron fuera.",
          "- Se reutilizaron las 15 respuestas iniciales de fundamentos porque el contenido de los prompts y los artefactos no cambió. [Comprobación](../v2/baseline_reuse_evidence.json).",
          "- Los perfiles de Codex y Claude fijaron sus modelos; OpenCode usó el modelo de su configuración predeterminada. [Configuración](../v2/models.json) y [versiones de CLI](environment.json).",
          "- Las sesiones avanzadas de OpenCode que agotaron un límite se reanudaron con la misma conversación y los mismos artefactos, sin pistas sobre la solución. Se suman los tiempos de ambos intentos.",
          "- Se descartó una continuación asociada por error a otra sesión AOB: devolvió de nuevo `hard_pattern_open` y no se incluyó en la puntuación de `hard_pattern`. [Salida descartada](../v2/opencode_wrong_session.json).",
          "- El gateway de OpenCode devolvió HTTP 429 o agotó el tiempo incluso en una consulta mínima durante la campaña. [Sondeo](provider_probe.json).",
          "- Las respuestas sin terminar por error del proveedor o por tiempo agotado figuran como pendientes; no se interpretan como respuestas incorrectas del modelo.",
          "- El benchmark es sintético y estas puntuaciones solo describen esta campaña local.",
          "", "## Datos", "",
          "- [Resumen JSON](summary.json) y puntuación por pregunta: " +
          ", ".join(f"[{agent}]({agent}_score.json)" for agent in MODELS) + ".",
          "- Las salidas brutas y los tiempos están en los archivos `results/*.json`, `results/v2/*.json`, `results/v3/*.json` y `results/v4/*.json` indicados en el resumen JSON.", ""]
(HERE / "RESULTADOS.md").write_text("\n".join(lines), encoding="utf-8")
print(HERE / "RESULTADOS.md")
