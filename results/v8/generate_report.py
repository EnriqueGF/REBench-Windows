"""Combine the frozen v7 campaign with the v8 repair challenge."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import benchmark
from verify_reuse import digest, snapshot as old_snapshot


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


old_manifest = read(ROOT / "results/v7/v7_evidence_manifest.json")
new_manifest = read(HERE / "v8_evidence_manifest.json")
cases = read(HERE / "cases.json")["cases"]
actual = {
    case["id"]: {
        "prompt_sha256": digest(benchmark.prompt_for(case).encode("utf-8")),
        "artifacts": {rel: digest((benchmark.PUBLIC / rel).read_bytes())
                      for rel in case["artifacts"]},
    }
    for case in cases
}
if old_snapshot() != old_manifest or actual != new_manifest:
    raise SystemExit("Evidence changed; historical answers cannot be reused")

key = read(benchmark.KEY)
models = {"codex": "gpt-6-sol", "claude": "claude-opus-4-7",
          "opencode": "explabs/glm-5.3-flash-abliterated"}
summaries = {}
for agent, model in models.items():
    paths = [ROOT / f"results/v7/{agent}_combined.json", HERE / f"{agent}_repair.json"]
    submissions, attempts, files = {}, [], []
    for path in paths:
        if not path.is_file():
            continue
        payload = read(path)
        files.append(str(path.relative_to(ROOT)))
        for submission in payload.get("submissions", []):
            case_id = submission["case_id"]
            if case_id in submissions:
                raise SystemExit(f"Duplicate answer: {agent}/{case_id}")
            submissions[case_id] = submission
        for item in payload.get("results", []):
            attempts.append({"case_id": item["case_id"], "seconds": item.get("seconds"),
                             "exit_code": item.get("exit_code"),
                             "parse_error": item.get("parse_error"),
                             "file": str(path.relative_to(ROOT))})
    report = benchmark.grade(cases, list(submissions.values()), key)
    evaluated = sum(q["points"] for case in cases if case["id"] in submissions
                    for q in case["questions"])
    evaluated_by_track = {track: sum(q["points"] for case in cases
                          if case["id"] in submissions and case["track"] == track
                          for q in case["questions"])
                          for track in ("foundations", "expert", "research")}
    lost = [{"case_id": row["case_id"], "question_id": row["question_id"],
             "earned": row["earned"], "points": row["points"]}
            for row in report["rows"] if row["case_id"] in submissions
            and row["earned"] < row["points"]]
    summaries[agent] = {"model": model, "earned": report["earned"],
                        "evaluated_points": evaluated, "total_points": report["total"],
                        "completed_cases": len(submissions), "total_cases": len(cases),
                        "missing_cases": report["missing_cases"],
                        "by_track": report["by_track"],
                        "evaluated_by_track": evaluated_by_track,
                        "lost_points": lost, "attempts": attempts, "source_files": files}
    benchmark.write_json(HERE / f"{agent}_combined.json", {
        "benchmark_version": "8.0", "profile": agent, "model": model,
        "submissions": list(submissions.values()), "source_files": files})
    benchmark.write_json(HERE / f"{agent}_score.json", report)

benchmark.write_json(HERE / "summary.json", {"benchmark_version": "8.0", "models": summaries})
lines = ["# REBench-Windows v8 — resultados", "",
         "25 casos, 103 preguntas y 908 puntos. «Respondidos» excluye casos sin JSON final; "
         "el banco completo mantiene el denominador 908.", "",
         "| Agente | Modelo | Puntos respondidos | Cobertura | Banco completo |",
         "|---|---|---:|---:|---:|"]
for agent, row in summaries.items():
    lines.append(f"| {agent.capitalize()} | `{row['model']}` | "
                 f"**{row['earned']}/{row['evaluated_points']}** | "
                 f"{row['completed_cases']}/{row['total_cases']} | {row['earned']}/{row['total_points']} |")
lines += ["", "| Agente | Fundamentos | Expertos | Investigación |",
          "|---|---:|---:|---:|"]
for agent, row in summaries.items():
    cells = [f"{row['by_track'][track]['earned']}/{row['evaluated_by_track'][track]}"
             for track in ("foundations", "expert", "research")]
    lines.append(f"| {agent.capitalize()} | " + " | ".join(cells) + " |")

lines += ["", "## Caso nuevo: reparar dos saltos en cuatro PE64", "",
          "| Agente | Puntuación | Tiempo | Estado |", "|---|---:|---:|---|"]
for agent, row in summaries.items():
    score = read(HERE / f"{agent}_score.json")
    earned = sum(item["earned"] for item in score["rows"]
                 if item["case_id"] == "hard_repair_aob")
    attempts = [a for a in row["attempts"] if a["case_id"] == "hard_repair_aob"]
    status = "respondido" if "hard_repair_aob" not in row["missing_cases"] else \
             (attempts[-1]["parse_error"] or "sin respuesta") if attempts else "pendiente"
    seconds = f"{attempts[-1]['seconds']:.1f} s" if attempts and attempts[-1]["seconds"] is not None else "pendiente"
    lines.append(f"| {agent.capitalize()} | {earned}/160 | {seconds} | {status} |")

lines += ["", "## Incidencias", ""]
for agent, row in summaries.items():
    if row["lost_points"]:
        lines.append(f"- {agent.capitalize()}: " + ", ".join(
            f"`{item['case_id']}/{item['question_id']}` "
            f"({item['earned']}/{item['points']})" for item in row["lost_points"]) + ".")
    if row["missing_cases"]:
        lines.append(f"- {agent.capitalize()} tiene pendientes: " +
                     ", ".join(f"`{cid}`" for cid in row["missing_cases"]) + ".")
    errors = [a for a in row["attempts"] if a["parse_error"] or a["exit_code"] not in (None, 0)]
    if errors:
        lines.append(f"- {agent.capitalize()}, intentos sin respuesta válida: " + ", ".join(
            f"`{a['case_id']}` ({a['seconds']} s; {a['parse_error'] or 'exit '+str(a['exit_code'])})"
            for a in errors) + ".")

lines += ["", "Los 24 casos anteriores se reutilizaron tras verificar SHA-256 de "
          "prompts y artefactos con [el manifiesto v7](../v7/v7_evidence_manifest.json). "
          "[El manifiesto v8](v8_evidence_manifest.json) congela los 25 casos. "
          "La prueba nueva exige dos patrones AOB únicos en `.text` para cuatro builds, "
          "incluida una oculta. El corrector parchea copias temporales y prueba entradas "
          "funcionales ocultas. Una ejecución sin JSON final queda pendiente.", "",
          "Los tiempos mezclan análisis, herramientas y latencia del proveedor. "
          "Las CLI comparten máquina con el repositorio privado; el directorio temporal "
          "por caso no constituye aislamiento de seguridad.", "",
          "[Resumen JSON](summary.json) · " + " · ".join(
              f"[{agent}](./{agent}_score.json)" for agent in models) + ""]
(HERE / "RESULTADOS.md").write_text("\n".join(lines), encoding="utf-8")
print(HERE / "RESULTADOS.md")
