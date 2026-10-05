"""Aggregate the v7 stream challenge with the verified v6 campaign."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import benchmark
from verify_reuse import snapshot as old_snapshot
from verify_reuse import digest

old_manifest = json.loads((ROOT / "results/v6/v6_evidence_manifest.json").read_text(encoding="utf-8"))
new_manifest = json.loads((HERE / "v7_evidence_manifest.json").read_text(encoding="utf-8"))
cases = json.loads((HERE / "cases.json").read_text(encoding="utf-8"))["cases"]
frozen_snapshot = {
    case["id"]: {
        "prompt_sha256": digest(benchmark.prompt_for(case).encode("utf-8")),
        "artifacts": {rel: digest((benchmark.PUBLIC / rel).read_bytes())
                      for rel in case["artifacts"]},
    }
    for case in cases
}
if old_snapshot() != old_manifest or frozen_snapshot != new_manifest:
    raise SystemExit("Evidence changed; historical answers cannot be reused")

key = benchmark.read_json(benchmark.KEY)
models = {"codex": "gpt-6-sol", "claude": "claude-opus-4-7",
          "opencode": "explabs/glm-5.3-flash-abliterated"}
summaries = {}
for agent, model in models.items():
    paths = [ROOT / f"results/v6/{agent}_combined.json", HERE / f"{agent}_stream.json"]
    submissions, attempts, files = {}, [], []
    for path in paths:
        if not path.is_file():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
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
             "earned": row["earned"], "points": row["points"],
             "submitted": row["submitted"], "expected": row["expected"]}
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
        "benchmark_version": "7.0", "profile": agent, "model": model,
        "submissions": list(submissions.values()), "source_files": files})
    benchmark.write_json(HERE / f"{agent}_score.json", report)

benchmark.write_json(HERE / "summary.json", {"benchmark_version": "7.0", "models": summaries})
lines = ["# REBench-Windows v7 — resultados", "",
         "24 casos, 96 preguntas y 748 puntos. La columna «respondidos» excluye casos sin JSON final; "
         "la puntuación sobre el banco completo mantiene el denominador 748.", "",
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

lines += ["", "## Caso nuevo: recurso cifrado y mensajes variables", "",
          "| Agente | Puntuación | Tiempo | Estado |", "|---|---:|---:|---|"]
for agent, row in summaries.items():
    score = benchmark.read_json(HERE / f"{agent}_score.json")
    earned = sum(item["earned"] for item in score["rows"]
                 if item["case_id"] == "hard_resource_stream")
    attempts = [a for a in row["attempts"] if a["case_id"] == "hard_resource_stream"]
    seconds = sum(a["seconds"] or 0 for a in attempts)
    status = "respondido" if "hard_resource_stream" not in row["missing_cases"] else \
             (attempts[-1]["parse_error"] or "sin respuesta") if attempts else "pendiente"
    lines.append(f"| {agent.capitalize()} | {earned}/206 | "
                 f"{seconds:.1f} s" if attempts else f"| {agent.capitalize()} | pendiente | pendiente | pendiente |")
    if attempts:
        lines[-1] += f" | {status} |"

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

lines += ["", "Los 23 casos anteriores se reutilizaron después de comprobar SHA-256 de "
          "sus prompts y artefactos contra [el manifiesto v6](../v6/v6_evidence_manifest.json). "
          "[El manifiesto v7](v7_evidence_manifest.json) congela los 24 casos actuales. "
          "El nuevo caso se ejecutó con un límite de 3.600 segundos y se corrigió en 384 mensajes "
          "ocultos con el intérprete DSL. Un proceso sin respuesta final queda pendiente, no se considera "
          "una solución incorrecta.", "",
          "Una puntuación perfecta sigue indicando techo para ese modelo en esta muestra. "
          "Los tiempos mezclan análisis, herramientas y latencia del proveedor; no son una medición "
          "controlada de velocidad. Las CLI comparten la máquina con el repositorio privado, así que "
          "el directorio temporal por caso no constituye aislamiento de seguridad.", "",
          "[Resumen JSON](summary.json) · " + " · ".join(
              f"[{agent}](./{agent}_score.json)" for agent in models) + ""]
(HERE / "RESULTADOS.md").write_text("\n".join(lines), encoding="utf-8")
print(HERE / "RESULTADOS.md")
