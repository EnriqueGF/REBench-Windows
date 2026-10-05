"""Merge the frozen v4 baseline with v5/v6 attempts and report coverage honestly."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import benchmark
from verify_reuse import snapshot
from freeze_evidence import snapshot as full_snapshot

expected = json.loads((HERE / "v5_reuse_manifest.json").read_text(encoding="utf-8"))
if snapshot() != expected:
    raise SystemExit("Frozen v5 evidence mismatch; historical answers cannot be reused")
full_expected = json.loads((HERE / "v6_evidence_manifest.json").read_text(encoding="utf-8"))
if full_snapshot() != full_expected:
    raise SystemExit("v6 public evidence changed since the campaign")

cases = benchmark.cases()["cases"]
key = benchmark.read_json(benchmark.KEY)
models = {"codex": "gpt-6-sol", "claude": "claude-opus-4-7",
          "opencode": "explabs/glm-5.3-flash-abliterated"}
new_ids = {"hard_tls_state", "hard_delay_import", "hard_unwind_frame"}
paths = {agent: [ROOT / f"results/v4/{agent}_combined.json",
                 ROOT / f"results/v5/{agent}_tls.json",
                 HERE / f"{agent}_new.json"] for agent in models}

summaries = {}
for agent, files in paths.items():
    submissions = {}
    attempts = []
    used_files = []
    for path in files:
        if not path.is_file():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        used_files.append(str(path.relative_to(ROOT)))
        for submission in payload.get("submissions", []):
            case_id = submission["case_id"]
            if case_id in submissions:
                raise SystemExit(f"Duplicate {agent}/{case_id}")
            submissions[case_id] = submission
        for result in payload.get("results", []):
            attempts.append({"case_id": result["case_id"], "seconds": result.get("seconds"),
                             "exit_code": result.get("exit_code"),
                             "parse_error": result.get("parse_error"),
                             "file": str(path.relative_to(ROOT))})
    if len(set(submissions) - {case["id"] for case in cases}):
        raise SystemExit("Unknown case in historical run")
    report = benchmark.grade(cases, list(submissions.values()), key)
    evaluated = sum(q["points"] for case in cases if case["id"] in submissions
                    for q in case["questions"])
    evaluated_by_track = {
        track: sum(q["points"] for case in cases
                   if case["id"] in submissions and case["track"] == track
                   for q in case["questions"])
        for track in ("foundations", "expert", "research")
    }
    lost = [{"case_id": row["case_id"], "question_id": row["question_id"],
             "earned": row["earned"], "points": row["points"],
             "submitted": row["submitted"], "expected": row["expected"]}
            for row in report["rows"] if row["case_id"] in submissions
            and row["earned"] < row["points"]]
    summaries[agent] = {"model": models[agent], "earned": report["earned"],
                        "evaluated_points": evaluated, "total_points": report["total"],
                        "completed_cases": len(submissions), "total_cases": len(cases),
                        "missing_cases": report["missing_cases"],
                        "by_track": report["by_track"],
                        "evaluated_by_track": evaluated_by_track, "lost_points": lost,
                        "attempts": attempts, "source_files": used_files}
    benchmark.write_json(HERE / f"{agent}_combined.json", {
        "benchmark_version": "6.0", "profile": agent, "model": models[agent],
        "submissions": list(submissions.values()), "source_files": used_files})
    benchmark.write_json(HERE / f"{agent}_score.json", report)

benchmark.write_json(HERE / "summary.json", {"benchmark_version": "6.0", "models": summaries})

lines = ["# REBench-Windows v6 — resultados", "",
         "23 casos, 89 preguntas y 542 puntos. La puntuación usa solo casos respondidos; "
         "la cobertura muestra cuánto del banco se completó.", "",
         "| Agente | Modelo | Puntos respondidos | Cobertura | Puntos del banco |",
         "|---|---|---:|---:|---:|"]
for agent, entry in summaries.items():
    lines.append(f"| {agent.capitalize()} | `{entry['model']}` | "
                 f"**{entry['earned']}/{entry['evaluated_points']}** | "
                 f"{entry['completed_cases']}/{entry['total_cases']} | "
                 f"{entry['earned']}/{entry['total_points']} |")

lines += ["", "| Agente | Fundamentos | Expertos | Investigación |",
          "|---|---:|---:|---:|"]
for agent, entry in summaries.items():
    cells = [f"{entry['by_track'][track]['earned']}/{entry['evaluated_by_track'][track]}"
             for track in ("foundations", "expert", "research")]
    lines.append(f"| {agent.capitalize()} | " + " | ".join(cells) + " |")

lines += ["", "## Casos de investigación", "",
          "| Caso | Puntos | Codex | Claude | OpenCode |",
          "|---|---:|---:|---:|---:|"]
for case in cases:
    if case.get("track") != "research":
        continue
    total = sum(q["points"] for q in case["questions"])
    cells = []
    for agent in models:
        entry = summaries[agent]
        if case["id"] in entry["missing_cases"]:
            cells.append("pendiente")
        else:
            score = benchmark.read_json(HERE / f"{agent}_score.json")
            earned = sum(row["earned"] for row in score["rows"] if row["case_id"] == case["id"])
            cells.append(f"{earned}/{total}")
    lines.append(f"| `{case['id']}` | {total} | " + " | ".join(cells) + " |")

lines += ["", "## Tiempo de los tres casos nuevos", "",
          "Límite de 3.600 segundos por caso. Segundos de cada intento registrado; "
          "incluyen espera de proveedor y trabajo con herramientas. "
          "Las ejecuciones simultáneas no son tiempo total de campaña.", "",
          "| Caso | Codex | Claude | OpenCode |", "|---|---:|---:|---:|"]
for case in cases:
    if case["id"] not in new_ids:
        continue
    cells = []
    for agent in models:
        attempts = [a for a in summaries[agent]["attempts"] if a["case_id"] == case["id"]]
        seconds = sum(a["seconds"] or 0 for a in attempts)
        cells.append(f"{seconds:.1f}" if attempts else "pendiente")
    lines.append(f"| `{case['id']}` | " + " | ".join(cells) + " |")

lines += ["", "## Errores y límites de la comparación", ""]
for agent, entry in summaries.items():
    if entry["lost_points"]:
        lines.append(f"- {agent.capitalize()}: " + ", ".join(
            f"`{item['case_id']}/{item['question_id']}` "
            f"({item['earned']}/{item['points']})" for item in entry["lost_points"]) + ".")
    if entry["missing_cases"]:
        lines.append(f"- {agent.capitalize()} tiene pendientes: " +
                     ", ".join(f"`{cid}`" for cid in entry["missing_cases"]) + ".")
    errors = [a for a in entry["attempts"] if a["parse_error"] or a["exit_code"] not in (None, 0)]
    if errors:
        lines.append(f"- {agent.capitalize()} tuvo intentos sin respuesta válida: " + ", ".join(
            f"`{a['case_id']}` ({a['seconds']} s; {a['parse_error'] or 'exit '+str(a['exit_code'])})"
            for a in errors) + ".")

if any(item["case_id"] == "hard_delay_import" and item["question_id"] == "q6"
       for item in summaries["claude"]["lost_points"]):
    lines.append("- En `hard_delay_import/q6`, Claude seleccionó A y C; faltó E: "
                 "sumar ImageBase al RVA de pUnloadIAT produce su VA preferida. "
                 "[Formato PE de Microsoft](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#delay-load-import-tables-image-only).")

lines += ["", "Los 21 casos v5 se reutilizaron solo después de comprobar SHA-256 de "
          "todos sus prompts y artefactos contra "
          "[el manifiesto v5](v5_reuse_manifest.json). "
          "[El manifiesto v6](v6_evidence_manifest.json) congela los 23 casos de esta campaña. "
          "Cada caso nuevo se ejecutó en un directorio temporal al que solo se copiaron los artefactos públicos; "
          "este entorno local no impide por sí mismo que una CLI con acceso amplio al disco busque el repositorio. "
          "La respuesta de selección múltiple se puntúa de forma exacta.", "",
          "Los resultados describen esta campaña local. Una puntuación perfecta aún indica "
          "techo para ese modelo; el tiempo mezcla razonamiento, herramientas y latencia del proveedor. "
          "Los dos casos nuevos se ejecutaron en paralelo por perfil y coincidieron con la ejecución TLS de OpenCode; "
          "sus tiempos no son una comparación controlada de velocidad. "
          "El perfil OpenCode usa el modelo configurado por defecto, sin override en la CLI; "
          "[el entorno registrado](environment.json) indica cuál estaba configurado.", "",
          "[Resumen JSON](summary.json) · " + " · ".join(
              f"[{agent}](./{agent}_score.json)" for agent in models) + ""]
(HERE / "RESULTADOS.md").write_text("\n".join(lines), encoding="utf-8")
print(HERE / "RESULTADOS.md")
