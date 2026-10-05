"""Produce a human-readable report from the three saved benchmark runs."""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import benchmark

DATA = benchmark.cases()
CASES = [case for case in DATA["cases"] if case.get("track") == "foundations"]
KEY = benchmark.read_json(benchmark.KEY)
SPECS = [
    ("codex", "gpt-6-sol", "0.160.0", 1),
    ("claude", "claude-opus-4-7", "2.1.289", 1),
    ("opencode", "explabs/glm-5.3-flash-abliterated", "1.2.26", 2),
]
RUNS = {}
REPORTS = {}
for name, model, version, jobs in SPECS:
    path = ROOT / "results" / f"{name}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    RUNS[name] = payload
    REPORTS[name] = benchmark.grade(CASES, payload["submissions"], KEY)

lines = [
    "# Resultados de REBench-Windows — 4 de octubre de 2026",
    "",
    "15 casos, 45 preguntas, 72 puntos. Cada caso se ejecutó en una sesión independiente.",
    "",
    "| Agente | Modelo fijado | CLI | Casos puntuables | Puntos | Tiempo de reloj | Suma de tiempos por caso |",
    "|---|---|---:|---:|---:|---:|---:|",
]
for name, model, version, jobs in SPECS:
    payload = RUNS[name]
    path = ROOT / "results" / f"{name}.json"
    started = datetime.fromisoformat(payload["started_at"])
    ended = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
    wall = round((ended - started).total_seconds(), 1)
    case_seconds = round(sum(result["seconds"] for result in payload["results"]), 1)
    score = REPORTS[name]
    lines.append(f"| {name.capitalize()} | `{model}` | {version} | {len(payload['submissions'])}/15 | "
                 f"{score['earned']}/{score['total']} ({score['percent']}%) | {wall} s | {case_seconds} s |")

lines += [
    "",
    "## Puntuación por caso",
    "",
    "| Caso | Codex | Claude | OpenCode |",
    "|---|---:|---:|---:|",
]
for case in CASES:
    row = [case["id"]]
    for name, _, _, _ in SPECS:
        entries = [x for x in REPORTS[name]["rows"] if x["case_id"] == case["id"]]
        row.append(f"{sum(x['earned'] for x in entries)}/{sum(x['points'] for x in entries)}")
    lines.append("| " + " | ".join(row) + " |")

lines += ["", "## Errores observados", ""]
misses = []
for name, _, _, _ in SPECS:
    for row in REPORTS[name]["rows"]:
        if row["earned"] < row["points"]:
            misses.append((name, row))
if misses:
    for name, row in misses:
        lines.append(f"- **{name.capitalize()} — {row['case_id']}/{row['question_id']}**: "
                     f"respondió `{row['submitted']}`; esperado `{row['expected']}`.")
else:
    lines.append("No hubo respuestas incorrectas.")
lines += [
    "",
    "Claude interpretó el QWORD de RVA `0x2028` como si estuviera en offset de archivo `0x228`; "
    "en la sección `.rdata` está en `0x628`. Por eso obtuvo el delta `0x40000000` "
    "como valor final en vez de `0x180001234`.",
    "",
    "## Condiciones de ejecución",
    "",
    "- Codex y Claude procesaron sus casos de uno en uno (ambos perfiles se lanzaron en paralelo). "
    "OpenCode procesó dos casos a la vez; "
    "la suma de tiempos por caso no es su duración total de reloj.",
    "- OpenCode usó el modelo predeterminado configurado en este equipo. Su gateway presentó "
    "saturación temporal (`HTTP 429`, plazas ocupadas). La tanda final terminó los 15 casos y "
    "no tuvo errores de parseo ni casos agotados por tiempo.",
    "- La puntuación automática exige coincidencia exacta en las opciones y en los valores. "
    "Las explicaciones libres se guardaron, pero no suman puntos; esta tabla no equivale "
    "a una auditoría manual de todos los razonamientos.",
    "- Se hizo una pasada por agente. Cada CLI conservó sus ajustes locales de esfuerzo y herramientas; "
    "no se igualó un presupuesto de tokens entre proveedores.",
    "- El banco usa escenarios sintéticos basados en problemas prácticos. Con 72/72 en dos "
    "agentes, esta versión ya tiene poco poder para separarlos por precisión; conviene añadir "
    "casos ciegos de varias etapas y validación manual antes de usarla para afirmar superioridad general.",
    "",
    "## Archivos",
    "",
    "- [Codex: salida y respuestas](codex.json), [puntuación](codex_score.json)",
    "- [Claude: salida y respuestas](claude.json), [puntuación](claude_score.json)",
    "- [OpenCode: salida y respuestas](opencode.json), [puntuación](opencode_score.json)",
    "- [Clasificación en JSON](ranking.json) y [configuración de modelos](models.json)",
    "",
]
out = ROOT / "results" / "RESULTADOS.md"
out.write_text("\n".join(lines), encoding="utf-8")
print(out)
