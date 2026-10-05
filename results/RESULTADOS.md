# Resultados de REBench-Windows — 4 de octubre de 2026

15 casos, 45 preguntas, 72 puntos. Cada caso se ejecutó en una sesión independiente.

| Agente | Modelo fijado | CLI | Casos puntuables | Puntos | Tiempo de reloj | Suma de tiempos por caso |
|---|---|---:|---:|---:|---:|---:|
| Codex | `gpt-6-sol` | 0.160.0 | 15/15 | 72/72 (100.0%) | 171.1 s | 170.9 s |
| Claude | `claude-opus-4-7` | 2.1.289 | 15/15 | 70/72 (97.22%) | 188.1 s | 187.9 s |
| Opencode | `explabs/glm-5.3-flash-abliterated` | 1.2.26 | 15/15 | 72/72 (100.0%) | 1571.7 s | 3065.1 s |

## Puntuación por caso

| Caso | Codex | Claude | OpenCode |
|---|---:|---:|---:|
| pe_rva | 3/3 | 3/3 | 3/3 |
| pe_reloc | 6/6 | 4/6 | 6/6 |
| abi_x64 | 6/6 | 6/6 | 6/6 |
| crash_av | 3/3 | 3/3 | 3/3 |
| wow64_view | 3/3 | 3/3 | 3/3 |
| unwind_x64 | 6/6 | 6/6 | 6/6 |
| symbols_pdb | 3/3 | 3/3 | 3/3 |
| loader_lock | 6/6 | 6/6 | 6/6 |
| etw_pid | 6/6 | 6/6 | 6/6 |
| plugin_lifetime | 3/3 | 3/3 | 3/3 |
| x86_stack | 6/6 | 6/6 | 6/6 |
| rip_relative | 3/3 | 3/3 | 3/3 |
| xor_config | 6/6 | 6/6 | 6/6 |
| com_activation | 6/6 | 6/6 | 6/6 |
| aob_versions | 6/6 | 6/6 | 6/6 |

## Errores observados

- **Claude — pe_reloc/q1**: respondió `0x0000000040000000`; esperado `0x180001234`.

Claude interpretó el QWORD de RVA `0x2028` como si estuviera en offset de archivo `0x228`; en la sección `.rdata` está en `0x628`. Por eso obtuvo el delta `0x40000000` como valor final en vez de `0x180001234`.

## Condiciones de ejecución

- Codex y Claude procesaron sus casos de uno en uno (ambos perfiles se lanzaron en paralelo). OpenCode procesó dos casos a la vez; la suma de tiempos por caso no es su duración total de reloj.
- OpenCode usó el modelo predeterminado configurado en este equipo. Su gateway presentó saturación temporal (`HTTP 429`, plazas ocupadas). La tanda final terminó los 15 casos y no tuvo errores de parseo ni casos agotados por tiempo.
- La puntuación automática exige coincidencia exacta en las opciones y en los valores. Las explicaciones libres se guardaron, pero no suman puntos; esta tabla no equivale a una auditoría manual de todos los razonamientos.
- Se hizo una pasada por agente. Cada CLI conservó sus ajustes locales de esfuerzo y herramientas; no se igualó un presupuesto de tokens entre proveedores.
- El banco usa escenarios sintéticos basados en problemas prácticos. Con 72/72 en dos agentes, esta versión ya tiene poco poder para separarlos por precisión; conviene añadir casos ciegos de varias etapas y validación manual antes de usarla para afirmar superioridad general.

## Archivos

- [Codex: salida y respuestas](codex.json), [puntuación](codex_score.json)
- [Claude: salida y respuestas](claude.json), [puntuación](claude_score.json)
- [OpenCode: salida y respuestas](opencode.json), [puntuación](opencode_score.json)
- [Clasificación en JSON](ranking.json) y [configuración de modelos](models.json)
