# REBench-Windows v4 — resultados

20 casos, 68 preguntas, 309 puntos. Los denominadores de la tabla incluyen solo casos respondidos; la cobertura indica cuántos se terminaron.

| Agente | Modelo | Fundamentos | Expertos | Investigación | Total | Casos respondidos |
|---|---|---:|---:|---:|---:|---:|
| Codex | `gpt-6-sol` | 72/72 | 112/112 | 125/125 | **309/309** | 20/20 |
| Opencode | `explabs/glm-5.3-flash-abliterated` | 72/72 | 112/112 | 125/125 | **309/309** | 20/20 |
| Claude | `claude-opus-4-7` | 70/72 | 112/112 | 125/125 | **307/309** | 20/20 |

## Casos avanzados

| Caso | Puntos | Codex | Claude | OpenCode |
|---|---:|---:|---:|---:|
| `hard_license` | 36 | 36/36 | 36/36 | 36/36 |
| `hard_vm` | 47 | 47/47 | 47/47 | 47/47 |
| `hard_pattern` | 29 | 29/29 | 29/29 | 29/29 |
| `hard_pipeline` | 69 | 69/69 | 69/69 | 69/69 |
| `hard_pattern_open` | 56 | 56/56 | 56/56 | 56/56 |

## Tiempo registrado por caso avanzado

Suma de los intentos en segundos; OpenCode puede incluir el primer intento agotado y su continuación. Los casos simultáneos hacen que estas cifras no sean tiempo de reloj de la campaña.

| Caso | Codex | Claude | OpenCode |
|---|---:|---:|---:|
| `hard_license` | 103.5 | 147.7 | 2001.1 |
| `hard_vm` | 119.4 | 323.2 | 2058.2 |
| `hard_pattern` | 66.7 | 44.8 | 1480.0 |
| `hard_pipeline` | 119.8 | 91.5 | 4004.8 |
| `hard_pattern_open` | 136.4 | 75.1 | 1085.5 |

## Incidencias y errores

- **Opencode**, intentos sin respuesta: `hard_license` (timeout, 1200.05 s), `hard_vm` (timeout, 1200.05 s), `hard_pattern` (timeout, 1200.05 s), `hard_pipeline` (timeout, 1800.05 s).
- **Claude**, respuestas incorrectas: `pe_reloc/q1` (-2).

## Interpretación

Codex y OpenCode empatan en precisión; Claude pierde dos puntos en `pe_reloc/q1`, donde respondió `0x40000000` (el delta de carga) en vez del QWORD ya relocacionado `0x180001234`. Los tres resolvieron los cinco casos avanzados.

Este resultado muestra un techo de puntuación para los casos avanzados de esta versión. Los tiempos de OpenCode incluyen saturación del proveedor, reintentos y sesiones continuadas, por lo que no miden aisladamente la velocidad del modelo. La pequeña diferencia de precisión tampoco permite inferir superioridad general entre modelos.

## Método

- Cada caso se ejecutó en una conversación y un directorio temporal nuevos. Los binarios y prompts públicos se copiaron allí; las claves privadas quedaron fuera.
- Se reutilizaron las 15 respuestas iniciales de fundamentos porque el contenido de los prompts y los artefactos no cambió. [Comprobación](../v2/baseline_reuse_evidence.json).
- Los perfiles de Codex y Claude fijaron sus modelos; OpenCode usó el modelo de su configuración predeterminada. [Configuración](../v2/models.json) y [versiones de CLI](environment.json).
- Las sesiones avanzadas de OpenCode que agotaron un límite se reanudaron con la misma conversación y los mismos artefactos, sin pistas sobre la solución. Se suman los tiempos de ambos intentos.
- Se descartó una continuación asociada por error a otra sesión AOB: devolvió de nuevo `hard_pattern_open` y no se incluyó en la puntuación de `hard_pattern`. [Salida descartada](../v2/opencode_wrong_session.json).
- El gateway de OpenCode devolvió HTTP 429 o agotó el tiempo incluso en una consulta mínima durante la campaña. [Sondeo](provider_probe.json).
- Las respuestas sin terminar por error del proveedor o por tiempo agotado figuran como pendientes; no se interpretan como respuestas incorrectas del modelo.
- El benchmark es sintético y estas puntuaciones solo describen esta campaña local.

## Datos

- [Resumen JSON](summary.json) y puntuación por pregunta: [codex](codex_score.json), [claude](claude_score.json), [opencode](opencode_score.json).
- Las salidas brutas y los tiempos están en los archivos `results/*.json`, `results/v2/*.json`, `results/v3/*.json` y `results/v4/*.json` indicados en el resumen JSON.
