# REBench-Windows v6 — resultados

23 casos, 89 preguntas y 542 puntos. La puntuación usa solo casos respondidos; la cobertura muestra cuánto del banco se completó.

| Agente | Modelo | Puntos respondidos | Cobertura | Puntos del banco |
|---|---|---:|---:|---:|
| Codex | `gpt-6-sol` | **542/542** | 23/23 | 542/542 |
| Claude | `claude-opus-4-7` | **530/542** | 23/23 | 530/542 |
| Opencode | `explabs/glm-5.3-flash-abliterated` | **412/412** | 22/23 | 412/542 |

| Agente | Fundamentos | Expertos | Investigación |
|---|---:|---:|---:|
| Codex | 72/72 | 112/112 | 358/358 |
| Claude | 70/72 | 112/112 | 348/358 |
| Opencode | 72/72 | 112/112 | 228/228 |

## Casos de investigación

| Caso | Puntos | Codex | Claude | OpenCode |
|---|---:|---:|---:|---:|
| `hard_tls_state` | 130 | 130/130 | 130/130 | pendiente |
| `hard_delay_import` | 48 | 48/48 | 38/48 | 48/48 |
| `hard_unwind_frame` | 55 | 55/55 | 55/55 | 55/55 |
| `hard_pipeline` | 69 | 69/69 | 69/69 | 69/69 |
| `hard_pattern_open` | 56 | 56/56 | 56/56 | 56/56 |

## Tiempo de los tres casos nuevos

Límite de 3.600 segundos por caso. Segundos de cada intento registrado; incluyen espera de proveedor y trabajo con herramientas. Las ejecuciones simultáneas no son tiempo total de campaña.

| Caso | Codex | Claude | OpenCode |
|---|---:|---:|---:|
| `hard_tls_state` | 140.6 | 151.8 | 3600.1 |
| `hard_delay_import` | 43.0 | 28.9 | 734.9 |
| `hard_unwind_frame` | 36.3 | 40.4 | 2631.5 |

## Errores y límites de la comparación

- Claude: `pe_reloc/q1` (0/2), `hard_delay_import/q6` (0/10).
- Opencode tiene pendientes: `hard_tls_state`.
- Opencode tuvo intentos sin respuesta válida: `hard_tls_state` (3600.05 s; timeout).
- En `hard_delay_import/q6`, Claude seleccionó A y C; faltó E: sumar ImageBase al RVA de pUnloadIAT produce su VA preferida. [Formato PE de Microsoft](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#delay-load-import-tables-image-only).

Los 21 casos v5 se reutilizaron solo después de comprobar SHA-256 de todos sus prompts y artefactos contra [el manifiesto v5](v5_reuse_manifest.json). [El manifiesto v6](v6_evidence_manifest.json) congela los 23 casos de esta campaña. Cada caso nuevo se ejecutó en un directorio temporal al que solo se copiaron los artefactos públicos; este entorno local no impide por sí mismo que una CLI con acceso amplio al disco busque el repositorio. La respuesta de selección múltiple se puntúa de forma exacta.

Los resultados describen esta campaña local. Una puntuación perfecta aún indica techo para ese modelo; el tiempo mezcla razonamiento, herramientas y latencia del proveedor. Los dos casos nuevos se ejecutaron en paralelo por perfil y coincidieron con la ejecución TLS de OpenCode; sus tiempos no son una comparación controlada de velocidad. El perfil OpenCode usa el modelo configurado por defecto, sin override en la CLI; [el entorno registrado](environment.json) indica cuál estaba configurado.

[Resumen JSON](summary.json) · [codex](./codex_score.json) · [claude](./claude_score.json) · [opencode](./opencode_score.json)