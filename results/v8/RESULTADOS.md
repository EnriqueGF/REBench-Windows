# REBench-Windows v8 — resultados

25 casos, 103 preguntas y 908 puntos. «Respondidos» excluye casos sin JSON final; el banco completo mantiene el denominador 908.

| Agente | Modelo | Puntos respondidos | Cobertura | Banco completo |
|---|---|---:|---:|---:|
| Codex | `gpt-6-sol` | **908/908** | 25/25 | 908/908 |
| Claude | `claude-opus-4-7` | **896/908** | 25/25 | 896/908 |
| Opencode | `explabs/glm-5.3-flash-abliterated` | **572/572** | 23/25 | 572/908 |

| Agente | Fundamentos | Expertos | Investigación |
|---|---:|---:|---:|
| Codex | 72/72 | 112/112 | 724/724 |
| Claude | 70/72 | 112/112 | 714/724 |
| Opencode | 72/72 | 112/112 | 388/388 |

## Caso nuevo: reparar dos saltos en cuatro PE64

| Agente | Puntuación | Tiempo | Estado |
|---|---:|---:|---|
| Codex | 160/160 | 175.1 s | respondido |
| Claude | 160/160 | 135.3 s | respondido |
| Opencode | 160/160 | 1535.6 s | respondido |

## Incidencias

- Claude: `pe_reloc/q1` (0/2), `hard_delay_import/q6` (0/10).
- Opencode tiene pendientes: `hard_resource_stream`, `hard_tls_state`.

Los 24 casos anteriores se reutilizaron tras verificar SHA-256 de prompts y artefactos con [el manifiesto v7](../v7/v7_evidence_manifest.json). [El manifiesto v8](v8_evidence_manifest.json) congela los 25 casos. La prueba nueva exige dos patrones AOB únicos en `.text` para cuatro builds, incluida una oculta. El corrector parchea copias temporales y prueba entradas funcionales ocultas. Una ejecución sin JSON final queda pendiente.

Los tiempos mezclan análisis, herramientas y latencia del proveedor. Las CLI comparten máquina con el repositorio privado; el directorio temporal por caso no constituye aislamiento de seguridad.

[Resumen JSON](summary.json) · [codex](./codex_score.json) · [claude](./claude_score.json) · [opencode](./opencode_score.json)