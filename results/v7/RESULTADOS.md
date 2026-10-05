# REBench-Windows v7 — resultados

24 casos, 96 preguntas y 748 puntos. La columna «respondidos» excluye casos sin JSON final; la puntuación sobre el banco completo mantiene el denominador 748.

| Agente | Modelo | Puntos respondidos | Cobertura | Banco completo |
|---|---|---:|---:|---:|
| Codex | `gpt-6-sol` | **748/748** | 24/24 | 748/748 |
| Claude | `claude-opus-4-7` | **736/748** | 24/24 | 736/748 |
| Opencode | `explabs/glm-5.3-flash-abliterated` | **412/412** | 22/24 | 412/748 |

| Agente | Fundamentos | Expertos | Investigación |
|---|---:|---:|---:|
| Codex | 72/72 | 112/112 | 564/564 |
| Claude | 70/72 | 112/112 | 554/564 |
| Opencode | 72/72 | 112/112 | 228/228 |

## Caso nuevo: recurso cifrado y mensajes variables

| Agente | Puntuación | Tiempo | Estado |
|---|---:|---:|---|
| Codex | 206/206 | 136.9 s | respondido |
| Claude | 206/206 | 230.0 s | respondido |
| Opencode | 0/206 | 3600.1 s | timeout |

## Incidencias

- Claude: `pe_reloc/q1` (0/2), `hard_delay_import/q6` (0/10).
- Opencode tiene pendientes: `hard_resource_stream`, `hard_tls_state`.
- Opencode, intentos sin respuesta válida: `hard_resource_stream` (3600.06 s; timeout).

Los 23 casos anteriores se reutilizaron después de comprobar SHA-256 de sus prompts y artefactos contra [el manifiesto v6](../v6/v6_evidence_manifest.json). [El manifiesto v7](v7_evidence_manifest.json) congela los 24 casos actuales. El nuevo caso se ejecutó con un límite de 3.600 segundos y se corrigió en 384 mensajes ocultos con el intérprete DSL. Un proceso sin respuesta final queda pendiente, no se considera una solución incorrecta.

Una puntuación perfecta sigue indicando techo para ese modelo en esta muestra. Los tiempos mezclan análisis, herramientas y latencia del proveedor; no son una medición controlada de velocidad. Las CLI comparten la máquina con el repositorio privado, así que el directorio temporal por caso no constituye aislamiento de seguridad.

[Resumen JSON](summary.json) · [codex](./codex_score.json) · [claude](./claude_score.json) · [opencode](./opencode_score.json)