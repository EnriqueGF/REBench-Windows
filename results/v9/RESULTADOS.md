# REBench-Windows v9 — resultados

26 casos, 111 preguntas y 1258 puntos. «Respondidos» excluye casos sin JSON final; el banco completo mantiene el denominador 1258.

| Agente | Modelo | Puntos respondidos | Cobertura | Banco completo |
|---|---|---:|---:|---:|
| Codex | `gpt-6-sol` | **1258/1258** | 26/26 | 1258/1258 |
| Claude | `claude-opus-4-7` | **1246/1258** | 26/26 | 1246/1258 |
| Opencode | `explabs/glm-5.3-flash-abliterated` | **572/572** | 23/26 | 572/1258 |

| Agente | Fundamentos | Expertos | Investigación |
|---|---:|---:|---:|
| Codex | 72/72 | 112/112 | 1074/1074 |
| Claude | 70/72 | 112/112 | 1064/1074 |
| Opencode | 72/72 | 112/112 | 388/388 |

## Caso nuevo: TLS, recurso y dos recorridos

| Agente | Puntuación | Tiempo | Estado |
|---|---:|---:|---|
| Codex | 350/350 | 306.0 s | respondido |
| Claude | 350/350 | 784.8 s | respondido |
| Opencode | 0/350 | 3600.0 s | timeout; runner cleanup failed |

## Incidencias

- Claude: `pe_reloc/q1` (0/2), `hard_delay_import/q6` (0/10).
- Opencode tiene pendientes: `hard_resource_stream`, `hard_tls_state`, `hard_tls_stream2`.
- Opencode, intentos sin respuesta válida: `hard_tls_stream2` (3600.0 s; timeout; runner cleanup failed).

Los 25 casos anteriores se reutilizaron tras verificar SHA-256 de prompts y artefactos con [el manifiesto v8](../v8/v8_evidence_manifest.json). [El manifiesto v9](v9_evidence_manifest.json) congela los 26 casos. La prueba nueva exige recuperar claves cifradas en RCDATA durante un callback TLS y reconstruir dos recorridos con estados compartidos, uno en sentido inverso. El corrector compara el programa DSL con 384 mensajes ocultos de 0 a 96 bytes. Una ejecución sin JSON final queda pendiente. El intérprete acepta `b` como alias de `bits` en rotaciones y desplazamientos; se aplicó la misma regla a todos los agentes al recalcular las puntuaciones, sin modificar sus respuestas. En el timeout de OpenCode, Windows impidió limpiar un archivo temporal llamado `nul`; se recuperó el estado de timeout, pero se perdió la salida parcial.

Los tiempos mezclan análisis, herramientas y latencia del proveedor. Las CLI comparten máquina con el repositorio privado; el directorio temporal por caso no constituye aislamiento de seguridad.

[Resumen JSON](summary.json) · [codex](./codex_score.json) · [claude](./claude_score.json) · [opencode](./opencode_score.json)