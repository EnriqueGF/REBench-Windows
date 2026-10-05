# REBench-Windows v10 — resultados

27 casos, 123 preguntas y 1380 puntos. «Respondidos» excluye casos sin JSON final; el banco completo mantiene el denominador 1380.

| Agente | Modelo | Puntos respondidos | Cobertura | Banco completo |
|---|---|---:|---:|---:|
| Codex | `gpt-6-sol` | **1380/1380** | 27/27 | 1380/1380 |
| Claude | `claude-opus-4-7` | **1354/1380** | 27/27 | 1354/1380 |
| Opencode | `explabs/glm-5.3-flash-abliterated` | **572/572** | 23/27 | 572/1380 |

| Agente | Fundamentos | Expertos | Investigación |
|---|---:|---:|---:|
| Codex | 72/72 | 112/112 | 1196/1196 |
| Claude | 70/72 | 112/112 | 1172/1196 |
| Opencode | 72/72 | 112/112 | 388/388 |

## Caso nuevo: minidump x64 real

| Agente | Puntuación | Tiempo | Estado |
|---|---:|---:|---|
| Codex | 122/122 | 151.3 s | respondido |
| Claude | 108/122 | 142.4 s | respondido |
| Opencode | 0/122 | 3600.1 s | timeout |

## Calibración de los cuatro casos nuevos

| Caso | Codex | Claude | OpenCode |
|---|---:|---:|---:|
| Recurso y mensaje variable (v7) | 206/206 (137 s) | 206/206 (230 s) | sin respuesta (3600 s) |
| Reparación AOB (v8) | 160/160 (175 s) | 160/160 (135 s) | 160/160 (1536 s) |
| TLS y dos recorridos (v9) | 350/350 (306 s) | 350/350 (785 s) | sin respuesta (3600 s) |
| Minidump x64 (v10) | 122/122 (151 s) | 108/122 (142 s) | sin respuesta (3600 s) |

## Incidencias

- Claude: `pe_reloc/q1` (0/2), `hard_delay_import/q6` (0/10), `hard_crash_dump/q10` (0/14).
- Opencode tiene pendientes: `hard_crash_dump`, `hard_resource_stream`, `hard_tls_state`, `hard_tls_stream2`.
- Opencode, intentos sin respuesta válida: `hard_crash_dump` (3600.05 s; timeout).

Los 26 casos anteriores se reutilizaron tras verificar SHA-256 de prompts y artefactos con [el manifiesto v9](../v9/v9_evidence_manifest.json). [El manifiesto v10](v10_evidence_manifest.json) congela los 27 casos. La prueba nueva utiliza un minidump real de Windows con contexto de excepción, módulos y memoria privada para reconstruir una dirección truncada a 32 bits. Una ejecución sin JSON final queda pendiente. Se recalculó la v9 aceptando `b` como alias de `bits` en el DSL; las respuestas originales no se modificaron. El timeout v9 de OpenCode se recuperó sin salida parcial tras un fallo de limpieza de un nombre reservado de Windows; el ejecutor ya tolera ese fallo.

Los tiempos mezclan análisis, herramientas y latencia del proveedor. Las CLI comparten máquina con el repositorio privado; el directorio temporal por caso no constituye aislamiento de seguridad.

[Resumen JSON](summary.json) · [codex](./codex_score.json) · [claude](./claude_score.json) · [opencode](./opencode_score.json)