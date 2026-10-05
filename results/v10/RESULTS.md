# REBench-Windows v10 results

The frozen v10 bank has **27 cases, 123 questions, and 1,380 points**. The complete-bank denominator includes cases without a final JSON answer.

| Agent | Pinned or observed model | Cases answered | Points on answered cases | Complete-bank score |
|---|---|---:|---:|---:|
| Codex | `gpt-6-sol` | 27/27 | 1,380/1,380 | **1,380/1,380** |
| Claude | `claude-opus-4-7` | 27/27 | 1,354/1,380 | **1,354/1,380** |
| OpenCode | `explabs/glm-5.3-flash-abliterated` | 23/27 | 572/572 | **572/1,380** |

| Agent | Foundations | Expert | Research |
|---|---:|---:|---:|
| Codex | 72/72 | 112/112 | 1,196/1,196 |
| Claude | 70/72 | 112/112 | 1,172/1,196 |
| OpenCode | 72/72 | 112/112 | 388/388 answered |

The v10 addition was a real Windows x64 minidump recorded with `MiniDumpWriteDump`. It requires reconstructing a pointer truncated to 32 bits from the exception context, module information, and private memory, then explaining the effect of the fix. Codex scored 122/122 in 151.3 seconds; Claude scored 108/122 in 142.4 seconds; OpenCode reached the 3,600-second limit without a final answer.

Other difficult additions included a resource-backed variable-length message transform, an AOB repair across four PE builds, and a TLS callback that recovers encrypted keys and traverses messages in both directions. Codex and Claude achieved full scores on those cases, while OpenCode completed only the AOB repair. The four unfinished OpenCode cases were `hard_crash_dump`, `hard_resource_stream`, `hard_tls_state`, and `hard_tls_stream2`.

Claude lost points on `pe_reloc/q1` (2), `hard_delay_import/q6` (10), and `hard_crash_dump/q10` (14). These are question-level outcomes, not a manual audit of every explanation. Free-form reasoning was retained but did not contribute automatic points.

Historical answers from the first 26 cases were reused only after SHA-256 verification of their prompts and artifacts against the [v9 evidence manifest](../v9/v9_evidence_manifest.json). The [v10 evidence manifest](v10_evidence_manifest.json) freezes all 27 cases. The v9 DSL scorer was corrected to accept `b` as an alias for `bits` in shift and rotation operations; all archived answers were rescored under the same rule without changing submissions.

Elapsed time includes model reasoning, tool calls, and provider latency. The local case directory did not isolate the agent from the full repository. Perfect v10 accuracy for Codex demonstrates a ceiling on this bank and motivated the [experimental v11 pilot](../hard_suite/PILOT.md).

[Machine-readable summary](summary.json) · [Codex score](codex_score.json) · [Claude score](claude_score.json) · [OpenCode score](opencode_score.json) · [Original Spanish campaign report](RESULTADOS.md)
