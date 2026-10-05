# Experimental v11 pilot — October 5, 2026

For fresh attempts with a 900-second limit, see the [extended comparison](EXTENDED_900.md). Codex Sol and Claude Opus 4.7 both solved the packed VM case under that longer budget.

These calibration runs cover **two of thirteen cases**, not the full 1,300-point v11 bank. Every case had a 300-second limit. The static AgentRE-style score is multiplied by 100 in the comparison table, so the two-case maximum is 200 points. A timeout counts as zero because no final answer was submitted; it does not prove that a tested candidate was wrong.

| Model and CLI | Static PE /100 | UPX + VM /100 | Pilot /200 |
|---|---:|---:|---:|
| Claude Opus 5.5 (`claude`) | **58.36** (130.81 s) | **100** (209.83 s) | **158.36** |
| Kimi K3 (OpenCode/OpenRouter) | 53.66 (97.38 s) | 0 (timeout, 300.05 s) | 53.66 |
| DeepSeek V4 Pro 0813 (OpenCode/OpenRouter) | 49.96 (92.03 s) | 0 (timeout, 300.05 s) | 49.96 |
| Codex Sol (`codex`) | 46.44 (140.34 s) | 0 (timeout, 300.05 s) | 46.44 |
| Claude Opus 4.7 (`claude`) | 37.00 (75.55 s) | 0 (timeout, 300.03 s) | 37.00 |
| DeepSeek V4.1 Flash (OpenCode/OpenRouter) | 0 (timeout, 300.05 s) | 0 (timeout, 300.05 s) | 0 |
| Former OpenCode default GLM 5.3 gateway | No valid run: Bearer key rejected | Not run | N/A |

Claude Opus 5.5 produced a binary-accepted code **and** the exact decrypted-bytecode SHA-256. Both checks passed the executable oracle and scorer. Its canonical model `claude-opus-5-5` was confirmed through a `claude` CLI probe. An earlier OpenCode/OpenRouter attempt for this model returned a provider error before producing an answer and is **excluded** from the comparison.

The static score printed by a track-level `grade` command is averaged over all ten static cases. For example, a single-case Kimi K3 pilot prints `0.0537/1.0` as the ten-case average, while its **case score** is `0.5366/1.0`. The table reports the latter, scaled to 100. The same distinction applies to the other single-case static trials. These are local adaptations and must not be reported as official AgentRE-Bench scores.

## Earlier VM calibration

The first custom VM compared characters independently and was retired after Codex solved two variants. The second VM combines three eight-character blocks in 64-bit state. Before UPX packing, Codex Sol and Claude Opus 4.7 both scored **100/100** on one second-generation variant, taking 573.84 and 533.38 seconds respectively under a looser 900-second budget. The final pilot added genuine UPX packing and reduced the limit to **300 seconds**. Both then timed out. Packing and budget changed together, so the pilot does not establish which change caused the timeouts.

The three packed PEs are 54,784 bytes each, compared with 113,664 bytes before UPX. They passed `upx -t` and 38-input differential checks against their original executables. The 300-second budget follows [CrackMeBench](https://arxiv.org/abs/2605.10597). No genuine Themida or VMProtect sample was used.

The upstream level-23 C2 ground truth was corrected locally: bytes in its PE decode to an invalid `inet_addr` string rather than the published `192.0.2.100`. That correction did not change any of these pilot scores; see [RESEARCH.md](../../RESEARCH.md).

## Raw attempts and scoring evidence

| Model | Static attempt and score | UPX + VM attempt and score |
|---|---|---|
| Claude Opus 5.5 | [attempt](../research/claude_opus_5_5_pilot.json), [score](../research/claude_opus_5_5_pilot_score.json) | [attempt](../protected/claude_opus_5_5_upx_pilot.json), [score](../protected/claude_opus_5_5_upx_pilot_score.json) |
| Kimi K3 | [attempt](../research/kimi_k3_openrouter_pilot.json), [score](../research/kimi_k3_openrouter_pilot_score.json) | [attempt](../protected/kimi_k3_openrouter_upx_pilot.json), [score](../protected/kimi_k3_openrouter_upx_pilot_score.json) |
| DeepSeek V4 Pro 0813 | [attempt](../research/deepseek_v4_pro_0813_openrouter_pilot.json), [score](../research/deepseek_v4_pro_0813_openrouter_pilot_score.json) | [attempt](../protected/deepseek_v4_pro_0813_openrouter_upx_pilot.json), [score](../protected/deepseek_v4_pro_0813_openrouter_upx_pilot_score.json) |
| Codex Sol | [attempt](../research/codex_current.json), [score](../research/codex_current_score.json) | [attempt](../protected/upx_codex_300_pilot.json), [score](../protected/upx_codex_300_score.json) |
| Claude Opus 4.7 | [attempt](../research/claude_retry.json), [score](../research/claude_score_pilot.json) | [attempt](../protected/upx_claude_300_pilot.json), [score](../protected/upx_claude_300_score.json) |
| DeepSeek V4.1 Flash | [attempt](../research/deepseek_v4_1_flash_openrouter_pilot.json), [score](../research/deepseek_v4_1_flash_openrouter_pilot_score.json) | [attempt](../protected/deepseek_v4_1_flash_openrouter_upx_pilot.json), [score](../protected/deepseek_v4_1_flash_openrouter_upx_pilot_score.json) |
| Former OpenCode default GLM 5.3 | [gateway error](../research/opencode.json) | Not run |

Some earlier VM attempts had provider-capacity or Claude CLI permission errors. They were retained in the raw results and retried without changing the case or model. Different CLIs, provider latency, and tool access affect elapsed time. Local temporary directories were **not an enforceable sandbox**: the agent machine also held the repository and answer keys. Run future blind trials on a separate isolated system with only the case artifact available.
