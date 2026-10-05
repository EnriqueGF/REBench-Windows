# Extended two-case comparison — October 5, 2026

The [original pilot](PILOT.md) allowed 300 seconds per case. This follow-up gives **every model 900 seconds per case** and uses a fresh attempt on each of the same two fixed artifacts. It is a **two-case calibration**, not a full 13-case v11 leaderboard or a blind model evaluation. Static scores are multiplied by 100, giving a two-case maximum of 200 points.

| Model and CLI | Static PE /100 | UPX + VM /100 | Two-case total /200 |
|---|---:|---:|---:|
| Claude Opus 5.5 (`claude`) | 40.49 (144.81 s) | **100** (206.16 s) | **140.49** |
| Kimi K3 (OpenCode/OpenRouter) | 47.97 (323.08 s) | 0 (timeout, 900.05 s) | 47.97 |
| DeepSeek V4 Pro 0813 (OpenCode/OpenRouter) | 51.20 (105.11 s) | 0 (timeout, 900.05 s) | 51.20 |
| Codex Sol (`codex`) | 45.00 (195.94 s) | **100** (508.00 s) | **145.00** |
| Claude Opus 4.7 (`claude`) | 35.11 (107.09 s) | **100** (727.54 s) | **135.11** |
| DeepSeek V4.1 Flash (OpenCode/OpenRouter) | 55.88 (66.42 s) | 0 (timeout, 900.05 s) | 55.88 |
| Former OpenCode default GLM 5.3 gateway | Authentication failure | Not run | N/A |

The static case is [`pe_69e70ad5f453`](../../public_research/pe_69e70ad5f453/evidence.txt), whose evidence-file SHA-256 is `702b3b6612413941700cd13c6a89589e5a73f07ee80f4e2e7c544d6692238e1d`. The protected case is [`vm_e1a4c106677a`](../../public_upx/vm_e1a4c106677a/guard.exe), whose packed PE SHA-256 is `4aa2c68ce9632f514b4bb2756304110c80d15232b87eaddc044cf912bff9de8a`. The static task uses field-level partial credit. The VM task awards 75 points for a code accepted by the executable and 25 for the exact hash of its decrypted bytecode. All three 100-point VM results passed **both** checks. A timeout means no final answer arrived before the limit; it is not evidence that a tested code was rejected.

In the 300-second pilot, Codex Sol and Opus 4.7 timed out on this packed PE. Under the longer budget they completed in 508.00 and 727.54 seconds respectively. This makes the five-minute table an unfair basis for saying that only Opus 5.5 could solve the task. The attempts are independent and model behavior varies between runs; this follow-up does not measure pass rates or isolate the effect of time from stochastic variation. Static scores also changed across the fresh attempts, including Opus 5.5 dropping from 58.36 to 40.49 and DeepSeek V4.1 Flash rising from a timeout to 55.88.

## Method and caveats

- Each model received the same static dossier and the same packed PE, with a 900-second wall-clock limit for each. The limit includes provider latency and tool work. These CLIs expose different tools and infrastructure, so elapsed time is not a pure measure of model speed.
- Model identifiers were `claude-opus-5-5`, `openrouter/moonshotai/kimi-k3`, `openrouter/deepseek/deepseek-v4-pro-0813`, `gpt-6-sol` through Codex CLI v0.160.0 at high reasoning effort, `claude-opus-4-7`, and `openrouter/deepseek/deepseek-v4.1-flash` respectively. The OpenCode default GLM gateway had rejected its Bearer credential in the original pilot; it has no valid score here.
- Two foreground `claude` parent processes failed to leave a result during the Opus 4.7 protected run. These are infrastructure failures, **not scored model failures**. A fresh Claude background session then received the same prompt and PE. Its final JSON was timestamped 727.54 seconds after session start, recovered into the standard result format, and graded by the same executable oracle. The recovered result identifies `execution_mode: claude_background` and records a SHA-256 of the locally retained session trace. The raw background transcript is omitted from this public repository because it contains unrelated local environment metadata.
- The public checkout includes sources, seeds, and answer keys. A temporary working directory does not prevent an agent from accessing them. Treat this as a local, non-blind calibration. For a defensible leaderboard, isolate agents from answer keys, use held-out variants, run several trials per model, and score all thirteen cases under a frozen protocol.

## Raw results

| Model | Static attempt and score | Protected attempt and score |
|---|---|---|
| Claude Opus 5.5 | [attempt](../research/claude_opus_5_5_900.json), [score](../research/claude_opus_5_5_900_score.json) | [attempt](../protected/claude_opus_5_5_upx_900.json), [score](../protected/claude_opus_5_5_upx_900_score.json) |
| Kimi K3 | [attempt](../research/kimi_k3_openrouter_900.json), [score](../research/kimi_k3_openrouter_900_score.json) | [attempt](../protected/kimi_k3_openrouter_upx_900.json), [score](../protected/kimi_k3_openrouter_upx_900_score.json) |
| DeepSeek V4 Pro 0813 | [attempt](../research/deepseek_v4_pro_0813_openrouter_900.json), [score](../research/deepseek_v4_pro_0813_openrouter_900_score.json) | [attempt](../protected/deepseek_v4_pro_0813_openrouter_upx_900.json), [score](../protected/deepseek_v4_pro_0813_openrouter_upx_900_score.json) |
| Codex Sol | [attempt](../research/codex_sol_900.json), [score](../research/codex_sol_900_score.json) | [attempt](../protected/codex_sol_upx_900.json), [score](../protected/codex_sol_upx_900_score.json) |
| Claude Opus 4.7 | [attempt](../research/claude_opus_4_7_900.json), [score](../research/claude_opus_4_7_900_score.json) | [recovered attempt](../protected/claude_opus_4_7_upx_900.json), [score](../protected/claude_opus_4_7_upx_900_score.json) |
| DeepSeek V4.1 Flash | [attempt](../research/deepseek_v4_1_flash_openrouter_900.json), [score](../research/deepseek_v4_1_flash_openrouter_900_score.json) | [attempt](../protected/deepseek_v4_1_flash_openrouter_upx_900.json), [score](../protected/deepseek_v4_1_flash_openrouter_upx_900_score.json) |

For a new trial, use `agentre_track.py run` and `protected_vm_bench.py run` with `--case`, `--timeout 900`, the selected CLI profile and exact `--model` where applicable, and a new `--output` path. Grade each result with its track's `grade` subcommand. Do not reuse any of the published answer files as agent input.
