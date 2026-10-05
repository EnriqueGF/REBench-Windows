# REBench-Windows

A Windows-focused reverse-engineering benchmark for coding agents. It includes PE analysis, x86/x64 ABI and unwind metadata, TLS callbacks, delayed imports, resources, AOB signatures, a real Windows minidump, encrypted bytecode, and packed Windows executables. Cases are synthetic and designed for authorized local analysis.

The repository contains two benchmark generations:

| Track | Cases | Maximum | Status |
|---|---:|---:|---|
| v10 legacy bank | 27 | 1,380 points | Frozen Spanish-language prompts and historical results |
| v11 experimental bank | 13 | 1,300 points | Ten static PE dossiers plus three seeded UPX-packed VM programs |

The v10 prompts remain in their original Spanish. Translating them would change the evaluated tasks and invalidate comparison with the recorded runs. Documentation and the new v11 agent prompts are in English.

## Results at a glance

The latest [900-second comparison](results/hard_suite/EXTENDED_900.md) repeats **two of the thirteen v11 cases** with fresh attempts for each model. Its static case is normalized to 100 points in this table.

| Model and CLI | Static PE /100 | UPX + VM /100 | Two-case total /200 |
|---|---:|---:|---:|
| Claude Opus 5.5 (`claude`) | 40.49 | 100 | 140.49 |
| Kimi K3 (OpenCode/OpenRouter) | 47.97 | 0, timeout | 47.97 |
| DeepSeek V4 Pro 0813 (OpenCode/OpenRouter) | 51.20 | 0, timeout | 51.20 |
| Codex Sol (`codex`) | 45.00 | 100 | 145.00 |
| Claude Opus 4.7 (`claude`) | 35.11 | 100 | 135.11 |
| DeepSeek V4.1 Flash (OpenCode/OpenRouter) | 55.88 | 0, timeout | 55.88 |
| OpenCode's former default GLM gateway | Authentication failure | Not run | N/A |

A timeout means no final answer arrived before the limit. Codex Sol and Opus 4.7 solved the packed case under 900 seconds after timing out in the [original 300-second pilot](results/hard_suite/PILOT.md). **These are local two-case results, not a full v11 leaderboard or a blind evaluation.** The [v10 results](results/v10/RESULTS.md) show Codex Sol at 1,380/1,380, Opus 4.7 at 1,354/1,380, and the former OpenCode default at 572/1,380 with four unfinished cases. Results from the two generations are not directly comparable.

## Requirements

- Windows with Python 3.10 or newer.
- To build new PE samples: MSVC x64 Build Tools and the Windows SDK. Prebuilt samples are included.
- To generate v11 static dossiers: `pefile==2024.8.26` and `capstone==5.0.7`.
- To run agents: the CLI and credentials for `codex`, `claude`, `opencode`, or `agy`, as applicable. Provider usage may incur charges.
- UPX 5.2.1 is downloaded by the build script if absent; the archive SHA-256 is checked.

The external [AgentRE-Bench V3](https://github.com/agentrebench/AgentRE-Bench) repository is pinned as a Git submodule. Clone with submodules and preserve its original line endings so its integrity checks pass:

```powershell
git -c core.autocrlf=false clone --recurse-submodules https://github.com/EnriqueGF/REBench-Windows.git
cd .\REBench-Windows
python .\verify_agentre_windows.py
python -m pip install pefile==2024.8.26 capstone==5.0.7
```

## Run the v11 experimental bank

The checked-in `public_research/`, `public_protected/`, and `public_upx/` directories contain ready-to-use samples. To regenerate them, use:

```powershell
python .\agentre_track.py build
python .\protected_vm_bench.py build --count 3
python .\protected_vm_bench.py upx
```

`build` without a seed generates new VM variants. The current checked-in examples have published reference data, so generate **fresh variants and keep their answer key off the agent machine** for a blind evaluation. Building replaces the corresponding local samples and manifest; keep a clean checkout if you want to reproduce the published pilot.

Run the complete 13-case bank with one model per profile and a 900-second limit per case:

```powershell
python .\hard_suite.py run codex --research-timeout 900 --vm-timeout 900
python .\hard_suite.py run claude --model claude-opus-5-5 --research-timeout 900 --vm-timeout 900
python .\hard_suite.py run opencode --model openrouter/moonshotai/kimi-k3 --research-timeout 900 --vm-timeout 900
```

`hard_suite.py` names output files by **profile**, so use a fresh checkout or distinct per-track `--output` paths when comparing several models through the same CLI. For one of the extended comparison cases:

```powershell
python .\agentre_track.py run claude --case pe_69e70ad5f453 --timeout 900 --model claude-opus-5-5 --output .\results\research\my_static.json
python .\agentre_track.py grade .\results\research\my_static.json
python .\protected_vm_bench.py run claude --upx --case vm_e1a4c106677a --timeout 900 --model claude-opus-5-5 --output .\results\protected\my_vm.json
python .\protected_vm_bench.py grade .\results\protected\my_vm.json
```

The static track gives field-level partial credit and penalizes unsupported claims. The VM track awards 75 points for any code accepted by the executable and 25 for the exact SHA-256 of its decrypted, decompressed bytecode. Raw output, stderr, elapsed time, parsed answers, infrastructure errors, and attempts are retained. The combined score treats missing or timed-out cases as zero while marking incomplete runs as provisional. See [RESEARCH.md](RESEARCH.md) for construction and limitations.

The PE samples are packed with **real UPX** and run a **custom VM with LZ-style compression and XTEA-CTR encryption**. They are not protected with Themida or VMProtect. An optional genuine Themida wrapping command is available only when a local Themida installation and project are supplied.

## Use the frozen v10 bank

The legacy bank has 27 cases, 123 questions, and 1,380 points. Its prompts are Spanish-language historical fixtures. Basic commands:

```powershell
python .\benchmark.py validate
python .\benchmark.py list
python .\benchmark.py show pe_reloc
python .\benchmark.py solutions --case pe_reloc
python .\benchmark.py export .\public_export
python .\benchmark.py run codex --case pe_rva --output .\results\my_codex.json
python .\benchmark.py grade .\results\my_codex.json --output .\results\my_codex_score.json
```

`benchmark.py run` starts each case in a fresh temporary directory, saves raw CLI output and structured responses after each case, and supports `--timeout`, `--jobs`, and `--config` to choose exact commands and models. `benchmark.py compare` combines two or more result files. `benchmark.py export` creates per-case folders with prompts and public artifacts but no reference answers.

The v10 scorer uses exact selection and numeric checks, executable oracles, hidden-input functional tests, AOB uniqueness across builds, and a Windows crash dump. The four functional cases use 256, 256, 384, and 384 hidden inputs respectively. See the [v10 report](results/v10/RESULTS.md) and [technical sources](RESEARCH.md).

## Reproducibility and evaluation boundaries

- This **public source tree includes reference answers, seeds, generator sources, and raw historical runs**. Do not give it to an agent during a blind attempt. Stage only the case dossier or PE on an isolated machine, and keep the scorer and answer key outside that machine. A temporary working directory alone is not a security boundary.
- The static AgentRE track is a local adaptation: agents receive textual PE evidence rather than the upstream interactive tool interface. Do not present its scores as official AgentRE-Bench results.
- One upstream level-23 C2 answer conflicts with the bytes frozen in its PE. The local scorer applies a documented byte-level correction without editing the upstream submodule; see [RESEARCH.md](RESEARCH.md).
- The pilot uses different CLIs and providers. Elapsed time includes provider latency and tool work. A single case cannot establish a general model ranking.
- To reproduce legacy results after rebuilding with a different MSVC toolchain, restore and verify the frozen artifacts:

```powershell
python .\results\v10\freeze_evidence.py restore
python .\results\v10\freeze_evidence.py verify
python .\results\v10\verify_reuse.py verify
python -m unittest discover -s .\tests -v
```

## Repository layout

| Path | Contents |
|---|---|
| `benchmark.py`, `public/`, `public_export/` | Legacy cases, scorer, and exported public cases |
| `agentre_track.py`, `public_research/` | Static PE dossiers and local AgentRE adaptation |
| `protected_vm_bench.py`, `public_protected/`, `public_upx/` | Seeded custom VM sources and PE samples |
| `hard_suite.py` | Combined 13-case runner and scorer |
| `private/` | Published reference answers and build sources; keep off contestant machines |
| `results/` | Historical raw attempts, scores, and English reports |
| `external/AgentRE-Bench/` | Pinned MIT-licensed upstream Git submodule |

The project's own code is published without a license grant at present. The AgentRE-Bench submodule retains its upstream MIT license. UPX is downloaded from its official release and is not vendored here.
