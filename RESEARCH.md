# Research and design notes for REBench-Windows v11

Codex Sol scored 1,380/1,380 on the v10 bank, so adding more questions of the same kind offered little discrimination. The experimental v11 tracks test PE technique identification, exact recovery of encrypted data, decompression and interpretation of VM bytecode, and recovery of a code accepted by a Windows executable.

## Sources informing the design

| Source | Relevant finding | Local design choice |
|---|---|---|
| [AgentRE-Bench V3](https://github.com/agentrebench/AgentRE-Bench/blob/main/version3/ANALYSIS.md) | Twenty PE32+ binaries in ten stripped/unstripped pairs; deterministic partial-credit scoring with penalties. No published model reached the maximum. | Adapt the ten stripped binaries into static evidence dossiers and use the upstream scorer. |
| [CrackMeBench](https://arxiv.org/abs/2605.10597) | Seeded generated crackmes, executable oracle, externally scored submissions, time budgets, and pass@1/pass@3. | Generate benign PE variants from seeds and verify submitted codes by execution. |
| [CREBench](https://github.com/wangyu-ovo/CREBench) | Separates identification, key extraction, reimplementation, and final recovery. | Score the accepted code and decrypted bytecode hash separately. |
| [Themida VM macro](https://www.oreans.com/help/tm/hm_vm-macro.htm) and [command-line protection](https://www.oreans.com/help/tm/hm_protecting-through-the-command.htm) | Commercial protection can translate selected code into VM opcodes and automate PE protection. | Provide an optional authentic Themida step, labeled as such only after protecting and testing the binary. |
| [VMProtect manual](https://www.vmpsoft.com/vmprotect/user-manual) | Virtualization, mutation, encryption, and packing can vary by build. | Vary the custom VM's seed, opcode map, key, and input order. |
| [UPX 5.2.1 release](https://github.com/upx/upx/releases/tag/v5.2.1) | Genuine Windows PE packing. | Pack the generated PE samples and verify `upx -t` and oracle equivalence. |

## Static AgentRE adaptation

`agentre_track.py build` checks the pinned upstream commit, selects only stripped PE files, and generates a dossier for each with headers, sections, entropy, imports, ASCII/UTF-16 strings, and x64 disassembly. The agent receives **the dossier, not the PE**. The case ID is derived from a builder salt and does not contain the original level; this public source release also contains that salt, so the ID is not a security boundary. The upstream scorer returns field-level scores and a 0–1 total; unanswered cases contribute zero to the local bank total.

This is **not the official AgentRE protocol**. The upstream agents have an interactive tool interface with a 25-call limit; this adaptation supplies a complete static dump. Published upstream answer keys and broad filesystem access also prevent the local pilot from being blind. For a credible tournament, run each agent in an isolated VM or container without network access, stage only its dossier, and keep the upstream repository and `private/` off the contestant machine.

`verify_agentre_windows.py` validated 120 published rows and the hashes of 366 raw files, binaries, sources, ground truths, and harness files. The wrapper only normalizes a POSIX-vs-Windows ledger-path comparison. Clone with `git -c core.autocrlf=false` so upstream line endings match its recorded hashes.

### Audited level-23 C2 correction

One upstream ground truth conflicts with bytes frozen in its PE. The 13-byte ciphertext `93 C3 CE AD 20 5F 8B DA DD 8A D3 99 32` and repeating XOR key `DE AD BE EF 13 37 CA FE` yield hex `4d6e70423368412403276d7621`, or `MnpB3hA$\x03'mv!`, **not** the published `192.0.2.100`. The program passes those bytes to `inet_addr`; [Microsoft documents](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-inet_addr) that an invalid IPv4 string returns `INADDR_NONE` (`255.255.255.255`). The code then uses port 8443.

The local scorer corrects only this answer and marks the report `local_c2_byte_correction`. It does not change the external repository or upstream scorer. This is an additional reason not to label the local results as official AgentRE-Bench scores.

## Protected Windows PE track

`protected_vm_bench.py build` compiles three benign PE64 code validators. The VM bytecode is compressed using literal and backward-reference commands, then encrypted using XTEA in counter mode. At runtime the program decrypts, decompresses, and interprets the bytecode in memory. Each generated variant changes the accepted code, character access order, opcodes, key, and nonce.

The second-generation validator combines three blocks of eight characters using 64-bit state, multiplication, rotation, addition, and one comparison after each block. This avoids independently invertible per-character comparisons. Before publication, the builder checks that the correct code prints `ACCEPT` and a control prints `REJECT`.

`protected_vm_bench.py upx` packs the PEs with authentic UPX 5.2.1. Each result passes `upx -t` and a differential check against the original over 38 inputs per binary. The three packed PEs are 54,784 bytes each, versus 113,664 bytes before packing. UPX itself can be reversed with `upx -d`; the central task is recovering the encrypted bytecode and solving the VM's coupled state.

Scoring awards 75 points for any code accepted by the binary and 25 for the exact SHA-256 of the decrypted, decompressed bytecode. Missing JSON and timeouts score zero in the bank total, but infrastructure errors are recorded separately and may be retried without changing the model or case. Only locally generated benign PEs are executed as oracles; third-party AgentRE binaries are converted to text.

### Commercial protection option

A genuine Themida artifact requires a licensed installation and configured `.tmd` or `.tm` project. When both are available:

```powershell
python .\protected_vm_bench.py themida --executable 'C:\path\Themida.exe' --project 'C:\path\bench.tmd'
python .\protected_vm_bench.py run codex --themida --timeout 300
python .\protected_vm_bench.py grade .\results\protected\themida_codex.json
```

The command checks the protector's exit status, accepted and rejected inputs, and output SHA-256. No genuine Themida-protected sample has been generated for this repository. **UPX and the custom VM must not be described as Themida or VMProtect.**

## What the pilot established

The [two-case pilot](results/hard_suite/PILOT.md) used 300 seconds per case. Claude Opus 5.5, invoked through `claude`, scored 0.5836/1 on the static PE and recovered both required outputs from the UPX+VM binary in 209.83 seconds. Kimi K3 scored 0.5366/1 on the static PE but timed out on the packed case. The older uncompressed/unpacked VM pilot was solved by Codex Sol and Opus 4.7 with roughly nine minutes per case. The packed five-minute pilot caused both to time out. These observations do not isolate packing from time budget as causal factors.

The theoretical maximum remains 100%; no benchmark can guarantee that a future model will stay below it. For a meaningful leaderboard, freeze cases and budgets before testing, generate fresh variants with a held-out seed, stage only the artifact, verify behavior through an external oracle, retain every attempt, and expand the bank when the best model approaches the ceiling. One or two pilot cases are not a complete model comparison.
