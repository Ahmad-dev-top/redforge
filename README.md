🔴 Live demo: [https://ahmad-dev-top.github.io/redforge-dashboard/](https://ahmad-dev-top.github.io/redforge-dashboard/)

# RedForge

Autonomous smart-contract exploit and formal-verification engine. Point it at a Solidity repository and it finds a bug, confirms it, patches it, and checks the fix.

## Proven on Damn Vulnerable DeFi

One end-to-end run of [Damn Vulnerable DeFi](https://github.com/theredguild/damn-vulnerable-defi), UnstoppableVault, finished `verified`. Artifacts are in [showcase/dvd-unstoppable-verified/](showcase/dvd-unstoppable-verified/).

| | |
|---|---|
| Vulnerability | `UnstoppableVault.flashLoan` (funds locked / denial of service) |
| Found by | Slither plus the LLM strategist, listed first of 20 hypotheses |
| Confirmed | Harness-checked `funds_locked` oracle, PoC attempt 1 |
| Patched | The pre-loan `convertToShares` equality check is removed. After repayment the patch reverts if `totalAssets()` is below the pre-loan balance. The same exploit was re-run and defeated |
| Verified | Differential behaviour preserved on attempt 3. Halmos proved `check_flashLoanNeverBlockedByBalanceMismatch` (replay of the saved property: 47 paths, 8.28s) |
| End state | `verified`. Cost $0.6519. Run `9f845086`. Untrusted code ran in a no-network sandbox |

This is one target in one repository. It is not a general guarantee.

<!-- BENCHMARK_TABLE_START -->
Fifteen challenges in that same repository. The first twelve rows are from one full-suite run. `puppet-v3`, `abi-smuggling`, and `compromised` were re-run after that run stopped on an empty API balance. `compromised` needs an off-chain key leak and is kept in the table.

| challenge | found | confirmed | patched | verified | cost | time |
|---|:--:|:--:|:--:|:--:|--:|--:|
| unstoppable | • | • | • |  | $0.364 | 1190s |
| naive-receiver | • | • | • |  | $0.231 | 944s |
| truster |  | • | • |  | $0.144 | 4014s |
| side-entrance | • | • | • |  | $0.249 | 1394s |
| the-rewarder | • | • | • |  | $0.645 | 1426s |
| selfie | • | • |  |  | $0.302 | 967s |
| puppet | • | • | • |  | $0.621 | 1714s |
| puppet-v2 | • |  |  |  | $0.054 | 213s |
| free-rider | • | • | • | • | $0.369 | 1184s |
| backdoor | • | • | • |  | $0.268 | 922s |
| climber | • | • | • | • | $0.235 | 921s |
| wallet-mining | • | • |  |  | $0.262 | 881s |
| puppet-v3 | • |  |  |  | $0.471 | 642s |
| abi-smuggling | • | • |  |  | $0.451 | 1134s |
| compromised | • | • | • |  | $0.213 | 775s |

**13/15 confirmed, 2/15 verified** · total cost $4.88 · detection 93% · exploit-confirmed 87% · verified 13%

The full table is also in [showcase/dvd-benchmark.md](showcase/dvd-benchmark.md).
<!-- BENCHMARK_TABLE_END -->

## How it works

The pipeline is scout, strategist, PoC loop, remediation, then verification. The harness decides whether an exploit worked: the model does not. `verified` requires the confirming exploit to fail on the patch, a passing differential test, and a Halmos proof. A Halmos timeout stays `patched`. It is not reported as `verified`.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env            # add your Anthropic key

docker build -t redforge-sandbox:latest -f docker/sandbox.Dockerfile .
redforge sandbox-check              # verifies the sandbox + that network is off

redforge scan https://github.com/OWNER/REPO   # clone + detect + Slither
redforge audit https://github.com/OWNER/REPO  # full pipeline
```

On Windows, activate with `.venv\Scripts\activate` and run the commands from the repository root.

## Layout

```
src/redforge/
  config.py          settings (env-driven)
  schemas.py         typed contracts + shared AuditState
  sandbox/           hardened Docker runner
  repo/              cloner + project detector
  static_analysis/   Slither runner -> Finding[]
  foundry/           forge test wrapper (sandboxed)
  oracles/           success oracles (anti-cheat)
  eval/              benchmark datasets + metrics harness
  cli.py             redforge entrypoint
docker/sandbox.Dockerfile
showcase/            saved audit artifacts, not product code
tests/
```

## Safety

Untrusted code runs only in a Docker sandbox with no network, resource caps, dropped capabilities, a non-root user, and a read-only root filesystem. PoCs are generated at runtime and are not committed as product code. The copies under `showcase/` are saved outputs from a benchmark run.
