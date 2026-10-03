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
