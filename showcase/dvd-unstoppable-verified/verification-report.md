# Verification report

Run `9f845086`. Damn Vulnerable DeFi, `UnstoppableVault.flashLoan`.

| field | value |
|---|---|
| existing_tests_pass | false |
| differential_equivalent | true |
| halmos_proved | true |
| halmos_timed_out | false |
| counterexample | none |
| status | verified |
| cost | $0.6519 |

`existing_tests_pass` is recorded and is not a gate. DVD's own tests assert the exploit, so they fail after a correct patch.

Differential passed on attempt 3 (attempts 1 and 2 compiled and failed). Halmos was not retried. The audit log recorded `halmos_proved=true`. Halmos stdout was not kept; `halmos-output.txt` is a replay of the saved `Verify.t.sol` from this run:

```
[PASS] check_flashLoanNeverBlockedByBalanceMismatch() (paths: 47, time: 8.28s, bounds: [])
Symbolic test result: 1 passed; 0 failed; time: 9.31s
```

PoC `hyp-0` confirmed on attempt 1. Remediation defeated that exploit on attempt 1. The strategist returned 20 hypotheses; `UnstoppableVault.flashLoan` was listed first.
