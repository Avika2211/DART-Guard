# DART-Guard

**Decision Assurance and Runtime Trust Guard**

*A Runtime Decision-Protection Layer Against Silent Data Corruption in System-1 Decision Models.*

> **Research prototype only:** Not independently hardware fault-isolated or certified for production security deployment.

DART-Guard wraps an existing neural decision model without retraining. It requires secondary verification, authorization, and fresh metadata before permitting an `EXECUTE` decision. It includes a research execution-gateway prototype with short-lived, single-use permits.

## Install and test

```bash
pip install -e '.[dev]'
pytest -q
```

## Example

```python
from dartguard import DARTGuard, Authorization

guard = DARTGuard(
    model=lambda state: state["primary_probability"],
    verifier=lambda state: state["verifier_probability"],
    authorization=lambda ctx: Authorization(ctx["permitted"], ctx["fresh"]),
)
result = guard.predict(
    {"primary_probability": .95, "verifier_probability": .20},
    {"permitted": True, "fresh": True},
)
assert result.final.value == "INSPECT"
```

**The example is demonstrative:** model/verifier callbacks must be independently implemented and trusted for real use. The executable must not accept unguarded decisions.

## Controlled experimental result

In a trained System-1 *proxy* checkpoint experiment with 6,300 FP32 fault attempts, 109 non-EXECUTE→EXECUTE transitions were observed. With a clean secondary verifier, 0 passed the wrapper; when the verifier shared corrupted output, 85 authorized transitions passed. Synthetic authorization labels and same-hardware execution limit conclusions.

The library focuses on the EXECUTE boundary; other decisions are not redundantly checked. It is **not a universal SDC detector**.

## Security caveats

The current gateway does **not** enforce a protected service boundary: an untrusted caller able to forge GuardResult and call permit issuance can obtain a permit; action arguments are not bound to permits; replay state is in-memory. Do not deploy it as a trusted execution gateway without redesign and independent security review.

See [security notes](GATEWAY_SECURITY_NOTES.md), [research scope](FINAL_SCOPE.md), [layer usage](README_LAYER.md), and [PyPI publishing](PUBLISHING.md).

