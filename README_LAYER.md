# DART-Guard: Decision protection layer

Wrap an existing decision model without retraining or modifying it.

```python
from dartguard import DARTGuard, Authorization
guard = DARTGuard(
    model=existing_model_probability,
    verifier=separately_operated_verifier_probability,
    authorization=lambda ctx: Authorization(permitted=ctx["allowed"], fresh=ctx["fresh"])
)
result = guard.predict(observation, context)
# Only dispatch result.final, never the unguarded model output.
```

**Current protection scope:** EXECUTE-specific authorization and second-opinion agreement. Non-EXECUTE actions are passed through without redundant verification. This does not detect all SDC, correct corrupted weights, or prove safety.

PyTorch models can be adapted using `pytorch_probability_adapter`. For a trusted deployment, verifier isolation and authorization provenance must be assessed externally; same-process replicas are not hardware independent.

**Research prototype.** PyPI publication is distinct from deployment of safety-critical autonomous agents.
