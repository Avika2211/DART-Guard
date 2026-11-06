"""Strict opt-in deployment configuration; not a security certification."""
from .core import Action, DecisionGuard, Authorization

class StrictDecisionGuard(DecisionGuard):
    """Fail-closed EXECUTE requires a separate verifier and authorization.

    Caller must provide an independently operated authorization service and
    a fault-diverse verifier. The library cannot attest their independence.
    """
    def __init__(self, model, authorization, secondary_model, *,
                 fallback=Action.INSPECT, decision=None):
        if secondary_model is None:
            raise ValueError("A secondary verifier is required")
        if secondary_model is model:
            raise ValueError("Same callable cannot be primary and secondary")
        if authorization is None:
            raise ValueError("Independent authorization is required")
        from .core import threshold_decision
        super().__init__(model, authorization, secondary_model,
                         require_agreement=True, fallback=fallback,
                         decision=decision or threshold_decision)
