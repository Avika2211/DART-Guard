"""A model-agnostic decision protection layer with an optional PyTorch adapter."""
from typing import Callable, Any
from .core import DecisionGuard, Action, Authorization, threshold_decision

class DARTGuard:
    """Wrap a decision model; protect EXECUTE with authorization and verification.

    A verifier must use a separately managed fault domain in actual deployments.
    Caller MUST route actions exclusively through returned `final` decisions.
    """
    def __init__(self, model: Callable[[Any], float],
                 verifier: Callable[[Any], float],
                 authorization: Callable[[Any], Authorization],
                 *, fallback: Action = Action.INSPECT,
                 decision=threshold_decision):
        if not callable(model) or not callable(verifier) or not callable(authorization):
            raise TypeError("model, verifier and authorization must be callable")
        if model is verifier:
            raise ValueError("verifier cannot be the identical callable")
        self._guard = DecisionGuard(
            model=model, secondary_model=verifier, authorization=authorization,
            require_agreement=True, fallback=fallback, decision=decision
        )
    def predict(self, observation, context):
        return self._guard.predict(observation, context)
    def __call__(self, observation, context):
        return self.predict(observation, context)

def pytorch_probability_adapter(module, *, device="cpu", output="probability"):
    """Convert a single-score torch.nn.Module to a callable.

    For `output="logit"`, sigmoid is applied. Module must output one scalar.
    This is an inference adapter, not an independent verifier.
    """
    if output not in ("probability", "logit"):
        raise ValueError("output must be probability or logit")
    import torch
    module.eval()
    def predict(observation):
        with torch.inference_mode():
            tensor = torch.as_tensor(observation, dtype=torch.float32, device=device)
            score = module(tensor).reshape(-1)
            if score.numel() != 1:
                raise ValueError("expected one output score")
            if output == "logit":
                score = torch.sigmoid(score)
            return float(score.item())
    return predict
