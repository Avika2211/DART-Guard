"""Fail-closed external authorization interface (not model-derived)."""
from dataclasses import dataclass
from typing import Callable, Any
@dataclass(frozen=True)
class PolicyRecord:
    permitted: bool
    version: str
    fresh: bool
    provenance: str

class IndependentPolicy:
    def __init__(self, provider: Callable[[Any], PolicyRecord]):
        self.provider = provider
    def authorize(self, context: Any) -> bool:
        try:
            p = self.provider(context)
            return isinstance(p, PolicyRecord) and p.permitted and p.fresh and bool(p.version) and bool(p.provenance)
        except Exception:
            return False
