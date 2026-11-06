"""Fail-closed decision protection with independent authorization.

Research prototype; no claims of hardware-fault detection or safety certification.
"""
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Any, Optional
import math

class Action(str, Enum):
    DELAY = 'DELAY'
    INSPECT = 'INSPECT'
    ASK = 'ASK'
    EXECUTE = 'EXECUTE'

@dataclass(frozen=True)
class Authorization:
    permitted: bool
    fresh: bool
    reason: str = ''

@dataclass(frozen=True)
class GuardResult:
    proposed: Action
    final: Action
    authorized: bool
    verified: bool
    reason: str
    primary_score: Optional[float]
    secondary_score: Optional[float]


def threshold_decision(probability: float) -> Action:
    """A1-A3 proxy mapping; configurable policies can use another mapping."""
    if not math.isfinite(probability) or not 0 <= probability <= 1:
        raise ValueError('Expected finite probability in [0, 1]')
    if probability < .10:
        return Action.DELAY
    if probability < .30:
        return Action.INSPECT
    if probability < .60:
        return Action.ASK
    return Action.EXECUTE

class DecisionGuard:
    """Protects EXECUTE; other actions pass through if valid.

    `authorization(context)` MUST query an independent trusted source. Never
    infer permission from the model's proposed action or clean-model labels.

    Optional `secondary_model` must be independent enough to provide meaningful
    fault diversity. Comparing two invocations of the same corrupted weights
    is NOT a fault-tolerance guarantee.
    """
    def __init__(self, model: Callable[[Any], float],
                 authorization: Callable[[Any], Authorization],
                 secondary_model: Optional[Callable[[Any], float]] = None,
                 require_agreement: bool = False,
                 fallback: Action = Action.INSPECT,
                 decision: Callable[[float], Action] = threshold_decision):
        if fallback == Action.EXECUTE:
            raise ValueError('Fallback must not EXECUTE')
        if require_agreement and secondary_model is None:
            raise ValueError('Agreement requires a secondary model')
        self.model = model
        self.authorization = authorization
        self.secondary_model = secondary_model
        self.require_agreement = require_agreement
        if not isinstance(fallback, Action):
            raise TypeError('fallback must be an Action')
        self.fallback = fallback
        self.decision = decision

    def predict(self, state: Any, context: Any) -> GuardResult:
        score = None
        secondary = None
        try:
            score = float(self.model(state))
            proposed = self.decision(score)
        except Exception:
            return GuardResult(self.fallback, self.fallback, False, False,
                               'invalid_primary_output', score, None)
        if not isinstance(proposed, Action):
            return GuardResult(self.fallback, self.fallback, False, False,
                               'invalid_decision_type', score, None)
        if proposed != Action.EXECUTE:
            return GuardResult(proposed, proposed, False, False,
                               'non_execution', score, None)
        # Independent verification is mandatory for every EXECUTE.
        try:
            auth = self.authorization(context)
            if not isinstance(auth, Authorization):
                raise TypeError('authorization must return Authorization')
            allowed = auth.permitted is True and auth.fresh is True
        except Exception:
            return GuardResult(proposed, self.fallback, False, False,
                               'authorization_unavailable', score, None)
        if not allowed:
            return GuardResult(proposed, self.fallback, False, False,
                               'authorization_denied_or_stale', score, None)
        if self.require_agreement:
            try:
                secondary = float(self.secondary_model(state))
                second_action = self.decision(secondary)
            except Exception:
                return GuardResult(proposed, self.fallback, True, False,
                                   'invalid_secondary_output', score, secondary)
            if not isinstance(second_action, Action) or second_action != Action.EXECUTE:
                return GuardResult(proposed, self.fallback, True, False,
                                   'secondary_disagreement', score, secondary)
        return GuardResult(proposed, proposed, True, True,
                           'authorized_execution', score, secondary)
