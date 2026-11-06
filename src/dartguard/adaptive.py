"""Experimental verification scheduling; never substitutes for authorization."""
from dataclasses import dataclass
import math
@dataclass(frozen=True)
class VerificationDecision:
    verify: bool
    reason: str

def schedule_verification(probability: float, threshold: float = 0.60, band: float = 0.10) -> VerificationDecision:
    if not isinstance(probability, (int, float)) or not math.isfinite(probability) or not 0 <= probability <= 1:
        return VerificationDecision(True, "invalid_primary")
    if abs(probability-threshold) <= band:
        return VerificationDecision(True, "near_execute_boundary")
    return VerificationDecision(False, "outside_band")
