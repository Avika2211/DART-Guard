"""Fail-closed subprocess verifier. Separate OS process is NOT hardware fault isolation."""
import json
import math
import subprocess
from typing import Sequence

class SubprocessVerifier:
    """Runs a JSON-stdin / JSON-stdout score worker per verification.

    Worker must read one JSON object from stdin and return {"probability": float}.
    Never run untrusted executable commands or feed untrusted pickle artifacts.
    """
    def __init__(self, command: Sequence[str], timeout_seconds: float = 15.0):
        if not command or timeout_seconds <= 0:
            raise ValueError("command and positive timeout required")
        self.command = tuple(command)
        self.timeout_seconds = timeout_seconds

    def __call__(self, state):
        try:
            payload = json.dumps({"state": state}, allow_nan=False)
            completed = subprocess.run(self.command, input=payload, text=True,
                                       capture_output=True, timeout=self.timeout_seconds,
                                       check=True)
            response = json.loads(completed.stdout)
            score = float(response["probability"])
            if not math.isfinite(score) or not 0 <= score <= 1:
                raise ValueError("invalid verifier score")
            return score
        except (subprocess.SubprocessError, OSError, ValueError, KeyError,
                TypeError, OverflowError, json.JSONDecodeError) as exc:
            raise RuntimeError("isolated verifier unavailable or invalid") from exc
