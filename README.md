# DART-Guard — Hardened research prototype

**DART-Guard (Decision Assurance and Runtime Trust Guard)** is a model-agnostic runtime decision-protection layer for neural System-1 decision models. It checks the primary prediction, a secondary verifier prediction, and authorization before allowing `EXECUTE`. An optional reference execution service issues short-lived permits.

**Research proof of concept only:** not production-certified, not hardware fault-isolated, and not validated on live operational authorization policies. Current evaluation assumes an uncorrupted verifier; correlated failures can defeat the mechanism.

## Quick start

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
```

```python
from dartguard import DARTGuard, Authorization

guard = DARTGuard(
    model=lambda state: state['primary_probability'],
    verifier=lambda state: state['secondary_probability'],
    authorization=lambda ctx: Authorization(ctx['permitted'], ctx['fresh']),
)
result = guard.predict(
    {'primary_probability': 0.9, 'secondary_probability': 0.2},
    {'permitted': True, 'fresh': True},
)
assert result.final.value != 'EXECUTE'
```

The example uses in-process callbacks to demonstrate the API, **not independent security services**. Only the guarded decision should reach the executor.

## Hardened trusted-service reference

`TrustedDecisionService` binds signed permits to the **principal, action ID, and exact canonical JSON arguments**, uses HMAC-SHA256, and atomically records permit nonces in SQLite for replay prevention (including after reinitialization against the same database). It rejects invalid/duplicate-key/noncanonical/nonfinite or oversized JSON and premature/expired permits.

**Critical limitation:** This class does not create a protected service boundary. Principal and policy context must come from trusted authenticated infrastructure, and the signing secret, verifier, replay database, and executor must be isolated from untrusted agents. SQLite replay claims prevent duplicate *attempts*, not exactly-once external side effects. The older `ExecutionGateway` is retained only for backward compatibility.

## Controlled experimental evidence

In the previously reported trained System-1 proxy experiment, 6,300 primary-only FP32 fault attempts produced 109 non-EXECUTE → EXECUTE transitions. Under a clean verifier, the prototype permitted **0/109**; when the verifier shared corruption, **85** authorization-permitted transitions passed. Authorization labels were synthetic; these do not represent independently labeled real-world unsafe actions.

## Repository contents

- `src/dartguard/`: protection wrapper, verifier adapter, policy, prototype gateways and trusted-service reference
- `tests/`: 67-test local regression suite, including replay, concurrency and permit tampering
- `examples/`: sample integration
- `SECURITY.md`, `SECURITY_BOUNDARIES.md`: threat assumptions, excluded security guarantees
- `PUBLISHING.md`: packaging instructions

**Do not market this as a production-certified agent security gateway.** See the security documents for the explicitly unverified assumptions. No PyPI publication is claimed.
