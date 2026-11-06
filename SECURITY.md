# Security model, disclosures and remaining work

## Trusted computing base

A real deployment requires an externally authenticated principal and policy context, protected decision/permit issuance, protected key storage, isolated verifier execution, a trusted executor reachable only through the enforcement gateway, and durable replay storage. **Those infrastructure guarantees are not delivered by this Python package.**

## Supported reference protections

- Fail-closed EXECUTE verification upon primary error, verifier disagreement, unavailable authorization, and stale permission.
- HMAC-authenticated permits bound to principal, action ID, and canonicalized JSON arguments.
- Short TTL, non-replayable nonce; SQLite atomic replay claim across processes using the same DB.
- Reject oversized, malformed, noncanonical, duplicate-key or nonfinite permit encodings.

## Unresolved risks

- `TrustedDecisionService.authorize` accepts caller-provided context/principal unless the deployment supplies authenticated transport identity.
- API-level protection cannot prevent direct executor calls if the executor is reachable by untrusted code.
- Same-host verifier can share corruption, dependencies, kernel compromise or model faults.
- SQLite DB/key tampering, compromised trusted process, supply-chain attacks and multi-host deployments are outside scope.
- Primary and verifier agreeing on the wrong action is not detected; non-EXECUTE actions are not redundantly checked.
- No formally verified code, penetration test or external security certification.
- Side effect can be lost after nonce claim on crash; not exactly-once processing.

Do not claim universal SDC protection or production certification. Report assumptions and all failed/missed cases.
