# DART-Guard trusted gateway — reference implementation

## Implemented

- The reference trusted component invokes the guard itself; it does not accept client-provided approval flags.
- Execution requires a signed permit bound to actor/principal, action ID and all strict JSON arguments.
- Short-lived permits use HMAC-SHA256 and a randomly provisioned secret.
- Nonces are durably claimed via SQLite `BEGIN IMMEDIATE` with a unique key. Replays are rejected across object reinitializations sharing the database.
- Failed verifier or policy checks prevent issuance.
- Claims are consumed before side effects: at-most-once **attempt**, not exactly-once execution.

## Not implemented / cannot be claimed

- No isolated operating-system service, transport authentication, mTLS, HSM/TPM, enclave or hardware-isolated verifier.
- No externally verified policy facts; a malicious caller must not control the policy context.
- No proof agents cannot reach the executor directly. OS permissions must enforce this.
- SQLite assumes a durable single-host filesystem; backup/restore or replica divergence can invalidate replay assumptions.
- No end-to-end live agent integration, operational monitoring, key rotation, supply-chain scanning, penetration test or independent security certification.

**This implementation is not a production security-certified gateway.** Protect the principal, signing secret and executor using real deployment infrastructure.
