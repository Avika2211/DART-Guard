# DART-Guard v1.2: prototype execution gateway

The gateway requires a signed, short-lived, single-use permit tied to an action identifier. It rejects missing, altered, expired, reused or action-mismatched permits.

**Critical trust assumptions:** `issue()` must only be called by trusted code; a caller able to forge a GuardResult or invoke `issue()` with arbitrary results can mint permits. The executor must not be callable directly outside the gateway. The HMAC secret must be held by a trusted gateway service and not exposed to untrusted model code. The in-memory replay set is not durable or multi-instance safe. Action arguments are not bound to the permit, only action_id. The implementation is a single-process research proof-of-concept, NOT a hardened network service.

Before any real deployment: move issuance and execution into a protected service, bind all action parameters and actor identity to the permit, use durable nonce storage, trusted policy provenance, process/host isolation, mutual authentication, crash recovery, auditable logs, external security review and actual agent integration tests.
