# Gateway security notes

The original `ExecutionGateway` is a demonstration and remains for backward compatibility.

For research security tests, prefer `TrustedDecisionService`:

- Validates actual `DARTGuard` results internally.
- Signs short-lived permits with HMAC-SHA256.
- Binds principal, action ID and exact JSON action arguments.
- Persists single-use nonce claims with atomic SQLite transactions.
- Rejects tampered/replayed/expired/malformed permits.

**Remaining deployment gaps:** this is not an isolated network service. If the agent can invoke the trusted class with forged context, reach its executor, or access signing keys/database, the reference protections are not sufficient. Same-host verifier corruption is possible. No hardware isolation or external security certification has been established.
