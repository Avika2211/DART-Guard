# DART-Guard Linux service-boundary candidate

## Achieved in this code

- UNIX-domain socket process boundary (Linux SO_PEERCRED); authenticated peer OS UID, no caller-supplied identity field.
- Explicit UID and action-handler allowlists; no generic command execution.
- Primary and verifier functions and the authorization provider live on the server side. Client cannot supply approvals or callbacks.
- Strict bounded JSON; malformed, duplicate-key, nonfinite, missing and extra fields rejected.
- Fail-closed response on model, policy, verifier and request errors.
- Internal short-lived HMAC permits bound to principal, action ID and exact JSON arguments.
- Atomic SQLite nonce claim before execution: at-most-once **attempt**, not exactly-once effect.
- Socket file mode 0600; existing socket path is not overwritten.

## Deployment prerequisites NOT proven by this research package

1. Run the trusted service as a distinct OS identity. A different process under the SAME UID is not an actual untrusted-code isolation boundary.
2. Protect the models, trusted policy credentials, executable code, signing key, database, and actual executor from the untrusted agent.
3. The socket and its parent directory must have deployment-appropriate group/ACL permissions. The 0600 reference defaults to the service UID.
4. Bind policy facts to authenticated identity, resource, action and arguments from a trusted source at time of execution.
5. Verifier/primary model fault-domain independence is not achieved by this code. Correlated faults can bypass the guard.
6. Ensure the executor is not directly reachable except via the gateway.
7. Use protected durable replay storage and handle rollback, multi-node coordination, database corruption, key rotation and crash recovery.
8. Evaluate actual authorization attacks, socket abuse, DoS, multi-user OS separation, privilege escalation, execution bypass and realistic correlated faults.
9. Add independent security review, penetration testing, monitoring, SLOs, incident response, software supply-chain controls and update processes.
10. Client-provided observations are untrusted. Both models could approve adversarial inputs; separately validate application data.

## Demonstration

\`\`\`bash
python -m pip install -e '.[dev]'
python -m pytest -q
python examples/unix_gateway_demo.py
\`\`\`

The demo uses the same UID across processes and synthetic decisions. No production certification, hardware isolation, validated operational policy, externally isolated verifier, or deployment readiness is claimed.
