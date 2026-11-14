# DART-Guard — Linux service research candidate

**Decision Assurance and Runtime Trust Guard** investigates runtime containment of silent numerical faults that change neural System-1 decision outputs. This repository contains a model-agnostic Python decision-protection wrapper and a Linux Unix-domain-socket gateway **reference implementation**.

**Status:** Research prototype, version **1.1.0rc1**. NOT security-certified or qualified for production use.

## Install, test and demo

\`\`\`bash
python -m pip install -e '.[dev]'
python -m pytest -q
python examples/unix_gateway_demo.py
\`\`\`

77+ tests were run locally on the source release candidate (79 passed in the latest local run). That demonstrates tested software behavior, not hardware fault isolation or external security validation.

## Architecture

1. A server-owned primary neural decision function proposes an action.
2. A separately defined verifier cross-checks the proposal.
3. Trusted policy verifies authenticated OS peer UID, the allowlisted action, and server-owned authorization/freshness conditions.
4. Successful EXECUTE requests are covered by short-lived HMAC-SHA256 permits binding peer principal, action ID and canonicalized action arguments.
5. SQLite atomically claims each permit nonce before invoking the allowlisted executor. Failed checks return a fail-closed denial.

The client cannot submit approval flags, arbitrary Python callbacks or a signing key. Linux SO_PEERCRED identifies the local peer process UID.

## Practical integration

The source package exports \`DARTGuard\`, \`Authorization\`, \`TrustedDecisionService\`, and the Linux-only module \`dartguard.unix_service\` containing \`ProtectedGateway\`, \`UnixGatewayServer\`, and \`call_gateway\`. The legacy \`ExecutionGateway\` remains for compatibility but is not the security reference.

See \`DEPLOYMENT_BOUNDARIES.md\` and \`SECURITY.md\` for threat assumptions and non-claims. The sample models and policies are synthetic demonstrators, **not a production authentication or authorization source**.

## Experimental scope

Separate controlled checkpoint experiments recorded 6,300 primary-only FP32 fault attempts, with 109 new EXECUTE transitions rejected under a clean verifier; 85 new EXECUTE transitions passed under shared corruption. These numbers represent model-level experiments with synthetic authorization labels, not a production incident rate.

Research evaluation also used externally sourced tau3-bench tasks and Gymnasium Taxi/MiniGrid environments. The benchmark reports do not establish independent verifier hardware isolation or superiority over all simpler methods. Full DART-Guard matched verifier-only in the tau3 and Taxi experiments.

## Responsible claims

- **Demonstrated:** Research-level decision gate, Linux process-boundary demo, argument-bound HMAC permits, SQLite replay claims, local automated tests.
- **Not demonstrated:** Fault-domain independent verifier, production non-bypassability, external security certification, malicious-compromise resistance under same UID, operational authorization correctness.

For reproducibility and related literature, see the accompanying manuscript draft and \`paper/RELATED_WORK.md\`.
