# Bounded research scope

The model-level DART-Guard prototype is frozen for research evaluation. Prior experiments included 6,300 primary-only FP32 fault attempts with 109 observed non-EXECUTE → EXECUTE transitions, all contained under an uncorrupted verifier; 85 transitions passed under deliberately shared corruption.

**Recent code hardening:** 67 local regression tests cover decision wrapper behavior, permit binding, invalid inputs, concurrent replay prevention and durable SQLite claims. This does not certify a production deployment or independently isolate verifier hardware.

The older `ExecutionGateway` persists for compatibility and uses in-memory replay state; the newer `TrustedDecisionService` reference binds action arguments and records replay claims to SQLite. Neither establishes a protected service boundary by itself.

Further real-world qualification requires authenticated policy facts and agent identity, isolated verifier/executor infrastructure, bypass protection, operational security testing and independent review. These are outside this research prototype.
