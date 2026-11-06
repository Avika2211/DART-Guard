# Changes in hardened research prototype

- Added strict canonical JSON and duplicate-key rejection for permits.
- Added payload size and expiry/nonce validation.
- Added HMAC-SHA256 permit binding for principal, action ID and exact action arguments.
- Added SQLite atomic replay-claim handling persisting across service object reinitialization.
- Added concurrent replay, tampering, persistence, argument-binding and malformed-input regression tests.
- Consolidated security and README limitations. No production certification is claimed.
