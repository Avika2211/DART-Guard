# DART-Guard: experimental PyPI source release

Package name in pyproject.toml: `dartguard-research` (availability unverified).

## Validate

```bash
python -m pip install -U build twine pytest
python -m pip install -e .
python -m pytest -q
python -m build
python -m twine check dist/*
```

Upload to TestPyPI and verify clean installation before publishing to PyPI. Publishing requires maintainer review of ownership, metadata, license, security and credentials.

## Limitations

This is research software, NOT a production security-certified agent gateway. The verifier is not hardware isolated. Gateway issuance is not protected from untrusted code, permits do not bind action arguments, and replay state is not persistent.

Controlled experimental evidence: 6,300 FP32 fault attempts, 109 fault-induced EXECUTE transitions, 0 permitted with clean verifier; 85 permitted under shared corruption. These results are not an operational guarantee.
