# PyPI release checklist

1. Verify ownership/availability of `dartguard-research` on PyPI.
2. Review metadata, maintainers, license and security disclosures.
3. In clean Python: `python -m pip install -U build twine pytest`.
4. Run `python -m pytest -q`, `python -m build`, `python -m twine check dist/*`.
5. Upload to TestPyPI and verify fresh installation with maintainer credentials.
6. Validate real external authorization and independently isolated verifier before any operational use.
7. Release with explicit experimental disclaimer.
8. Never set deployment readiness to true based on unit tests.
