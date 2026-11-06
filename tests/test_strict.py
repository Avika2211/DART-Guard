import pytest
from dartguard import StrictDecisionGuard, Action, Authorization

def test_strict_requires_secondary():
    with pytest.raises(ValueError):
        StrictDecisionGuard(lambda _: .9, lambda _: Authorization(True, True), None)
def test_strict_denies_when_secondary_disagrees():
    g=StrictDecisionGuard(lambda _: .9, lambda _: Authorization(True,True), lambda _: .2)
    assert g.predict(None,None).final != Action.EXECUTE
def test_strict_permits_with_two_agreements_and_auth():
    g=StrictDecisionGuard(lambda _: .9, lambda _: Authorization(True,True), lambda _: .8)
    assert g.predict(None,None).final == Action.EXECUTE
def test_strict_rejects_same_callable():
    f=lambda _: .9
    with pytest.raises(ValueError):
        StrictDecisionGuard(f, lambda _: Authorization(True,True), f)
