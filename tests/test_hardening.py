import pytest
from dartguard.core import Action, Authorization, DecisionGuard
def allow(_): return Authorization(True, True)
def test_nan_fails_closed():
    r=DecisionGuard(lambda _: float('nan'),allow).predict(None,None)
    assert r.final != Action.EXECUTE
def test_primary_exception_fails_closed():
    def fail(_): raise OSError("inference offline")
    assert DecisionGuard(fail,allow).predict(None,None).final != Action.EXECUTE
def test_authorization_exception_fails_closed():
    def fail(_): raise ConnectionError("policy offline")
    assert DecisionGuard(lambda _: .9,fail).predict(None,None).final != Action.EXECUTE
def test_secondary_exception_fails_closed():
    def fail(_): raise OSError("replica offline")
    r=DecisionGuard(lambda _: .9,allow,fail,require_agreement=True).predict(None,None)
    assert r.final != Action.EXECUTE
def test_secondary_disagreement():
    r=DecisionGuard(lambda _: .9,allow,lambda _: .2,require_agreement=True).predict(None,None)
    assert r.final != Action.EXECUTE
def test_no_agreement_without_secondary():
    with pytest.raises(ValueError): DecisionGuard(lambda _: .9,allow,require_agreement=True)
def test_reject_executing_fallback():
    with pytest.raises(ValueError): DecisionGuard(lambda _: .9,allow,fallback=Action.EXECUTE)
def test_stale_denied():
    r=DecisionGuard(lambda _: .9,lambda _: Authorization(True,False)).predict(None,None)
    assert r.final != Action.EXECUTE
def test_invalid_custom_action():
    r=DecisionGuard(lambda _: .9,allow,decision=lambda _: "EXECUTE").predict(None,None)
    assert r.final != Action.EXECUTE
