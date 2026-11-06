import pytest
from dartguard import DARTGuard, Authorization, Action

def allow(_): return Authorization(True, True)
def test_allows_agreed_execute():
    g=DARTGuard(lambda x:.9,lambda x:.8,allow)
    assert g.predict({},{}).final==Action.EXECUTE
def test_blocks_faulted_execute():
    g=DARTGuard(lambda x:.9,lambda x:.2,allow)
    assert g.predict({},{}).final!=Action.EXECUTE
def test_blocks_stale_permission():
    g=DARTGuard(lambda x:.9,lambda x:.9,lambda _:Authorization(True,False))
    assert g.predict({},{}).final!=Action.EXECUTE
def test_nonexecute_passes_through():
    g=DARTGuard(lambda x:.2,lambda x:.9,allow)
    assert g.predict({},{}).final==Action.INSPECT
def test_invalid_primary_fails_closed():
    g=DARTGuard(lambda x:float('nan'),lambda x:.9,allow)
    assert g.predict({},{}).final!=Action.EXECUTE
def test_same_verifier_rejected():
    f=lambda x:.9
    with pytest.raises(ValueError):DARTGuard(f,f,allow)
