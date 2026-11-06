import pytest, secrets, time
from dartguard import DARTGuard, Authorization, Action, ExecutionGateway, Permit

def guard(p,v,allow=True,fresh=True):
    return DARTGuard(lambda _:p,lambda _:v,lambda _:Authorization(allow,fresh)).predict({}, {})
def gateway():
    calls=[]
    return ExecutionGateway(secrets.token_bytes(32),lambda action: calls.append(action)),calls
def test_authorized_execute_only():
    g,c=gateway();p=g.issue(guard(.9,.9),"send")
    g.execute(p,"send"); assert c==["send"]
def test_no_unguarded_execute():
    g,c=gateway()
    with pytest.raises(PermissionError):g.execute(None,"send")
    assert not c
def test_disagreement_denied():
    g,c=gateway()
    with pytest.raises(PermissionError):g.issue(guard(.9,.2),"send")
def test_stale_policy_denied():
    g,c=gateway()
    with pytest.raises(PermissionError):g.issue(guard(.9,.9,fresh=False),"send")
def test_replay_denied():
    g,c=gateway();p=g.issue(guard(.9,.9),"send");g.execute(p,"send")
    with pytest.raises(PermissionError):g.execute(p,"send")
def test_wrong_action_denied():
    g,c=gateway();p=g.issue(guard(.9,.9),"send")
    with pytest.raises(PermissionError):g.execute(p,"delete")
def test_tamper_denied():
    g,c=gateway();p=g.issue(guard(.9,.9),"send")
    with pytest.raises(PermissionError):g.execute(Permit(p.payload,p.mac[:-1]+"0"),"send")
def test_expiry_denied():
    g=ExecutionGateway(secrets.token_bytes(32),lambda action:None,ttl_seconds=.001)
    p=g.issue(guard(.9,.9),"send");time.sleep(.02)
    with pytest.raises(PermissionError):g.execute(p,"send")
