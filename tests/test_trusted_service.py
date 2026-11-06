import os, secrets, pytest
from dartguard import DARTGuard, Authorization, TrustedDecisionService, BoundPermit

def make(tmp_path,primary=.9,secondary=.9,allow=True,fresh=True,secret=None,clock=None):
    guard=DARTGuard(lambda _:primary,lambda _:secondary,
                    lambda ctx:Authorization(allow,fresh))
    calls=[]
    service=TrustedDecisionService(guard,lambda action,args:calls.append((action,args)),
             tmp_path/'replay.sqlite',secret or (b'z'*32),ttl_seconds=3.0,**({'clock':clock} if clock else {}))
    return service,calls
def issue(s,kwargs=None):
    return s.authorize(principal='agent1',action_id='transfer',arguments=kwargs or {'amount':5},observation={},context={})
def execute(s,p,kwargs=None):
    return s.execute(permit=p,principal='agent1',action_id='transfer',arguments=kwargs or {'amount':5})
def test_accepted_and_replay_persist(tmp_path):
    s,calls=make(tmp_path);p=issue(s);execute(s,p)
    assert len(calls)==1
    s2,calls2=make(tmp_path)
    with pytest.raises(PermissionError,match='already used'):execute(s2,p)
    assert calls2==[]
def test_wrong_arguments(tmp_path):
    s,calls=make(tmp_path);p=issue(s)
    with pytest.raises(PermissionError,match='arguments'):execute(s,p,{'amount':500})
    assert not calls
def test_wrong_principal(tmp_path):
    s,calls=make(tmp_path);p=issue(s)
    with pytest.raises(PermissionError,match='principal'):s.execute(permit=p,principal='agent2',action_id='transfer',arguments={'amount':5})
def test_tamper(tmp_path):
    s,calls=make(tmp_path);p=issue(s)
    with pytest.raises(PermissionError):execute(s,BoundPermit(p.payload,'f'*64))
@pytest.mark.parametrize('primary,secondary,allow,fresh',[(.2,.9,True,True),(.9,.2,True,True),(.9,.9,False,True),(.9,.9,True,False)])
def test_denied(tmp_path,primary,secondary,allow,fresh):
    s,calls=make(tmp_path,primary,secondary,allow,fresh)
    with pytest.raises(PermissionError):issue(s)
def test_expiry(tmp_path):
    now=[100.0]
    s,calls=make(tmp_path,clock=lambda:now[0]);p=issue(s);now[0]+=4
    with pytest.raises(PermissionError,match='Expired'):execute(s,p)
def test_bad_args(tmp_path):
    s,calls=make(tmp_path)
    with pytest.raises(ValueError):issue(s,{'nan':float('nan')})
def test_no_permit(tmp_path):
    s,calls=make(tmp_path)
    with pytest.raises(PermissionError):execute(s,None)
