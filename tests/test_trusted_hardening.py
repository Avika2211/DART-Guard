import hashlib, hmac, json, secrets
from concurrent.futures import ThreadPoolExecutor
import pytest
from dartguard import DARTGuard, Authorization, TrustedDecisionService, BoundPermit
from dartguard.trusted_service import canonical, strict_parse

KEY = b'x' * 32

def make(db, calls):
    g = DARTGuard(lambda _: .9, lambda _: .9,
                  lambda ctx: Authorization(True, True))
    return TrustedDecisionService(g, lambda action, args: calls.append((action, args)), db, KEY)

def issue(s, args=None):
    return s.authorize(principal='agent', action_id='transfer',
                       arguments={'amount': 5} if args is None else args,
                       observation={}, context={})

def execute(s, p, args=None):
    return s.execute(permit=p, principal='agent', action_id='transfer',
                     arguments={'amount': 5} if args is None else args)

def test_concurrent_replay_at_most_one(tmp_path):
    calls = []
    s = make(tmp_path/'r.sqlite', calls)
    p = issue(s)
    def attempt(_):
        try: execute(s, p); return True
        except PermissionError: return False
    with ThreadPoolExecutor(max_workers=12) as pool:
        result=list(pool.map(attempt, range(40)))
    assert sum(result) == 1 and len(calls) == 1

def test_replay_after_reinitialization(tmp_path):
    calls=[]; db=tmp_path/'r.sqlite'; p=issue(make(db,calls))
    execute(make(db,calls),p)
    with pytest.raises(PermissionError, match='already used'):
        execute(make(db,calls),p)
    assert len(calls)==1

def test_signature_forgery_rejected(tmp_path):
    calls=[];s=make(tmp_path/'r.sqlite',calls);p=issue(s)
    obj=json.loads(p.payload);obj['arguments']['amount']=500
    forged=BoundPermit(canonical(obj),p.signature)
    with pytest.raises(PermissionError):execute(s,forged,{'amount':500})
    assert calls==[]

def test_argument_binding_blocks_extra_parameter(tmp_path):
    s=make(tmp_path/'r.sqlite',[]);p=issue(s)
    with pytest.raises(PermissionError,match='arguments'):
        execute(s,p,{'amount':5,'destination':'attacker'})

def test_json_strictness():
    for v in [float('nan'), float('inf'), {'x':{1:'bad'}}, {'x':(1,2)}, object()]:
        with pytest.raises((ValueError,TypeError)): canonical(v)
    with pytest.raises(PermissionError): strict_parse('{"a":1,"a":2}')
    with pytest.raises(PermissionError): strict_parse('{' + 'a'*70000 + '}')

def test_noncanonical_payload_rejected(tmp_path):
    s=make(tmp_path/'r.sqlite',[])
    p=issue(s)
    obj=json.loads(p.payload)
    noncanonical=json.dumps(obj,indent=2)
    signed=BoundPermit(noncanonical,hmac.new(KEY,noncanonical.encode(),hashlib.sha256).hexdigest())
    with pytest.raises(PermissionError,match='Malformed'):
        execute(s,signed)

def test_nonce_uniqueness(tmp_path):
    s=make(tmp_path/'r.sqlite',[])
    assert len({json.loads(issue(s).payload)['nonce'] for _ in range(300)})==300

def test_invalid_ttl(tmp_path):
    g=DARTGuard(lambda _: .9,lambda _: .9,lambda _: Authorization(True,True))
    for ttl in [0, -1, float('nan'),float('inf'),61]:
        with pytest.raises(ValueError):
            TrustedDecisionService(g,lambda a,v:None,tmp_path/'r.sqlite',KEY,ttl_seconds=ttl)
