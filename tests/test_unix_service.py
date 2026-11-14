import json
import os
import socket
import threading
import pytest
from dartguard import Authorization
from dartguard.unix_service import (ProtectedGateway, UnixGatewayServer, call_gateway,
                                     _strict_request)

def fixture_server(tmp_path, *, primary=0.9, verifier=0.9, permitted=True, uids=None):
    calls = []
    action = lambda args: calls.append(dict(args)) or {'accepted': len(calls)}
    gate = ProtectedGateway(
        primary=lambda o: primary, verifier=lambda o: verifier,
        policy=lambda uid, name, args: Authorization(permitted, True),
        executors={'perform': action},
        allowed_uids=uids if uids is not None else [os.getuid()],
        database_path=tmp_path/'claims.db', signing_secret=b'z'*32)
    srv = UnixGatewayServer(tmp_path/'gateway.sock', gate)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, thread, calls

def finish(srv, thread):
    srv.shutdown(); srv.server_close(); thread.join(timeout=4)

def test_authorized_executes(tmp_path):
    s, t, calls=fixture_server(tmp_path)
    try:
        r=call_gateway(tmp_path/'gateway.sock','perform',{'x':1},{'state':2})
        assert r=={'ok':True,'result':{'accepted':1}}
        assert calls==[{'x':1}]
    finally:finish(s,t)

@pytest.mark.parametrize('primary,verifier,permitted',[(0.1,0.9,True),(.9,.1,True),(.9,.9,False)])
def test_deny_and_no_side_effect(tmp_path,primary,verifier,permitted):
    s,t,calls=fixture_server(tmp_path,primary=primary,verifier=verifier,permitted=permitted)
    try:
        assert call_gateway(tmp_path/'gateway.sock','perform',{},None)['ok'] is False
        assert calls==[]
    finally:finish(s,t)

def test_unknown_action_denied(tmp_path):
    s,t,calls=fixture_server(tmp_path)
    try:
        assert not call_gateway(tmp_path/'gateway.sock','shell',{'command':'id'},None)['ok']
        assert calls==[]
    finally:finish(s,t)

def test_unauthorized_uid_denied(tmp_path):
    s,t,calls=fixture_server(tmp_path,uids=[os.getuid()+1])
    try:
        assert not call_gateway(tmp_path/'gateway.sock','perform',{},None)['ok']
        assert calls==[]
    finally:finish(s,t)

def test_untrusted_approval_flags_denied(tmp_path):
    s,t,calls=fixture_server(tmp_path)
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as c:
            c.connect(str(tmp_path/'gateway.sock'))
            c.sendall(b'{"action":"perform","arguments":{},"observation":null,"authorized":true}\n')
            response=c.recv(1024)
            assert not json.loads(response)['ok']
        assert calls==[]
    finally:finish(s,t)

def test_duplicate_keys_rejected():
    with pytest.raises(ValueError, match='duplicate'):
        _strict_request(b'{"action":"perform","action":"other","arguments":{},"observation":null}')

def test_socket_cannot_replace_file(tmp_path):
    p=tmp_path/'gateway.sock';p.write_text('existing')
    g=ProtectedGateway(primary=lambda o:.9,verifier=lambda o:.9,
                       policy=lambda *a:Authorization(True,True),
                       executors={'perform':lambda a:None},allowed_uids=[os.getuid()],
                       database_path=tmp_path/'claims.db',signing_secret=b'z'*32)
    with pytest.raises(FileExistsError): UnixGatewayServer(p,g)

def test_peer_cannot_spoof_uid_using_payload(tmp_path):
    s,t,calls=fixture_server(tmp_path,uids=[os.getuid()+1])
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as c:
            c.connect(str(tmp_path/'gateway.sock'))
            c.sendall(json.dumps({'action':'perform','arguments':{},'observation':None,
                                  'uid':os.getuid()+1}).encode()+b'\n')
            assert json.loads(c.recv(2048))['ok'] is False
        assert calls==[]
    finally:finish(s,t)

def test_socket_permissions(tmp_path):
    import stat
    s,t,calls=fixture_server(tmp_path)
    try:
        assert stat.S_IMODE(os.stat(tmp_path/'gateway.sock').st_mode)==0o600
    finally:finish(s,t)

def test_rejected_nonfinite_inputs(tmp_path):
    s,t,calls=fixture_server(tmp_path)
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as c:
            c.connect(str(tmp_path/'gateway.sock'))
            c.sendall(b'{"action":"perform","arguments":{"x":NaN},"observation":null}\n')
            assert json.loads(c.recv(1024))['ok'] is False
        assert not calls
    finally:finish(s,t)
