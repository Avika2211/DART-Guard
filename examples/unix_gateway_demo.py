"""Demo only. NOT a real authorization policy, trained model or safe deployment.

Run: PYTHONPATH=src python examples/unix_gateway_demo.py
The demo starts the gateway in a DIFFERENT PROCESS, but with the SAME OS UID.
Real deployments must use distinct UIDs and protect the executor, model, key,
policy credentials, runtime directory and database from the agent identity.
"""
import multiprocessing as mp
import os
import tempfile
from pathlib import Path
from dartguard import Authorization
from dartguard.unix_service import ProtectedGateway, UnixGatewayServer, call_gateway

def server(path, db, ready):
    gate = ProtectedGateway(
        primary=lambda observation: observation['primary'],
        verifier=lambda observation: observation['verifier'],
        policy=lambda peer_uid, action, args: Authorization(
            permitted=(action == 'echo' and args.get('allowed') is True), fresh=True),
        executors={'echo': lambda args: {'echoed': args['message']}},
        allowed_uids=[os.getuid()], database_path=db, signing_secret=os.urandom(32))
    gateway = UnixGatewayServer(path, gate)
    ready.set()
    try:
        gateway.serve_forever()
    finally:
        gateway.server_close()

def main():
    with tempfile.TemporaryDirectory() as d:
        path = str(Path(d)/'gateway.sock')
        ready=mp.Event()
        child=mp.Process(target=server,args=(path,Path(d)/'used.sqlite3',ready))
        child.start()
        try:
            if not ready.wait(5): raise RuntimeError('gateway startup failed')
            print(call_gateway(path,'echo',{'allowed':True,'message':'hello'},
                               {'primary':.9,'verifier':.9}))
            print(call_gateway(path,'echo',{'allowed':False,'message':'denied'},
                               {'primary':.9,'verifier':.9}))
            print(call_gateway(path,'echo',{'allowed':True,'message':'verifier rejects'},
                               {'primary':.9,'verifier':.1}))
        finally:
            child.terminate();child.join(timeout=5)
if __name__=='__main__':main()
