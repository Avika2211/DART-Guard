"""Capability-enforcing execution gateway for research.

A valid capability proves a guard-approved decision was passed to this gateway.
It does not prove physical verifier isolation or correctness of authorization.
"""
from dataclasses import dataclass
import hmac, hashlib, secrets, time, json
from .core import Action

@dataclass(frozen=True)
class Permit:
    payload: str
    mac: str

class ExecutionGateway:
    def __init__(self, secret: bytes, executor, ttl_seconds=2.0):
        if not isinstance(secret, bytes) or len(secret)<32: raise ValueError("Use >=32 random secret bytes")
        if not callable(executor): raise TypeError("executor must be callable")
        if ttl_seconds<=0: raise ValueError("ttl_seconds must be positive")
        self.__secret=secret
        self.__executor=executor
        self.__ttl=ttl_seconds
        self.__used=set()
    def issue(self, result, action_id: str):
        if result.final!=Action.EXECUTE or not result.authorized or not result.verified:
            raise PermissionError("No verified, authorized EXECUTE")
        if not isinstance(action_id,str) or not action_id: raise ValueError("action_id required")
        payload=json.dumps({"action_id":action_id,"expires":time.time()+self.__ttl,
                            "nonce":secrets.token_hex(16)},separators=(",",":"),sort_keys=True)
        return Permit(payload,hmac.new(self.__secret,payload.encode(),hashlib.sha256).hexdigest())
    def execute(self, permit:Permit, action_id:str, *args, **kwargs):
        if not isinstance(permit,Permit): raise PermissionError("Missing permit")
        expected=hmac.new(self.__secret,permit.payload.encode(),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected,permit.mac): raise PermissionError("Invalid permit")
        try: data=json.loads(permit.payload)
        except (TypeError,ValueError): raise PermissionError("Malformed permit")
        if data.get("action_id")!=action_id: raise PermissionError("Wrong action")
        if not isinstance(data.get("expires"),(int,float)) or time.time()>data["expires"]:
            raise PermissionError("Expired permit")
        if permit.mac in self.__used: raise PermissionError("Replayed permit")
        self.__used.add(permit.mac)
        return self.__executor(action_id,*args,**kwargs)
