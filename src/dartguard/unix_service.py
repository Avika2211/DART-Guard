"""Linux-only bounded, process-separable gateway reference.

The model, verifier, authorization service, signing key and action handlers must
be created in the gateway process. Requests cannot supply approval decisions.
Linux SO_PEERCRED authenticates the OS UID of the connecting process. This is
NOT hardware isolation, a general-purpose sandbox or production certification.
"""
import json
import os
import socket
import socketserver
import stat
import struct
import threading
from pathlib import Path
from .core import Authorization, Action
from .layer import DARTGuard
from .trusted_service import TrustedDecisionService, canonical

MAX_REQUEST_BYTES = 65536

def _strict_request(raw):
    def unique(pairs):
        obj = {}
        for k, v in pairs:
            if k in obj:
                raise ValueError('duplicate JSON key')
            obj[k] = v
        return obj
    def bad_constant(v):
        raise ValueError('nonfinite number')
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError('request too large')
    request = json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                         parse_constant=bad_constant)
    canonical(request)
    if type(request) is not dict or set(request) != {'action', 'arguments', 'observation'}:
        raise ValueError('invalid request envelope')
    if type(request['action']) is not str or not request['action'] or len(request['action']) > 128:
        raise ValueError('invalid action')
    if type(request['arguments']) is not dict:
        raise ValueError('invalid arguments')
    return request

class ProtectedGateway:
    """Server-owned models, policy and executor with action and OS UID allowlists.

    policy(uid, action_id, args) MUST check actual fresh permissions using a
    trusted source. primary(obs) and verifier(obs) MUST be server-owned.
    executors[action] MUST be privileged operations inaccessible directly
    to the connecting client. Do not configure unrestricted shell execution.
    """
    def __init__(self, *, primary, verifier, policy, executors, allowed_uids,
                 database_path, signing_secret):
        if not callable(primary) or not callable(verifier) or not callable(policy):
            raise TypeError('trusted model and policy functions are mandatory')
        if primary is verifier:
            raise ValueError('primary and verifier cannot be identical callable')
        if type(executors) is not dict or not executors or not all(
            type(k) is str and callable(v) for k, v in executors.items()
        ):
            raise ValueError('Provide an explicit action -> handler allowlist')
        if not allowed_uids or not all(type(x) is int and x >= 0 for x in allowed_uids):
            raise ValueError('Explicit allowed_uids required')
        self._policy = policy
        self._executors = dict(executors)
        self._uids = frozenset(allowed_uids)
        self._primary = primary
        self._verifier = verifier
        self._db_path = str(database_path)
        self._secret = signing_secret

    def handle(self, peer_uid, request):
        if peer_uid not in self._uids:
            raise PermissionError('untrusted operating-system identity')
        action = request['action']
        args = request['arguments']
        if action not in self._executors:
            raise PermissionError('action not allowlisted')
        # Policy is a server-owned function; client cannot provide policy flags.
        def authorization(_):
            result = self._policy(peer_uid, action, args)
            if not isinstance(result, Authorization):
                raise TypeError('Policy must return Authorization')
            return result
        guard = DARTGuard(self._primary, self._verifier, authorization)
        trusted = TrustedDecisionService(
            guard=guard, executor=lambda name, payload: self._executors[name](payload),
            database_path=self._db_path, secret=self._secret,
        )
        principal = 'uid:' + str(peer_uid)
        permit = trusted.authorize(principal=principal, action_id=action,
                                   arguments=args, observation=request['observation'], context=None)
        # Permit stays in the gateway, not returned to the untrusted caller.
        return trusted.execute(permit=permit, principal=principal,
                               action_id=action, arguments=args)

class _RequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            if not hasattr(socket, 'SO_PEERCRED'):
                raise RuntimeError('Linux SO_PEERCRED required')
            creds = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            _pid, uid, _gid = struct.unpack('3i', creds)
            data = bytearray()
            while len(data) <= MAX_REQUEST_BYTES:
                chunk = self.request.recv(min(4096, MAX_REQUEST_BYTES + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if b'\n' in chunk:
                    break
            if not data.endswith(b'\n') or len(data) > MAX_REQUEST_BYTES:
                raise ValueError('incomplete/oversized request')
            request = _strict_request(bytes(data[:-1]))
            output = self.server.gateway.handle(uid, request)
            response = {'ok': True, 'result': output}
            canonical(response)
        except Exception as exc:
            response = {'ok': False, 'error': 'request_denied'}
            self.server.record_error(exc)
        try:
            self.request.sendall((canonical(response) + '\n').encode('utf-8'))
        except (OSError, ValueError):
            pass

class UnixGatewayServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False
    def __init__(self, socket_path, gateway, *, on_error=None):
        if os.name != 'posix' or not hasattr(socket, 'SO_PEERCRED'):
            raise RuntimeError('Linux SO_PEERCRED required')
        path = Path(socket_path)
        if not path.parent.is_dir():
            raise ValueError('Socket parent directory must exist')
        if path.exists() or path.is_symlink():
            raise FileExistsError('Refusing to replace socket path')
        self.gateway = gateway
        self.record_error = on_error or (lambda exc: None)
        super().__init__(str(path), _RequestHandler)
        os.chmod(str(path), 0o600)
    def server_close(self):
        path = self.server_address
        super().server_close()
        try:
            if stat.S_ISSOCK(os.lstat(path).st_mode):
                os.unlink(path)
        except FileNotFoundError:
            pass

def call_gateway(socket_path, action, arguments, observation, *, timeout=5):
    data = canonical({'action': action, 'arguments': arguments,
                      'observation': observation}).encode('utf-8') + b'\n'
    if len(data) > MAX_REQUEST_BYTES:
        raise ValueError('request too large')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(str(socket_path))
        sock.sendall(data)
        buf = bytearray()
        while len(buf) < MAX_REQUEST_BYTES:
            block = sock.recv(4096)
            if not block:
                break
            buf.extend(block)
            if b'\n' in block:
                break
    if not buf.endswith(b'\n'):
        raise ConnectionError('missing gateway response')
    response = _strict_response(bytes(buf[:-1]))
    return response

def _strict_response(raw):
    result = json.loads(raw.decode('utf-8'))
    if type(result) is not dict or type(result.get('ok')) is not bool:
        raise ValueError('malformed gateway response')
    return result
