"""Argument-bound, single-use execution permits (research reference).

Security depends on separating this class and its secret/executor from untrusted
agent code. The Python class does NOT create a trusted process boundary.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import secrets
import sqlite3
import time
from typing import Callable
from .core import Action

MAX_PAYLOAD_BYTES = 65536

def canonical(value):
    """Strict deterministic JSON; reject NaN, nonstring keys and unsupported types."""
    def valid(v):
        if v is None or type(v) in (str, bool, int):
            return
        if type(v) is float:
            if not math.isfinite(v):
                raise ValueError('Non-finite action argument')
            return
        if type(v) is list:
            for x in v: valid(x)
            return
        if type(v) is dict:
            if not all(type(k) is str for k in v):
                raise ValueError('Object keys must be strings')
            for x in v.values(): valid(x)
            return
        raise ValueError('Action arguments must be strict JSON values')
    valid(value)
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True, allow_nan=False)
    if len(encoded.encode('utf-8')) > MAX_PAYLOAD_BYTES:
        raise ValueError('Payload too large')
    return encoded


def strict_parse(raw):
    if type(raw) is not str or len(raw.encode('utf-8')) > MAX_PAYLOAD_BYTES:
        raise PermissionError('Malformed or oversized permit')
    def pairs(items):
        d = {}
        for k, v in items:
            if k in d:
                raise ValueError('Duplicate JSON key')
            d[k] = v
        return d
    def fail_const(_): raise ValueError('Nonfinite JSON constant')
    try:
        parsed = json.loads(raw, object_pairs_hook=pairs, parse_constant=fail_const)
        canonical(parsed)
        if canonical(parsed) != raw:
            raise ValueError('Noncanonical JSON encoding')
        return parsed
    except (TypeError, ValueError, OverflowError) as e:
        raise PermissionError('Malformed permit') from e

@dataclass(frozen=True)
class BoundPermit:
    payload: str
    signature: str

class TrustedDecisionService:
    """Trusted-core reference, NOT a remotely authenticated or isolated service.

    Call authorization from a protected service identity and keep the executor,
    secret, authorization provider and DB inaccessible to untrusted agents.
    """
    def __init__(self, guard, executor: Callable, database_path, secret: bytes,
                 ttl_seconds=3.0, clock=time.time):
        if not callable(executor): raise TypeError('executor must be callable')
        if type(secret) is not bytes or len(secret) < 32:
            raise ValueError('At least 32 secret bytes required')
        if (not isinstance(ttl_seconds, (int, float)) or
            not math.isfinite(ttl_seconds) or ttl_seconds <= 0 or ttl_seconds > 60):
            raise ValueError('TTL out of range')
        self._guard = guard
        self._executor = executor
        self._secret = secret
        self._db_path = str(database_path)
        self._ttl = float(ttl_seconds)
        self._clock = clock
        with self._db() as c:
            c.execute('CREATE TABLE IF NOT EXISTS used_permits '
                      '(nonce TEXT PRIMARY KEY, used_at REAL NOT NULL)')

    @contextmanager
    def _db(self):
        c = sqlite3.connect(self._db_path, timeout=10, isolation_level=None)
        try:
            c.execute('PRAGMA busy_timeout=10000')
            yield c
        finally:
            c.close()

    def _sign(self, payload):
        return hmac.new(self._secret, payload.encode('utf-8'), hashlib.sha256).hexdigest()

    def authorize(self, *, principal: str, action_id: str, arguments: dict,
                  observation, context):
        # NOTE: authenticated principal/context MUST be provided by trusted transport.
        if not isinstance(principal, str) or not principal or not isinstance(action_id, str) or not action_id:
            raise ValueError('principal and action_id required')
        if type(arguments) is not dict:
            raise ValueError('arguments must be a JSON object')
        canonical(arguments)
        result = self._guard.predict(observation, context)
        if result.final != Action.EXECUTE or result.authorized is not True or result.verified is not True:
            raise PermissionError('Guard did not approve EXECUTE')
        now = float(self._clock())
        if not math.isfinite(now): raise ValueError('Nonfinite clock')
        payload = canonical({'v': 1, 'principal': principal, 'action_id': action_id,
            'arguments': arguments, 'issued_at': now, 'expires_at': now + self._ttl,
            'nonce': secrets.token_hex(24)})
        return BoundPermit(payload, self._sign(payload))

    def execute(self, *, permit: BoundPermit, principal: str, action_id: str,
                arguments: dict):
        if not isinstance(permit, BoundPermit) or type(permit.signature) is not str:
            raise PermissionError('Missing or malformed permit')
        item = strict_parse(permit.payload)
        expected = self._sign(permit.payload)
        if not hmac.compare_digest(expected, permit.signature):
            raise PermissionError('Invalid permit signature')
        if not isinstance(item, dict) or type(item.get('v')) is not int or item['v'] != 1:
            raise PermissionError('Unsupported permit version')
        if item.get('principal') != principal or item.get('action_id') != action_id:
            raise PermissionError('Permit principal/action mismatch')
        if type(arguments) is not dict or canonical(item.get('arguments')) != canonical(arguments):
            raise PermissionError('Permit arguments mismatch')
        issued = item.get('issued_at')
        expires = item.get('expires_at')
        nonce = item.get('nonce')
        if (type(issued) not in (float, int) or type(expires) not in (float, int) or
            type(nonce) is not str or len(nonce) != 48 or
            any(ch not in '0123456789abcdef' for ch in nonce)):
            raise PermissionError('Malformed permit claims')
        if not all(math.isfinite(x) for x in (issued, expires)):
            raise PermissionError('Nonfinite permit time')
        now = float(self._clock())
        if not math.isfinite(now) or now < issued or now >= expires or expires - issued > self._ttl + 1e-5:
            raise PermissionError('Expired or premature permit')
        # Atomic replay claim before side effect: at-most-once ATTEMPT, not exactly-once execution.
        with self._db() as c:
            try:
                c.execute('BEGIN IMMEDIATE')
                c.execute('INSERT INTO used_permits(nonce,used_at) VALUES (?,?)', (nonce, now))
                c.execute('COMMIT')
            except sqlite3.IntegrityError as e:
                c.execute('ROLLBACK')
                raise PermissionError('Permit already used') from e
            except Exception:
                c.execute('ROLLBACK')
                raise
        return self._executor(action_id, arguments)
