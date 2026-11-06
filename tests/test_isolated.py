import sys
from dartguard import SubprocessVerifier
from dartguard.core import DecisionGuard, Authorization, Action

def test_separate_process_agreement():
    code = "import sys,json; x=json.load(sys.stdin); print(json.dumps({'probability': 0.91}))"
    v = SubprocessVerifier([sys.executable, '-c', code])
    guard = DecisionGuard(lambda s: 0.91, lambda c: Authorization(True, True), v, True)
    assert guard.predict({}, {}).final == Action.EXECUTE
def test_secondary_failure_is_fail_closed():
    v = SubprocessVerifier([sys.executable, '-c', 'raise SystemExit(2)'])
    guard = DecisionGuard(lambda s: 0.91, lambda c: Authorization(True, True), v, True)
    assert guard.predict({}, {}).final != Action.EXECUTE
def test_secondary_timeout_is_fail_closed():
    v = SubprocessVerifier([sys.executable, '-c', 'import time;time.sleep(2)'], 0.05)
    guard = DecisionGuard(lambda s: 0.91, lambda c: Authorization(True, True), v, True)
    assert guard.predict({}, {}).final != Action.EXECUTE
def test_secondary_disagreement_is_fail_closed():
    code = "import sys,json; json.load(sys.stdin); print(json.dumps({'probability': 0.21}))"
    v = SubprocessVerifier([sys.executable, '-c', code])
    guard = DecisionGuard(lambda s: 0.91, lambda c: Authorization(True, True), v, True)
    assert guard.predict({}, {}).final != Action.EXECUTE
