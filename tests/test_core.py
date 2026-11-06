import unittest
from dartguard import DecisionGuard, Authorization, Action, threshold_decision

class GuardTests(unittest.TestCase):
    def test_thresholds(self):
        self.assertEqual(threshold_decision(.60), Action.EXECUTE)
        self.assertEqual(threshold_decision(.30), Action.ASK)
        self.assertEqual(threshold_decision(.10), Action.INSPECT)
    def test_independent_denial(self):
        g = DecisionGuard(lambda s: .95, lambda c: Authorization(False, True))
        self.assertNotEqual(g.predict(None, None).final, Action.EXECUTE)
    def test_stale_denial(self):
        g = DecisionGuard(lambda s: .95, lambda c: Authorization(True, False))
        self.assertEqual(g.predict(None, None).final, Action.INSPECT)
    def test_verified_execution(self):
        g = DecisionGuard(lambda s: .95, lambda c: Authorization(True, True))
        self.assertEqual(g.predict(None, None).final, Action.EXECUTE)
    def test_nan_fails_closed(self):
        g = DecisionGuard(lambda s: float('nan'), lambda c: Authorization(True, True))
        self.assertEqual(g.predict(None, None).reason, 'invalid_primary_output')
    def test_secondary_disagreement(self):
        g = DecisionGuard(lambda s: .9, lambda c: Authorization(True, True),
                          secondary_model=lambda s: .2, require_agreement=True)
        self.assertEqual(g.predict(None, None).reason, 'secondary_disagreement')
    def test_secondary_nonfinite(self):
        g = DecisionGuard(lambda s: .9, lambda c: Authorization(True, True),
                          secondary_model=lambda s: float('inf'), require_agreement=True)
        self.assertEqual(g.predict(None, None).final, Action.INSPECT)
    def test_authorization_failure(self):
        def broken(_): raise ConnectionError('offline')
        g = DecisionGuard(lambda s: .9, broken)
        self.assertEqual(g.predict(None, None).reason, 'authorization_unavailable')
    def test_no_execute_fallback(self):
        with self.assertRaises(ValueError):
            DecisionGuard(lambda s: .9, lambda c: Authorization(True, True), fallback=Action.EXECUTE)
if __name__ == '__main__': unittest.main()
