import unittest
from dartguard.policy import IndependentPolicy,PolicyRecord
from dartguard.adaptive import schedule_verification
class TestPolicy(unittest.TestCase):
    def test_valid(self): self.assertTrue(IndependentPolicy(lambda _:PolicyRecord(True,'v1',True,'service')).authorize({}))
    def test_stale(self): self.assertFalse(IndependentPolicy(lambda _:PolicyRecord(True,'v1',False,'service')).authorize({}))
    def test_missing_provenance(self): self.assertFalse(IndependentPolicy(lambda _:PolicyRecord(True,'v1',True,'')).authorize({}))
    def test_provider_failure(self): self.assertFalse(IndependentPolicy(lambda _:1/0).authorize({}))
    def test_boundary(self): self.assertTrue(schedule_verification(.59).verify)
    def test_far(self): self.assertFalse(schedule_verification(.99).verify)
    def test_nan(self): self.assertTrue(schedule_verification(float('nan')).verify)
if __name__=='__main__':unittest.main()
