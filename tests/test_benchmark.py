import importlib.util
from pathlib import Path
spec=importlib.util.spec_from_file_location('bench',Path(__file__).resolve().parents[1]/'benchmark.py')
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
def test_synthetic_oracles():
    rows=[dict(clean_action='ASK',fault_action='EXECUTE'),dict(clean_action='EXECUTE',fault_action='EXECUTE'),dict(clean_action='ASK',fault_action='INVALID')]
    r=b.run(rows)
    assert r['allow_all/authorization_only']['fault_induced_new_execute_remaining']==1
    assert r['deny_all/authorization_only']['fault_induced_new_execute_remaining']==0
    assert r['clean_execute_proxy/authorization_only']['fault_induced_new_execute_remaining']==0
