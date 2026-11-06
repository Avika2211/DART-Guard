"""Retrospective trace replay; NOT an independent authorization evaluation."""
import argparse,csv,json
from pathlib import Path
ACTIONS={'DELAY','INSPECT','ASK','EXECUTE','INVALID'}

def load(path):
    with open(path,newline='') as f: rows=list(csv.DictReader(f))
    for r in rows:
        assert r['clean_action'] in ACTIONS and r['fault_action'] in ACTIONS
    return rows

def run(rows):
    result={}
    for oracle in ['allow_all','deny_all','clean_execute_proxy']:
        for mechanism in ['unguarded','authorization_only','authorization_plus_clean_reference']:
            nnew=nblocked=legitimate=nretained=0
            for r in rows:
                clean,fault=r['clean_action'],r['fault_action']
                permitted={'allow_all':True,'deny_all':False,'clean_execute_proxy':clean=='EXECUTE'}[oracle]
                proposed=fault=='EXECUTE'
                allowed=proposed and (mechanism=='unguarded' or permitted)
                if mechanism=='authorization_plus_clean_reference': allowed=allowed and clean=='EXECUTE'
                nnew+=int(clean!='EXECUTE' and allowed)
                nblocked+=int(proposed and not allowed)
                legitimate+=int(clean=='EXECUTE')
                nretained+=int(clean=='EXECUTE' and allowed)
            result[f'{oracle}/{mechanism}']={'fault_induced_new_execute_remaining':nnew,'proposed_execute_blocked':nblocked,'clean_execute_retained':nretained,'clean_execute_total':legitimate,'attempts':len(rows)}
    return result

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--traces',required=True);p.add_argument('--out',default='benchmark_results.json');a=p.parse_args()
    rows=load(a.traces);result=run(rows)
    Path(a.out).write_text(json.dumps(result,indent=2))
    print(json.dumps(result,indent=2))
