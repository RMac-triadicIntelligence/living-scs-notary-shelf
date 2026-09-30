from pathlib import Path
import subprocess, sys, json, time, os

ROOT = Path(__file__).resolve().parent
WORK = ROOT / 'work'
LOGS = ROOT / 'logs'
P = sys.executable
GROUPS = {
    'core': [
        ('manifest_original', ROOT.parent/'living_scs_v114_1', ['sha256sum','-c','MANIFEST_v114.sha256']),
        ('selftest_v114', WORK/'v114', [P,'selftest_v114.py']),
        ('unittest_v114', WORK, [P,'-m','unittest','discover','-s','tests','-v']),
        ('reentrancy_v114', WORK/'redteam_v114', [P,'test_l4_1_reentrancy.py']),
        *[(f'harness_v114_{label}',WORK/'v114',[P,'lscs_harness.py',file,'--mutants']) for label,file in [('baseline','lscs_baseline.json'),('grok','grok_attacks.json'),('round2','round2_attacks.json')]],
        ('selftest_v113', WORK/'v113_ref', [P,'selftest_v113.py']),
        *[(f'harness_v113_{label}',WORK/'v113_ref',[P,'lscs_harness.py',file,'--mutants']) for label,file in [('baseline','lscs_baseline.json'),('grok','grok_attacks.json'),('round2','round2_attacks.json')]],
    ],
    'fuzz114': [('fuzz_v114', WORK, [P,'tools/fuzz_counts.py',str(WORK/'redteam_v114/fuzz.py')])],
    'fuzz113': [('fuzz_v113', WORK, [P,'tools/fuzz_counts.py',str(WORK/'redteam_v113/fuzz.py')])],
    'differential': [('differential', WORK, [P,'tools/differential.py'])],
    'proofs': [
        *[(f'{v}_{p.stem}', WORK/f'redteam_{v}',[P,p.name]) for v in ['v113','v114'] for p in sorted((WORK/f'redteam_{v}').glob('p*.py'))],
        ('backstop_compare',WORK,[P,'tools/backstop_compare.py']),
        ('compare_receipts',WORK,[P,'tools/compare_receipts.py']),
    ],
}

group = sys.argv[1]
statuses=[]
for name,cwd,cmd in GROUPS[group]:
    start=time.monotonic()
    with (LOGS/f'{name}.txt').open('w') as log:
        log.write(f'CWD: {cwd}\nCOMMAND: {json.dumps(cmd)}\n\n');log.flush()
        try:
            r=subprocess.run(cmd,cwd=cwd,stdout=log,stderr=subprocess.STDOUT,timeout=240,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
            status=r.returncode
        except subprocess.TimeoutExpired: status='TIMEOUT'
        log.write(f'\nEXIT_CODE: {status}\n')
    row={'name':name,'cwd':str(cwd),'command':cmd,'exit_code':status,'seconds':round(time.monotonic()-start,3)}
    statuses.append(row);print(json.dumps(row),flush=True)
    (ROOT/f'status_{group}.json').write_text(json.dumps(statuses,indent=2))
