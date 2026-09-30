from pathlib import Path
import hashlib, json, subprocess, sys, importlib.util, os

ROOT=Path(__file__).resolve().parent
WORK=ROOT/'work'
ORIGINAL=ROOT.parent/'living_scs_v114_1'
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()

target=ROOT/'patch_reproduction'/'core.py'
target.parent.mkdir(exist_ok=True)
target.write_bytes((ORIGINAL/'v113_ref/living_scs_v113/core.py').read_bytes())
source=(ORIGINAL/'make_v114_patch.py').read_text()
old='P = Path("/workspace/lab5/v114/living_scs_v114/core.py")'
assert source.count(old)==1
source=source.replace(old,'P = Path('+repr(str(target))+')')
script=target.parent/'make_v114_patch.py'
script.write_text(source)
subprocess.run([sys.executable,str(script)],check=True)
assert target.read_bytes()==(ORIGINAL/'v114/living_scs_v114/core.py').read_bytes()
print('Patch reproduction: byte-identical PASS',sha(target))

sys.path.insert(0,str(WORK/'v114'))
import lscs_harness as H
mutants=list(H.package_mutants())
assert len(mutants)==12
print('Mutants: 12/12 substitutions applied and modules imported')

spec=importlib.util.spec_from_file_location('common',str(WORK/'redteam_v113/common.py'))
common=importlib.util.module_from_spec(spec);sys.modules['common']=common;spec.loader.exec_module(common)
spec=importlib.util.spec_from_file_location('old_reentrancy_tests',str(WORK/'redteam_v114/test_l4_1_reentrancy.py'))
tests=importlib.util.module_from_spec(spec);spec.loader.exec_module(tests)
failures=[]
for name,fn in vars(tests).items():
    if name.startswith('test_') and callable(fn):
        try: fn(); print('v113 control PASS',name)
        except Exception as e: failures.append(name); print('v113 control FAIL',name,type(e).__name__,str(e))
assert set(failures)=={'test_reentrant_commit_refused','test_reentrant_refusal_propagates_atomically'}
print('Old-version sensitivity control: expected 2/4 failures reproduced')

summary=[]
for version in ['v113_ref','v114']:
    for path in sorted((WORK/version/'receipts').glob('*.json')):
        r=json.loads(path.read_text()); rows=[row for session in r['sessions'] for row in session['rows']]
        orig=json.loads((ORIGINAL/version/'receipts'/path.name).read_text())
        oldrows={(s['name'],row['id']):row for s in orig['sessions'] for row in s['rows']}
        changes=[]
        for s in r['sessions']:
            for row in s['rows']:
                o=oldrows[(s['name'],row['id'])]
                if o['outcome']!=row['outcome']:
                    changes.append({'id':row['id'],'stored':o['outcome'],'rerun':row['outcome'],'reason':row['reason']})
        row={'version':version,'receipt':path.name,'sessions':len(r['sessions']),'attempts':len(rows),'accepts':sum(s['accepted'] for s in r['sessions']),'status':r['target_status'],'breaches':len(r['breaches']),'faults':r['faults'],'harness_errors':r['harness_errors'],'expectation_mismatches':sum(not x['matches_expect'] for x in rows),'killed':[k for k,v in r['mutant_kill'].items() if v],'changes_from_shipped_receipt':changes}
        summary.append(row);print(json.dumps(row))
(ROOT/'receipt_summary.json').write_text(json.dumps(summary,indent=2))

manifest=(ORIGINAL/'MANIFEST_v114.sha256').read_text().splitlines()
listed=set()
for line in manifest:
    digest,name=line.split(maxsplit=1);listed.add(name)
    assert sha(ORIGINAL/name)==digest, name
actual={str(p.relative_to(ORIGINAL)) for p in ORIGINAL.rglob('*') if p.is_file()}
assert actual-listed=={'MANIFEST_v114.sha256'}
assert not listed-actual
for core in ['v113_ref/living_scs_v113/core.py','v114/living_scs_v114/core.py']:
    assert sha(ORIGINAL/core)==sha(WORK/core)
print('Original manifest still PASS; 104/104 entries; no missing or unlisted payloads; both engine cores unchanged')
