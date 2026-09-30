"""Extract the supplied archive and create a path-adjusted working copy in a fresh folder."""
from pathlib import Path
import zipfile, shutil, difflib, json, hashlib, sys, platform
import cryptography

root=Path(__file__).resolve().parent
source=root.parent/'living_scs_v114_1'
work=root/'work'
archive=root.parent/'living_scs_v114_1.zip'
if source.exists() or work.exists():
    raise SystemExit('Use a fresh extraction folder: source/work already exists.')
with zipfile.ZipFile(archive) as z:
    for item in z.infolist():
        p=(source/item.filename).resolve()
        assert p.is_relative_to(source.resolve())
        assert (item.external_attr>>16)&0o170000 != 0o120000
    z.extractall(source)
shutil.copytree(source,work)
(root/'logs').mkdir(exist_ok=True)
diff=[];changed=[]
for p in work.rglob('*.py'):
    if p.name=='core.py': continue
    old=p.read_text();new=old.replace('/workspace/lab5',str(work))
    if old!=new:
        p.write_text(new);changed.append(str(p.relative_to(work)))
        diff.extend(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='original/'+str(p.relative_to(work)),tofile='working/'+str(p.relative_to(work))))
(root/'path_adjustments.diff').write_text(''.join(diff))
info={'python':sys.version,'platform':platform.platform(),'cryptography':cryptography.__version__,'source':str(source),'work':str(work),'path_adjusted_files':changed,'core_sha256':hashlib.sha256((work/'v114/living_scs_v114/core.py').read_bytes()).hexdigest()}
(root/'environment.json').write_text(json.dumps(info,indent=2))
print(json.dumps(info,indent=2))
