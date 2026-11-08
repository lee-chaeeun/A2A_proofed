from pathlib import Path
from datetime import datetime, timezone
import json,subprocess,shutil,hashlib,os

root=Path('/home/bitchae/aisafety/swarmalign/a2a-identity-zkp')
run=root/'results/zk/20261108-002724'
out=root/'results/reviewer-zk'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
out.mkdir(parents=True)
rows=[json.loads(l) for l in (run/'decisions.jsonl').read_text().splitlines() if l]
env=os.environ.copy();env['RISC0_DEV_MODE']='0'
verified=[]
for h,img in sorted({(r['receipt_sha256'],r['expected_image_id_hex']) for r in rows}):
 import base64
 raw=(run/'receipts'/f'{h}.bin').read_bytes()
 p=subprocess.run([str(root/'zk/target/release/zkverify')],input=json.dumps({'receipt_b64':base64.b64encode(raw).decode(),'expected_image_id_hex':img}),env=env,capture_output=True,text=True)
 resp=json.loads(p.stdout)
 group=[r for r in rows if r['receipt_sha256']==h and r['expected_image_id_hex']==img]
 result={'receipt':h,'image':img,'hash_matches_filename':hashlib.sha256(raw).hexdigest()==h,'exit':p.returncode,'verified':resp.get('verified'),'kind':resp.get('receipt_kind'),'rows':len(group),'matches_recorded_validity':all(r['proof_valid']==resp.get('verified') for r in group),'matches_recorded_journal':all(not r['proof_valid'] or r['verified_journal_hex']==resp.get('journal_hex') for r in group)}
 verified.append(result)
print('Receipt verification:',len(verified),'unique receipt/image pairs;',sum(v['verified'] for v in verified),'valid;',all(v['hash_matches_filename'] and v['matches_recorded_validity'] and v['matches_recorded_journal'] for v in verified),'all match retained rows')
(out/'receipt-reverification.json').write_text(json.dumps(verified,indent=2)+'\n')

def cop(src,dst):
 shutil.copytree(src,dst,ignore=shutil.ignore_patterns('oracle-controls','process-logs','boot'))
checks=[]
def check(name,fn):
 d=out/name;cop(run,d);fn(d)
 p=subprocess.run([str(root/'bin/a2aid'),'zk-oracle','--results',str(d)],cwd=root,capture_output=True,text=True)
 (d/'reviewer-cli.log').write_text(p.stdout+p.stderr)
 summ=json.loads((d/'oracle-summary.json').read_text())
 item={'case':name,'exit':p.returncode,'rows':summ['rows'],'scored':summ['scored'],'incomplete':summ['incomplete'],'disagreements':summ['observed_vs_policy_semantics_disagreements']};checks.append(item);print(json.dumps(item))
check('baseline',lambda d:None)
def omit(d):
 p=d/'decisions.jsonl';rs=[json.loads(l) for l in p.read_text().splitlines() if l];p.write_text(''.join(json.dumps(r)+'\n' for r in rs if r['fixture']!='Z4'))
check('removed-stale-witness-fixture',omit)
def duplicate(d):
 p=d/'decisions.jsonl';s=p.read_text();p.write_text(s+s.splitlines()[0]+'\n')
check('duplicated-policy-cell',duplicate)
def corrupt(d):
 for p in (d/'receipts').glob('*.bin'):p.write_bytes(b'not-a-receipt')
check('all-receipt-bytes-corrupted',corrupt)
def noapproval(d):
 p=d/'events.jsonl';es=[json.loads(l) for l in p.read_text().splitlines() if l]
 p.write_text(''.join(json.dumps(e)+'\n' for e in es if e['kind']!='approval_inserted'))
check('all-approval-events-removed',noapproval)
(out/'oracle-checks.json').write_text(json.dumps(checks,indent=2)+'\n')

prov=json.loads((run/'provenance.json').read_text());diff=[]
bins={'bin:prove':root/'zk/target/release/zkprove','bin:verify':root/'zk/target/release/zkverify','bin:fake':root/'zk/target/release/zkfake'}
for f,h in prov['sha256'].items():
 p=bins[f] if f in bins else root/f
 if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest()!=h:diff.append(f)
summary={'provenance_mismatches':diff,'matrix_rows':len(rows),'matches':sum(r['match'] for r in rows),'Z6_Z7_identical_receipts':{r['receipt_sha256'] for r in rows if r['fixture']=='Z6'}=={r['receipt_sha256'] for r in rows if r['fixture']=='Z7'},'prediction_frozen_at':json.loads((run/'predictions-frozen.json').read_text())['frozen_at'],'run_started':prov['started_utc']}
(out/'provenance-check.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary));print('Evidence:',out)
