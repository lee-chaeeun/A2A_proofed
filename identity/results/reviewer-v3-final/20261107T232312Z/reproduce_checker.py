from pathlib import Path
from datetime import datetime,timezone
import json,shutil,subprocess,hashlib,csv

root=Path('/home/bitchae/aisafety/swarmalign/a2a-identity')
stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
out=root/'results/reviewer-v3-final'/stamp
out.mkdir(parents=True)
source=root/'internal/audit/testdata/base'
honest='1_honest_uninterrupted'
split='3_split_connection'
cases=[]
def run(name,mutate):
 d=out/name;shutil.copytree(source,d)
 mutate(d)
 p=subprocess.run([str(root/'bin/a2aid'),'audit-release','--results',str(d)],capture_output=True,text=True)
 (d/'reviewer-cli.log').write_text(p.stdout+p.stderr)
 summary=json.loads((d/'release-audit-summary.json').read_text())
 row={'case':name,'exit':p.returncode,'decisions':summary['decisions'],'verdict':summary['verdict'],'outcomes':summary['outcomes'],'unexpected_cells':summary.get('unexpected_cells',[])}
 cases.append(row);print(json.dumps(row))
def edit(d,cell,f):
 p=d/'cells'/cell/'decision.json';doc=json.loads(p.read_text());f(doc);p.write_text(json.dumps(doc,indent=2)+'\n')
run('baseline',lambda d:None)
run('empty-inventoried-rejected-cell',lambda d:edit(d,split,lambda doc:doc.update(decisions=[])))
def extra(d):
 p=d/'cells'/'UNDECLARED';p.mkdir();(p/'decision.json').write_text('{not-json\n')
run('unexpected-malformed-cell',extra)
def no_appraisal(d):
 def m(doc):
  es=doc['decisions'][0]['requester_events']
  es[:]=[e for e in es if e['kind']!='appraised']
  for i,e in enumerate(es,1):e['seq']=i
 edit(d,honest,m)
 # Remove the mirrored event too: both evidence streams lack an appraisal event.
 p=d/'cells'/honest/'controller-events.jsonl'
 es=[json.loads(l) for l in p.read_text().splitlines() if l]
 es=[e for e in es if not(e['kind']=='req_event' and e['data'].get('kind')=='appraised')]
 p.write_text(''.join(json.dumps(e)+'\n' for e in es))
run('removed-appraised-event',no_appraisal)
def ctx(d):
 def m(doc):
  for sess in doc['sessions']:
   sess['action']='DIFFERENT-ACTION';sess['audience']='DIFFERENT-AUDIENCE'
 edit(d,honest,m)
run('changed-session-action-audience',ctx)
def invpolicy(d):
 p=d/'run-inventory.json';doc=json.loads(p.read_text())
 for c in doc['cells']:
  if c.get('cell',c.get('Cell'))==honest:c['policy']='T+cb'
 p.write_text(json.dumps(doc,indent=2)+'\n')
run('inventory-policy-mismatch',invpolicy)

(out/'reviewer-findings.json').write_text(json.dumps({'binary_sha256':hashlib.sha256((root/'bin/a2aid').read_bytes()).hexdigest(),'cases':cases},indent=2)+'\n')
print('evidence:',out)
