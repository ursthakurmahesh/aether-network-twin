import copy,unittest
from findings import prepare,checked,KEYS
from core import Problem
class FindingsTests(unittest.TestCase):
 def setUp(self):
  self.p={'summary':{k:0 for k in KEYS},'question':'explain','consent':True};self.p['summary'].update(packets=22,tcp=16,udp=6,dnsResponses=3,dnsErrors=3,resets=2)
  self.r={'answer':'Some responses report errors.','hypotheses':[{'title':'Name lookup failed','evidenceIds':['E5'],'explanation':'The DNS error responses may indicate missing names.','cannotProve':'The root cause is unknown.','nextCheck':'Check the authorized device logs.'}]}
 def test_valid(self): self.assertEqual(len(prepare(self.p)['evidence']),10)
 def test_output(self): self.assertEqual(checked(self.r,prepare(self.p)),self.r)
 def test_extra_sensitive_field(self):
  for k in ['filename','domain','src','payload','history']:
   p=copy.deepcopy(self.p);p['summary'][k]='private'
   with self.assertRaises(Problem):prepare(p)
 def test_bad_counts(self):
  for x in [True,-1,100001,1.5,'22',None]:
   p=copy.deepcopy(self.p);p['summary']['packets']=x
   with self.assertRaises(Problem):prepare(p)
 def test_consent(self):
  self.p['consent']=False
  with self.assertRaises(Problem):prepare(self.p)
 def test_free_text_rejected(self):
  self.p['question']='Please upload something'
  with self.assertRaises(Problem):prepare(self.p)
 def test_consistency(self):
  self.p['summary']['dnsErrors']=4
  with self.assertRaises(Problem):prepare(self.p)
 def test_unknown_reference(self):
  self.r['hypotheses'][0]['evidenceIds']=['E999']
  with self.assertRaises(Problem):checked(self.r,prepare(self.p))
 def test_unsafe_output(self):
  for x in ['See https://example.com','Address 192.0.2.1','<script>','`command`']:
   r=copy.deepcopy(self.r);r['answer']=x
   with self.assertRaises(Problem):checked(r,prepare(self.p))
 def test_extra_response_fields(self):
  self.r['command']='bad'
  with self.assertRaises(Problem):checked(self.r,prepare(self.p))
 def test_empty_hypotheses(self):
  self.r['hypotheses']=[]
  with self.assertRaises(Problem):checked(self.r,prepare(self.p))
if __name__=='__main__':unittest.main()
