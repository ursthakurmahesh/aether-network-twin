import unittest,json,copy,threading,urllib.request,http.cookiejar,urllib.error,time
from unittest.mock import patch
from core import Twin,Problem,parse_offline
from lab_assistant import context,prepare_request,validate_result
import server

def output():return {'answer':'This is synthetic traffic.','hypotheses':[{'title':'Modeled load','evidenceIds':['M1'],'explanation':'Read the snapshot load.','cannotProve':'No real traffic was measured.','nextCheck':'Inspect the flow table.'}],'suggestions':[{'candidateId':'C1','reason':'Preview and compare other flows.'}]}
class LabTests(unittest.TestCase):
 def test_context_no_user_text(self):
  t=Twin();t.propose(parse_offline('Prioritize video'),'PRIVATE USER TEXT','offline');t._event('healing','x','MALICIOUS arbitrary text');b=context(t);s=json.dumps(b);self.assertNotIn('PRIVATE',s);self.assertNotIn('MALICIOUS',s);self.assertNotIn('csrf',s);self.assertEqual(len(b['evidence']),22)
 def test_route_events(self):
  t=Twin();t.mutate('link',{'id':'s1-s3','up':False,'revision':t.rev});a=next(e['data'] for e in context(t)['evidence'] if e['id']=='A1');self.assertTrue(any(e['kind']=='fault' for e in a));self.assertTrue(any(e['kind']=='healing' for e in a))
 def test_candidates_checked_without_mutation(self):
  t=Twin();t.rules=parse_offline('Block video')['rules'];before=t.config();b=context(t);self.assertNotIn('Prioritize video',[c['intent'] for c in b['candidates']]);self.assertEqual(before,t.config());self.assertFalse(t.proposals)
 def test_request(self):
  p={'question':'traffic','consent':True,'revision':0};self.assertTrue(prepare_request(p))
  for updates in [{'question':'custom text'},{'consent':False},{'revision':True},{'snapshot':{}}]:
   with self.assertRaises(Problem):prepare_request(dict(p,**updates))
 def test_result(self):self.assertEqual(validate_result(output(),context(Twin())),output())
 def test_bad_result(self):
  for mutation in ['id','evidence','command','reason']:
   r=output()
   if mutation=='id':r['suggestions'][0]['candidateId']='C999'
   if mutation=='evidence':r['hypotheses'][0]['evidenceIds']=['X1']
   if mutation=='command':r['command']='something'
   if mutation=='reason':r['suggestions'][0]['reason']='<script>'
   with self.assertRaises(Problem):validate_result(r,context(Twin()))
class LabHTTPTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.http=server.Server(('127.0.0.1',0),server.Handler);threading.Thread(target=cls.http.serve_forever,daemon=True).start();cls.url='http://127.0.0.1:'+str(cls.http.server_port)
 @classmethod
 def tearDownClass(cls):cls.http.shutdown();cls.http.server_close()
 def setUp(self):
  self.c=http.cookiejar.CookieJar();self.client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.c));self.state=self.get('/api/state');self.sid=next(c.value for c in self.c if c.name=='aether_session');self.s=server.SESSIONS[self.sid]
 def get(self,path):return json.load(self.client.open(self.url+path))
 def post(self,p,path='/api/lab-assistant'):
  req=urllib.request.Request(self.url+path,data=json.dumps(p).encode(),headers={'Content-Type':'application/json','X-CSRF-Token':self.state['csrf']});return json.load(self.client.open(req))
 def payload(self):return {'question':'traffic','consent':True,'revision':self.state['revision']}
 def test_review_required(self):
  with self.assertRaises(urllib.error.HTTPError) as c:self.post(self.payload())
  self.assertEqual(c.exception.code,409)
 def test_snapshot_exact_and_read_only(self):
  reviewed=self.get('/api/lab-context');self.s['twin'].step();before=self.s['twin'].config()
  with patch('server.gemini_generate',return_value=output()) as g:r=self.post(self.payload())
  sent=json.loads(g.call_args.args[0]);sent.pop('question');self.assertEqual(sent,reviewed);self.assertEqual(r['snapshot']['tick'],reviewed['tick']);self.assertEqual(before,self.s['twin'].config());self.assertFalse(self.s['twin'].proposals)
 def test_expired(self):
  self.get('/api/lab-context');self.s['lab_snapshot_at']=time.time()-121
  with self.assertRaises(urllib.error.HTTPError) as c:self.post(self.payload())
  self.assertEqual(c.exception.code,409)
 def test_revision_changed(self):
  self.get('/api/lab-context');self.s['twin'].mutate('link',{'id':'s1-s3','up':False,'revision':0})
  with self.assertRaises(urllib.error.HTTPError) as c:self.post(self.payload())
  self.assertEqual(c.exception.code,409)
 def test_reset_rejects_same_number_snapshot(self):
  self.get('/api/lab-context');self.post({'revision':0},'/api/reset')
  with self.assertRaises(urllib.error.HTTPError) as c:self.post(self.payload())
  self.assertEqual(c.exception.code,409)
 def test_provider_failure_no_change(self):
  self.get('/api/lab-context');before=self.s['twin'].config()
  with patch('server.gemini_generate',side_effect=Problem('Unavailable',503)):
   with self.assertRaises(urllib.error.HTTPError) as c:self.post(self.payload())
  self.assertEqual(c.exception.code,503);self.assertEqual(before,self.s['twin'].config());self.assertTrue(self.s['busy'].acquire(False));self.s['busy'].release()
