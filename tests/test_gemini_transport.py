import io,json,os,sqlite3,unittest,urllib.error
from unittest.mock import patch
import server
from core import Problem
class GeminiTransportTests(unittest.TestCase):
 def setUp(self):
  self.db=sqlite3.connect(':memory:',check_same_thread=False);self.db.execute('CREATE TABLE usage(day TEXT PRIMARY KEY,calls INTEGER NOT NULL)');self.s={'llm_calls':0};self.stack=[]
  for p in [patch.object(server,'DB',self.db),patch.object(server,'LLM_ENABLED',True),patch.object(server,'MODEL','gemini-3.8-flash'),patch.dict(os.environ,{'GEMINI_API_KEY':'test-placeholder-not-a-real-key'})]:p.start();self.stack.append(p)
 def tearDown(self):
  for p in reversed(self.stack):p.stop()
  self.db.close()
 def response(self,finish='STOP'):
  return io.BytesIO(json.dumps({'candidates':[{'finishReason':finish,'content':{'parts':[{'text':'{"ok":true}'}]}}]}).encode())
 def test_success_and_low_config(self):
  with patch.object(server.urllib.request,'urlopen',return_value=self.response()) as op:
   self.assertEqual(server.gemini_generate('synthetic test',self.s),{'ok':True});req=op.call_args.args[0];c=json.loads(req.data)['generationConfig'];self.assertEqual(c['thinkingConfig'],{'thinkingLevel':'low'});self.assertNotIn('temperature',c);self.assertEqual(op.call_args.kwargs['timeout'],45)
 def test_incomplete_rejected(self):
  with patch.object(server.urllib.request,'urlopen',return_value=self.response('MAX_TOKENS')):
   with self.assertRaisesRegex(Problem,'complete answer'):server.gemini_generate('synthetic test',self.s)
 def test_timeout_explicit(self):
  with patch.object(server.urllib.request,'urlopen',side_effect=TimeoutError):
   with self.assertRaisesRegex(Problem,'timed out'):server.gemini_generate('synthetic test',self.s)
 def test_oversized_rejected(self):
  with patch.object(server.urllib.request,'urlopen',return_value=io.BytesIO(b'x'*196609)):
   with self.assertRaisesRegex(Problem,'size limit'):server.gemini_generate('synthetic test',self.s)
 def test_malformed_explicit(self):
  with patch.object(server.urllib.request,'urlopen',return_value=io.BytesIO(b'not-json')):
   with self.assertRaisesRegex(Problem,'incomplete or invalid'):server.gemini_generate('synthetic test',self.s)
 def test_http_failure_no_fallback(self):
  with patch.object(server.urllib.request,'urlopen',side_effect=urllib.error.HTTPError('https://example.invalid',429,'quota',{},None)) as op:
   with self.assertRaisesRegex(Problem,'HTTP 429'):server.gemini_generate('synthetic test',self.s)
   self.assertEqual(op.call_count,1)
 def test_session_cap_prevents_call(self):
  self.s['llm_calls']=8
  with patch.object(server.urllib.request,'urlopen') as op:
   with self.assertRaisesRegex(Problem,'eight Gemini'):server.gemini_generate('synthetic test',self.s)
   op.assert_not_called()
if __name__=='__main__':unittest.main()
