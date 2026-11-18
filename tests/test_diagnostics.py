import io,json,unittest,urllib.error
from unittest.mock import patch
import diagnostics as d

class DnsTests(unittest.TestCase):
 def setUp(self):
  d.CACHE.clear();d.REQUESTS.clear()
 def response(self,data):return io.BytesIO(json.dumps(data).encode())
 def test_names(self):
  self.assertEqual(d.domain_name('Example.COM.'),'example.com')
  for x in ['localhost','127.0.0.1','http://example.com','a.local','x.internal','example.com/path','evil.com@localhost','bad..com','a.'+'x'*64+'.com','a.localhost','10.0.0.1.nip.io/','foo.arpa','::1','-a.com','a-.com','x.com?name=foo','a.com\nHeader:x']:
   with self.subTest(x=x),self.assertRaises(d.LookupProblem):d.domain_name(x)
 def test_success_fixed_url_and_cache(self):
  data={'Status':0,'Answer':[{'type':1,'data':'192.0.2.1'}]}
  with patch.object(d.OPENER,'open',return_value=self.response(data)) as f:
   r=d.check_dns('example.com');self.assertEqual(r['addresses'],['192.0.2.1']);self.assertFalse(r['cached']);self.assertTrue(d.check_dns('example.com')['cached']);self.assertEqual(f.call_count,1)
   req=f.call_args.args[0];self.assertTrue(req.full_url.startswith('https://dns.google/resolve?'));self.assertIn('edns_client_subnet=0.0.0.0%2F0',req.full_url)
 def test_nxdomain(self):
  with patch.object(d.OPENER,'open',return_value=self.response({'Status':3})):
   self.assertIn('NXDOMAIN',d.check_dns('missing.example.com')['summary'])
 def test_empty_A(self):
  with patch.object(d.OPENER,'open',return_value=self.response({'Status':0})):
   self.assertIn('no IPv4',d.check_dns('example.com')['summary'])
 def test_timeout(self):
  with patch.object(d.OPENER,'open',side_effect=TimeoutError()):
   with self.assertRaises(d.LookupProblem) as e:d.check_dns('example.com')
   self.assertEqual(e.exception.status,502)
 def test_bad_json(self):
  with patch.object(d.OPENER,'open',return_value=io.BytesIO(b'not json')):
   with self.assertRaises(d.LookupProblem):d.check_dns('example.com')
 def test_wrong_schema(self):
  for data in [[],{}, {'Status':'0'},{'Status':0,'Answer':{}}]:
   with self.subTest(data=data),patch.object(d.OPENER,'open',return_value=self.response(data)):
    with self.assertRaises(d.LookupProblem):d.check_dns('example.com')
 def test_response_limit(self):
  with patch.object(d.OPENER,'open',return_value=io.BytesIO(b' '*131073)):
   with self.assertRaises(d.LookupProblem):d.check_dns('example.com')
 def test_rate_limit(self):
  import time
  d.REQUESTS.extend([time.monotonic()]*12)
  with self.assertRaises(d.LookupProblem) as e:d.check_dns('example.com')
  self.assertEqual(e.exception.status,429)
 def test_redirect_refused(self):
  with self.assertRaises(d.LookupProblem):d.NoRedirect().redirect_request(None,None,302,'',{},'http://127.0.0.1/')

if __name__=='__main__':unittest.main()
