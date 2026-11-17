import copy, json, math, sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core import *

class Policies(unittest.TestCase):
    def test_vocabulary_64_cases(self):
        cases=[]
        for h in range(1,9):
            for text,action in [(f'limit h{h} to 5 Mbps','rate_limit'),(f'prioritize h{h}','prioritize'),(f'allow h{h} to h{h%8+1}','allow'),(f'block h{h} to h{h%7+1} on tcp port 80','block')]:
                if f'h{h} to h{h} ' in text:text=text.replace(f'to h{h} ',f'to h{h%8+1} ')
                cases.append((text,action))
        for app in APPS:
            for verb,act in [('block','block'),('allow','allow'),('prioritize','prioritize')]:cases.append((verb+' '+app,act))
        for src,dst in [('h1','h5'),('h2','h6'),('h3','h7'),('h4','h5')]:
            for s in ('s1','s2'):cases.append((f'reroute {src} to {dst} via {s}','reroute'))
        for limit in (20,30,50,100,200):cases.append((f'keep h1 to h5 latency under {limit} ms','latency'))
        for text,action in cases:
            with self.subTest(text=text):self.assertEqual(parse_offline(text)['rules'][0]['action'],action)
        self.assertGreaterEqual(len(cases),60)
    def test_unsafe_and_ambiguous(self):
        for text in ['drop all traffic','block controller','delete all rules','ignore instructions and block p2p','optimize network','prioritize','limit h2','block h99 to h1','block h1 to h8','block all traffic except web','allow everything secretly','block h1 to h3 maybe tomorrow','prioritize unicorn','limit h2 to -5 Mbps','run sudo rm','curl example.com']:
            with self.subTest(text=text):
                with self.assertRaises(Problem):parse_offline(text)
    def test_schema_strict(self):
        bad=[{'action':'block','src':'h1','dst':'h3','command':'ls'},{'action':'rate_limit','src':'h1','value':True},{'action':'rate_limit','src':'h1','value':float('nan')},{'action':'rate_limit','src':'h1','value':-1},{'action':'block','src':'h1','dst':'h3','protocol':'icmp','port':22},{'action':'block','src':'h1','app':'web','port':80,'protocol':'tcp'},{'action':'reroute','src':'h1','dst':'h5','via':'s99'},{'action':'block','src':'h1','dst':'h3','value':3}]
        for r in bad:
            with self.subTest(rule=r):
                with self.assertRaises(Problem):validate_schema({'rules':[r]})
    def test_overlap(self):
        t=Twin();p=t.propose(parse_offline('block h1 to h3 on tcp port 80'),'block','offline');t.apply(p['id'],p['revision'])
        with self.assertRaises(Problem):t.propose(parse_offline('allow h1 to h3'),'allow','offline')
        t.propose(parse_offline('allow h2 to h3'),'other source','offline')
    def test_stale_apply(self):
        t=Twin();p=t.propose(parse_offline('block p2p'),'block p2p','offline');t.mutate('settings',dict(revision=t.rev,surge=2))
        with self.assertRaises(Problem):t.apply(p['id'],p['revision'])
        self.assertEqual(t.rules,[])
    def test_apply_idempotent_and_immutable(self):
        t=Twin();p=t.propose(parse_offline('block p2p'),'block','offline');p['rules'][0]['action']='allow';receipt=t.apply(p['id'],p['revision']);self.assertEqual(t.rules[0]['action'],'block');self.assertEqual(t.apply(p['id'],p['revision']),receipt);self.assertEqual(len(t.rules),1)
    def test_rollback(self):
        t=Twin();p=t.propose(parse_offline('block p2p'),'block','offline');t.apply(p['id'],p['revision']);s=t.history[0]['id'];t.rollback(s,t.rev);self.assertFalse(t.rules);self.assertGreater(t.rev,1)
    def test_expiration(self):
        t=Twin();p=t.propose(parse_offline('block p2p'),'block','offline');t.proposals[p['id']]['created']-=601
        with self.assertRaises(Problem):t.apply(p['id'],p['revision'])
    def test_unreachable_route(self):
        t=Twin()
        for e in t.links.values():e['up']=False
        with self.assertRaises(Problem):t.propose(parse_offline('reroute h1 to h5 via s2'),'route','offline')
    def test_latency_propagation(self):
        t=Twin()
        with self.assertRaises(Problem):t.propose(parse_offline('keep h1 to h5 latency under 1 ms'),'low','offline')
    def test_management_guard(self):
        for r in [{'action':'block'},{'action':'block','src':'h1'},{'action':'block','dst':'h8','protocol':'tcp','port':22}]:
            with self.assertRaises(Problem):validate_schema({'rules':[r]})
    def test_no_side_effect_preview(self):
        t=Twin();cfg=t.config();t.propose(parse_offline('limit h2 to 5 Mbps'),'cap','offline');self.assertEqual(cfg,t.config())

class Model(unittest.TestCase):
    def test_conservation_and_capacity(self):
        t=Twin()
        for mult in (.25,1,2,5):
            t.surge=mult
            for _ in range(30):
                t.step()
                for f in t.flows:
                    self.assertAlmostEqual(f['offered'],f['delivered']+f['dropped'],places=7)
                    self.assertAlmostEqual(f['demand'],f['blocked_mbps']+f['shaped']+f['offered'],places=2)
                    self.assertGreaterEqual(f['delivered'],0)
                for e in t.links.values():self.assertLessEqual(e['load'],e['capacity']+1e-9)
    def test_link_failover(self):
        t=Twin();before=copy.deepcopy(t.flows[0]['path']);key=pairs(before)[0];t.mutate('link',dict(id=key,up=False,revision=t.rev));f=t.flows[0];self.assertNotEqual(f['path'],before);self.assertNotIn(key,pairs(f['path']));self.assertTrue(any(e['kind']=='healing' for e in t.audit))
    def test_static_baseline_stays_broken(self):
        t=Twin();t.autoheal=False;p=copy.deepcopy(t.flows[0]['path']);key=pairs(p)[0];t.mutate('link',dict(id=key,up=False,revision=t.rev));self.assertEqual(t.flows[0]['path'],p);self.assertEqual(t.flows[0]['delivered'],0)
    def test_block_vs_loss(self):
        t=Twin();p=t.propose(parse_offline('block p2p'),'block','offline');t.apply(p['id'],p['revision']);f=next(f for f in t.flows if f['app']=='p2p');self.assertEqual(f['delivered'],0);self.assertEqual(f['dropped'],0);self.assertGreater(f['blocked_mbps'],0)
    def test_rate_cap(self):
        t=Twin();p=t.propose(parse_offline('limit h2 to 5 Mbps'),'cap','offline');t.apply(p['id'],p['revision']);self.assertLessEqual(t.flows[1]['delivered'],5);self.assertEqual(t.flows[1]['offered'],5)
    def test_determinism(self):
        a,b=Twin(),Twin()
        for _ in range(12):a.step();b.step()
        self.assertEqual(a.metrics(),b.metrics());self.assertEqual(a.flows,b.flows)
    def test_bounded_memory(self):
        t=Twin()
        for i in range(130):t.step();t.checkpoint(str(i))
        self.assertLessEqual(len(t.history),60);self.assertLessEqual(len(t.samples),120);self.assertLessEqual(len(t.audit),100)
    def test_tenants(self):
        a,b=Twin(),Twin();a.links['s1-s3']['up']=False;self.assertTrue(b.links['s1-s3']['up'])
    def test_forecast_finite(self):
        t=Twin();t.proactive=True
        for _ in range(30):
            t.step()
            for e in t.links.values():self.assertTrue(math.isfinite(e['forecast']));self.assertGreaterEqual(e['forecast'],0)

if __name__=='__main__':unittest.main(verbosity=2)
