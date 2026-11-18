import copy, unittest
from core import Twin, pairs, parse_offline

class Healing(unittest.TestCase):
    def fail(self,t,key):t.mutate('link',dict(id=key,up=False,revision=t.rev))
    def test_same_tick_comparison(self):
        t=Twin();self.fail(t,'s1-s3');i=t.state()['incidents'][0]
        self.assertEqual(i['tick'],0);self.assertEqual(len(i['flows']),5)
        self.assertLess(i['without_healing']['throughput'],i['after']['throughput'])
        self.assertFalse(t.links['s1-s3']['up'])
        for f in t.flows:self.assertNotIn('s1-s3',pairs(f['path']))
    def test_reactive_off_beats_proactive(self):
        t=Twin();t.autoheal=False;t.proactive=True;p=t.flows[0]['path'][:];self.fail(t,pairs(p)[0])
        for _ in range(8):t.step()
        self.assertEqual(t.flows[0]['path'],p);self.assertEqual(t.flows[0]['delivered'],0)
        self.assertEqual(t.flows[0]['route_status'],'healing_disabled')
    def test_enable_heals_frozen(self):
        t=Twin();t.autoheal=False;self.fail(t,'s1-s3');t.mutate('settings',dict(autoheal=True,revision=t.rev))
        self.assertNotIn('s1-s3',pairs(t.flows[0]['path']));self.assertGreater(t.flows[0]['delivered'],0)
    def test_partition_not_success(self):
        t=Twin()
        for key in ['s1-s3','s2-s3','s3-s4']:self.fail(t,key)
        self.assertEqual(t.flows[0]['path'],[]);self.assertEqual(t.flows[0]['route_status'],'unreachable')
        self.assertTrue(any(e['title']=='No alternate path' and e['kind']=='fault' for e in t.audit))
    def test_empty_path_stays_frozen_when_disabled(self):
        t=Twin()
        for key in ['s1-s3','s2-s3','s3-s4']:self.fail(t,key)
        t.autoheal=False;t.proactive=True;t.mutate('link',dict(id='s1-s3',up=True,revision=t.rev));t.step()
        self.assertEqual(t.flows[0]['path'],[])
    def test_recover_empty_logged(self):
        t=Twin()
        for key in ['s1-s3','s2-s3','s3-s4']:self.fail(t,key)
        t.mutate('link',dict(id='s1-s3',up=True,revision=t.rev))
        self.assertTrue(t.flows[0]['path']);self.assertTrue(any('unreachable to' in e['detail'] and e['kind']=='healing' for e in t.audit))
    def test_approved_route_works_when_autoheal_off(self):
        t=Twin();t.autoheal=False;p=t.propose(parse_offline('reroute h1 to h5 via s2'),'route','offline');t.apply(p['id'],p['revision'])
        self.assertIn('s2',t.flows[0]['path'])
    def test_unused_link(self):
        t=Twin();self.fail(t,'s1-s2');self.assertEqual(t.incidents[0]['flows'],[])
    def test_capacity_not_promised(self):
        t=Twin();t.surge=5;t.step(0);self.fail(t,'s1-s3')
        self.assertTrue(any(f['route_status']=='capacity_limited' for f in t.flows))
        for e in t.links.values():self.assertLessEqual(e['load'],e['capacity']+1e-9)
    def test_restore_preserves_other_state(self):
        t=Twin();p=t.propose(parse_offline('block video'),'block video','offline');t.apply(p['id'],p['revision']);rules=copy.deepcopy(t.rules)
        self.fail(t,'s1-s3');self.fail(t,'s1-s4');t.mutate('link',dict(id='s1-s4',up=True,revision=t.rev))
        self.assertEqual(rules,t.rules);self.assertFalse(t.links['s1-s3']['up'])
    def test_incident_bounded_and_immutable(self):
        t=Twin();self.fail(t,'s1-s3');record=copy.deepcopy(t.incidents[0]);t.step();self.assertEqual(record,t.incidents[0])
        for n in range(20):t.mutate('link',dict(id='s1-s3',up=bool(n%2==0),revision=t.rev))
        self.assertLessEqual(len(t.incidents),12)
    def test_noop_no_revision(self):
        t=Twin();t.mutate('link',dict(id='s1-s3',up=True,revision=t.rev));self.assertEqual(t.rev,0)
