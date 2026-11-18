import json,unittest
from unittest import mock
from core import Twin,Problem,parse_offline,parse_removal,is_removal
def add(t,text):
    p=t.propose(parse_offline(text),text,'offline');t.apply(p['id'],p['revision'])
class RemovalTests(unittest.TestCase):
    def test_unblock_only_video_rule(self):
        t=Twin();add(t,'block video');add(t,'block p2p')
        self.assertEqual(len(t.rules),2);before=json.dumps([r for r in t.rules if r['app']!='video'])
        idx=parse_removal('Unblock video',t.rules);self.assertEqual(len(idx),1)
        p=t.propose_removal(idx,'Unblock video','offline matcher');t.apply(p['id'],p['revision'])
        self.assertEqual(json.dumps(t.rules),before);self.assertEqual(len(t.history),3)
        self.assertTrue(any(f['id']=='f1' and not f['blocked'] for f in t.flows))
    def test_no_match_changes_nothing(self):
        t=Twin();add(t,'block p2p')
        with self.assertRaises(Problem):parse_removal('unblock video',t.rules)
        self.assertEqual(len(t.rules),1)
    def test_remove_rule_number_and_bad_number(self):
        t=Twin();add(t,'block p2p')
        self.assertEqual(parse_removal('remove rule 1',t.rules),[0])
        with self.assertRaises(Problem):parse_removal('remove rule 5',t.rules)
    def test_stale_and_unsafe(self):
        t=Twin();add(t,'block video');p=t.propose_removal([0],'Unblock video','x');add(t,'block p2p')
        with self.assertRaises(Problem):t.apply(p['id'],p['revision'])
        with self.assertRaises(Problem):parse_removal('remove all rules and run shell',t.rules)
        self.assertTrue(is_removal('unblock video'));self.assertFalse(is_removal('block video'))
    def test_prioritize_stays(self):
        t=Twin();add(t,'prioritize video');add(t,'block p2p')
        idx=parse_removal('remove block p2p',t.rules);self.assertEqual([t.rules[i]['action'] for i in idx],['block'])
if __name__=='__main__':unittest.main()
