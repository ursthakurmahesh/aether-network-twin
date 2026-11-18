"""AETHER deterministic network digital twin. No packets or shell commands are sent."""
from __future__ import annotations
import copy, hashlib, heapq, json, math, re, secrets, threading, time
from collections import deque

HOSTS = {f'h{i}': f's{(i-1)//2+3}' for i in range(1,9)}
APPS = {'web': ('tcp',443), 'voice': ('udp',5060), 'video': ('udp',5004), 'p2p': ('tcp',6881), 'dns': ('udp',53)}
ACTIONS = {'block','allow','rate_limit','prioritize','reroute','latency'}
class Problem(ValueError):
    def __init__(self, message, status=422):
        super().__init__(message); self.status=status

def edge_id(a,b): return '-'.join(sorted((a,b)))
def pairs(path): return [edge_id(a,b) for a,b in zip(path,path[1:])]
def topology():
    return {edge_id(a,b):dict(id=edge_id(a,b),a=a,b=b,capacity=cap,delay=delay,up=True,load=0.0,utilization=0.0,forecast=0.0)
            for a,b,cap,delay in [('s1','s2',100,2),('s1','s3',40,3),('s1','s4',40,3),('s1','s5',40,4),('s1','s6',40,4),('s2','s3',40,4),('s2','s4',40,4),('s2','s5',40,3),('s2','s6',40,3),('s3','s4',20,2),('s5','s6',20,2) ]}

def pathfind(links, src, dst, avoid=(), via=None, proactive=False, latency_aware=False):
    start, end = HOSTS.get(src,src), HOSTS.get(dst,dst)
    def segment(s,t):
        heap=[(0,[s])]; seen=set()
        while heap:
            cost,path=heapq.heappop(heap); u=path[-1]
            if u==t: return path
            if u in seen: continue
            seen.add(u)
            for e in links.values():
                if not e['up'] or e['id'] in avoid: continue
                v=e['b'] if e['a']==u else e['a'] if e['b']==u else None
                if v and v not in path:
                    penalty=20*max(e.get('forecast',0),e.get('utilization',0))**3 if proactive else 0
                    if latency_aware: penalty+=0.2*e.get('utilization',0)/max(.05,1-e.get('utilization',0))
                    heapq.heappush(heap,(cost+e['delay']+penalty,path+[v]))
        return []
    out=[]
    for s,t in zip([start]+([via] if via else []),([via] if via else [])+[end]):
        p=segment(s,t)
        if not p: return []
        out+=p if not out else p[1:]
    if len(out)!=len(set(out)): return []
    return out

def selector_matches(rule,flow):
    return all(rule.get(k,'any') in ('any',flow[k]) for k in ('src','dst','app')) and rule.get('protocol','any') in ('any', flow['protocol']) and (rule.get('port') is None or rule['port']==flow['port'])
def overlaps(a,b):
    return all(a.get(k,'any')=='any' or b.get(k,'any')=='any' or a.get(k)==b.get(k) for k in ('src','dst','app','protocol')) and (a.get('port') is None or b.get('port') is None or a['port']==b['port'])

def validate_schema(bundle):
    if type(bundle) is not dict or set(bundle)!={'rules'} or type(bundle['rules']) is not list or not 1<=len(bundle['rules'])<=12: raise Problem('Expected an object with 1-12 rules and no other fields.')
    result=[]
    for raw in bundle['rules']:
        if type(raw) is not dict or set(raw)-{'action','src','dst','app','protocol','port','value','via','avoid'}: raise Problem('Unknown rule fields are not permitted.')
        if raw.get('action') not in ACTIONS: raise Problem('Unsupported policy action.')
        r=dict(action=raw['action'],src=raw.get('src','any'),dst=raw.get('dst','any'),app=raw.get('app','any'),protocol=raw.get('protocol','any'))
        for k in ('src','dst'):
            if r[k] not in {*HOSTS,'any'}: raise Problem('Unknown host. Use h1 through h8.')
        if r['src']==r['dst'] and r['src']!='any': raise Problem('Source and destination must differ.')
        if r['app'] not in {*APPS,'any'} or r['protocol'] not in {'tcp','udp','icmp','any'}: raise Problem('Unknown application or protocol.')
        if raw.get('port') is not None:
            if type(raw['port']) is not int or not 1<=raw['port']<=65535 or r['protocol'] not in {'tcp','udp'}: raise Problem('Ports require TCP/UDP and an integer from 1 to 65535.')
            r['port']=raw['port']
        if r['app']!='any':
            proto,port=APPS[r['app']]
            if r['protocol'] not in ('any',proto) or r.get('port',port)!=port: raise Problem('Application and protocol/port disagree.')
            r['protocol']=proto; r['port']=port
        if r['action'] in {'rate_limit','latency'}:
            v=raw.get('value')
            if type(v) not in (float,int) or not math.isfinite(v) or not 0<v<=1000: raise Problem('A positive finite value up to 1000 is required.')
            r['value']=float(v)
        elif 'value' in raw: raise Problem('Unexpected numeric value for this action.')
        if r['action']=='reroute':
            if r['src']=='any' or r['dst']=='any': raise Problem('Reroute requires exact source and destination hosts.')
            via=raw.get('via'); avoid=raw.get('avoid',[])
            if via is not None and via not in {f's{i}' for i in range(1,7)}: raise Problem('Unknown waypoint switch.')
            if type(avoid) is not list or len(avoid)>4 or any(type(e) is not str or e not in topology() for e in avoid): raise Problem('Avoid must contain up to four known link IDs.')
            if not via and not avoid: raise Problem('Reroute needs a waypoint or an avoided link.')
            r['via']=via;r['avoid']=avoid
        elif 'via' in raw or 'avoid' in raw: raise Problem('Waypoints and avoided links only apply to reroute.')
        if r['action']=='block' and r['src']=='any' and r['dst']=='any' and r['app']=='any' and r['protocol']=='any': raise Problem('Safety gate: network-wide drop is forbidden.')
        # Preserve management access to h8 (the management host).
        if r['action']=='block' and r['dst'] in ('h8','any') and r['app']=='any' and r['protocol'] in ('any','tcp') and r.get('port') in (None,22): raise Problem('Safety gate: management SSH reachability must remain available.')
        result.append(r)
    return {'rules':result}

DANGER = re.compile(r'\b(controller|shell|sudo|exec|delete|ignore|system prompt|api.key|password|secret|override|instructions|script|curl|wget)\b|[{}<>`]|https?://',re.I)
def parse_offline(text):
    if type(text) is not str or not 1<=len(text.strip())<=1000: raise Problem('Write an intent between 1 and 1000 characters.')
    if DANGER.search(text): raise Problem('Intent rejected: management targets, commands and instruction overrides are not accepted.')
    rules=[]
    for c in re.split(r'\s+and\s+|;|,\s*(?=(?:block|allow|limit|prioritize|keep|reroute|route)\b)',text.lower().strip()):
        c=c.strip().rstrip('.')
        hosts=re.findall(r'\bh\d+\b',c)
        if any(h not in HOSTS for h in hosts): raise Problem('Unknown host. Use h1 through h8.')
        r={'src':hosts[0] if hosts else 'any','dst':hosts[1] if len(hosts)>1 else 'any'}
        names=[k for k in APPS if re.search(r'\b'+k+r'\b',c)]
        if re.search(r'voice|voip|sip',c): names=['voice']
        if re.search(r'video|calls',c) and not names: names=['video']
        if re.search(r'bittorrent|peer.to.peer|p2p',c): names=['p2p']
        if re.search(r'web|https',c): names=['web']
        if len(names)>1: raise Problem('Specify one application per clause, joined by and.')
        if names:r['app']=names[0]
        proto=re.search(r'\b(tcp|udp|icmp)\b',c)
        if proto:r['protocol']=proto.group(1)
        port=re.search(r'\bport\s+(\d+)\b',c)
        if port:r['port']=int(port.group(1));r.setdefault('protocol','tcp')
        if re.match(r'^(block|deny|drop)\b',c): r['action']='block'
        elif re.match(r'^(allow|permit)\b',c): r['action']='allow'
        elif re.match(r'^(limit|rate.limit|cap|throttle)\b',c):
            r['action']='rate_limit';v=re.search(r'(?<![\w.])([+-]?\d+(?:\.\d+)?)\s*mbps\b',c)
            if not v:raise Problem('Clarify the bandwidth limit in Mbps, for example: limit h2 to 5 Mbps.')
            r['value']=float(v.group(1))
        elif re.match(r'^(prioritize|prioritise|prioritization|give priority to)\b',c):r['action']='prioritize'
        elif re.match(r'^(keep|latency|ensure)\b',c) and 'latency' in c:
            r['action']='latency';v=re.search(r'(?<![\w.])([+-]?\d+(?:\.\d+)?)\s*ms\b',c)
            if not v:raise Problem('Clarify the latency ceiling in milliseconds.')
            r['value']=float(v.group(1))
        elif re.match(r'^(reroute|route)\b',c):
            r['action']='reroute';v=re.search(r'(?:via|through)\s+(s\d+)\b',c);a=re.search(r'avoid(?:ing)?\s+(s\d+-s\d+)\b',c)
            if v:r['via']=v.group(1)
            if a:r['avoid']=[a.group(1)]
        else: raise Problem('Clarification needed. Use block, allow, limit, prioritize, reroute, or keep latency with explicit hosts/application.')
        if r['action'] in {'allow','rate_limit','prioritize'} and not hosts and not names:raise Problem('Clarify which host or application this should affect.')
        if r['action']=='block' and not hosts and not names and c not in {'block all traffic','drop all traffic','deny all traffic'}:raise Problem('Clarify the traffic selector. Nothing has been applied.')
        # Do not silently discard unknown words or qualifiers in the constrained parser.
        leftover=re.sub(r'\bh\d+\b|\bs\d+(?:-s\d+)?\b|\d+(?:\.\d+)?|\b(block|deny|drop|allow|permit|limit|rate|cap|throttle|prioritize|prioritise|prioritization|give|priority|to|keep|latency|ensure|under|below|at|most|maximum|less|than|reroute|route|via|through|avoid|avoiding|from|on|port|tcp|udp|icmp|mbps|ms|traffic|all|any|the|for|of|video|voice|voip|sip|calls|p2p|peer|bittorrent|web|https|dns|network)\b|[-\s]','',c)
        if leftover: raise Problem('Some wording is outside the offline parser vocabulary. Simplify the intent or use Gemini. Nothing was applied.')
        rules.append(r)
    return validate_schema({'rules':rules})

REMOVE_WORDS=re.compile(r'^\s*(unblock|un-block|remove|undo|lift|revoke|cancel|stop|unlimit|unprioriti[sz]e|clear|get rid of|turn off|take off|disable)\b',re.I)
def is_removal(text):return type(text) is str and bool(REMOVE_WORDS.match(text))
def parse_removal(text,rules):
    """Deterministic removal: returns indexes of existing approved rules. Never invents or edits rules."""
    if type(text) is not str or not 1<=len(text.strip())<=1000:raise Problem('Write an intent between 1 and 1000 characters.')
    if DANGER.search(text):raise Problem('Intent rejected: management targets, commands and instruction overrides are not accepted.')
    c=text.lower().strip().rstrip('.')
    m=re.search(r'\brules?\s+(\d+(?:\s*(?:,|and)\s*\d+)*)\b',c)
    if m:
        nums=[int(n) for n in re.findall(r'\d+',m.group(1))]
        if any(not 1<=n<=len(rules) for n in nums):raise Problem('No such rule number. Open Policy registry to see rule numbers. Nothing was changed.')
        return [n-1 for n in nums]
    verb=re.match(r'^\s*(unblock|un-block|remove|undo|lift|revoke|cancel|stop|unlimit|unprioriti[sz]e|clear|get rid of|turn off|take off|disable)\b',c).group(1)
    rest=c[len(c)-len(c.lstrip()):] if False else re.sub(r'^\s*'+verb,'',c).strip()
    action={'unblock':'block','un-block':'block','unlimit':'rate_limit','unprioritize':'prioritize','unprioritise':'prioritize'}.get(verb)
    for a,words in (('block',r'\b(block|blocking|blocked|deny|drop)\b'),('rate_limit',r'\b(limit|cap|throttle|rate)\b'),('prioritize',r'\b(prioriti[sz]e|prioriti[sz]ing|priority)\b'),('reroute',r'\b(reroute|route)\b'),('latency',r'\blatency\b'),('allow',r'\b(allow|permit)\b')):
        if re.search(words,rest):action=a
    hosts=re.findall(r'\bh\d+\b',rest)
    if any(h not in HOSTS for h in hosts):raise Problem('Unknown host. Use h1 through h8.')
    names=[k for k in APPS if re.search(r'\b'+k+r'\b',rest)]
    if re.search(r'voice|voip|sip',rest):names=['voice']
    if re.search(r'video|calls',rest) and not names:names=['video']
    if re.search(r'bittorrent|peer.to.peer|p2p',rest):names=['p2p']
    if re.search(r'\bweb\b|https',rest):names=['web']
    if len(names)>1:raise Problem('Name one application per removal, for example: unblock video. Nothing was changed.')
    if not action and verb not in ('unblock','un-block','unlimit','unprioritize','unprioritise'):raise Problem('Say which kind of rule to remove, for example: unblock video, or remove rule 2. Nothing was changed.')
    if not hosts and not names:raise Problem('Name a host or application, for example: unblock video, or remove rule 2. Nothing was changed.')
    out=[]
    for i,r in enumerate(rules):
        if action and r['action']!=action:continue
        if names and r['app']!=names[0]:continue
        if hosts and r['src'] not in hosts and r['dst'] not in hosts:continue
        if len(hosts)>1 and not (r['src']==hosts[0] and r['dst']==hosts[1]):continue
        out.append(i)
    if not out:raise Problem('No approved rule matches that. Open Policy registry to see current rules. Nothing was changed.',404)
    return out

class Twin:
    def __init__(self):
        self.lock=threading.RLock();self.links=topology();self.rules=[];self.rev=0;self.tick=0;self.proactive=False;self.autoheal=True;self.surge=1.;self.history=deque(maxlen=60);self.audit=deque(maxlen=100);self.samples=deque(maxlen=120);self.link_history={e:deque(maxlen=20) for e in self.links};self.proposals={};self.receipts={};self.flows=[];self._last_paths={};self._last_reroute={};self._routing_rev=-1;self.last_seen=time.time();self._event('system','Twin initialized','Six switches, eight hosts. All traffic is synthetic.');self.step(0)
    def _event(self,kind,title,detail,**kw):self.audit.appendleft(dict(id=secrets.token_hex(6),at=time.time(),tick=self.tick,kind=kind,title=title,detail=detail,**kw))
    def config(self):return copy.deepcopy(dict(rules=self.rules,links={k:{f:e[f] for f in ('up','capacity','delay')} for k,e in self.links.items()},autoheal=self.autoheal,proactive=self.proactive,surge=self.surge))
    def checkpoint(self,label):
        self.history.appendleft(dict(id=secrets.token_hex(6),rev=self.rev,label=label,at=time.time(),config=self.config()))
    def route(self,f,rules=None,links=None):
        rules=self.rules if rules is None else rules;links=self.links if links is None else links
        relevant=[r for r in rules if selector_matches(r,f)];routes=[r for r in relevant if r['action']=='reroute'];r=routes[-1] if routes else {}
        return pathfind(links,f['src'],f['dst'],r.get('avoid',()),r.get('via'),self.proactive,any(r['action']=='latency' for r in relevant) and self.autoheal)
    def check(self,bundle):
        canonical=validate_schema(bundle);combined=self.rules+canonical['rules'];errors=[]
        if len(combined)>64:raise Problem('Policy limit reached. Roll back or reset this twin.')
        for i,a in enumerate(combined):
            for b in combined[i+1:]:
                if overlaps(a,b) and a!=b:
                    if 'block' in {a['action'],b['action']} and a['action']!=b['action']:errors.append('Overlapping block and non-block policies conflict. Roll back the conflicting rule first.')
                    if a['action']==b['action']=='reroute' and (a.get('via'),a.get('avoid'))!=(b.get('via'),b.get('avoid')):errors.append('Overlapping explicit routes disagree.')
                    if a['action']==b['action']=='rate_limit' and a['value']!=b['value']:errors.append('Overlapping rate limits disagree.')
        for r in canonical['rules']:
            if r['action'] in ('reroute','latency'):
                for src in ([r['src']] if r['src']!='any' else HOSTS):
                    for dst in ([r['dst']] if r['dst']!='any' else HOSTS):
                        if src==dst:continue
                        f=dict(src=src,dst=dst,app=r['app'],protocol=r['protocol'],port=r.get('port',0));p=self.route(f,combined)
                        if not p:errors.append(f'No feasible route for {src} to {dst}.')
                        elif r['action']=='latency' and sum(self.links[k]['delay'] for k in pairs(p))*2>r['value']:errors.append(f'Propagation alone exceeds {r["value"]} ms RTT for {src} to {dst}.')
        if errors:raise Problem(' '.join(dict.fromkeys(errors)))
        return canonical
    def propose(self,bundle,text,source):
        b=self.check(bundle); token=secrets.token_urlsafe(18)
        preview=self.preview(b['rules'])
        if len(self.proposals)>=16:self.proposals.pop(next(iter(self.proposals)))
        p=dict(id=token,revision=self.rev,created=time.time(),intent=text,rules=b['rules'],source=source,checks=['Strict schema','Management protection','Overlap conflicts','Route feasibility','Digital-twin dry run'],preview=preview)
        self.proposals[token]=copy.deepcopy(p);self._event('validation','Policy validated',f'{len(b["rules"])} rule(s) staged; explicit approval required.');return p
    def propose_removal(self,indexes,text,source):
        idx=sorted(set(indexes))
        if not idx or len(idx)>12 or any(type(i) is not int or not 0<=i<len(self.rules) for i in idx):raise Problem('No matching approved rule to remove. Nothing was changed.')
        token=secrets.token_urlsafe(18);removed=[copy.deepcopy(self.rules[i]) for i in idx];preview=self.preview([],idx)
        if len(self.proposals)>=16:self.proposals.pop(next(iter(self.proposals)))
        p=dict(id=token,revision=self.rev,created=time.time(),intent=text,rules=[],remove=idx,removed=removed,source=source,checks=['Only the listed approved rules are removed','Other policies, link states and settings are untouched','Remaining rules re-validated','Digital-twin dry run'],preview=preview)
        self.proposals[token]=copy.deepcopy(p);self._event('validation','Rule removal validated',f'{len(idx)} rule(s) staged for removal; explicit approval required.');return p
    def preview(self,rules,remove=()):
        other=Twin();other.links=copy.deepcopy(self.links);other.rules=copy.deepcopy([r for i,r in enumerate(self.rules) if i not in set(remove)]+rules);other.tick=self.tick;other.surge=self.surge;other.proactive=self.proactive;other.autoheal=self.autoheal;other.step(0)
        return dict(before=self.metrics(),after=other.metrics(),affected=[f['id'] for f in other.flows if any(selector_matches(r,f) for r in rules+[self.rules[i] for i in remove])])
    def apply(self,pid,revision):
        if pid in self.receipts:return self.receipts[pid]
        p=self.proposals.get(pid)
        if not p:raise Problem('Proposal not found. Prepare it again.',404)
        if time.time()-p['created']>600:raise Problem('Proposal expired. Prepare it again.',409)
        if type(revision) is not int or revision!=self.rev or p['revision']!=self.rev:raise Problem('The twin changed after preview. Re-validate the intent before approving.',409)
        if p.get('remove'):
            idx=set(p['remove']);keep=[r for i,r in enumerate(self.rules) if i not in idx]
            if [self.rules[i] for i in sorted(idx)]!=p['removed']:raise Problem('The rules changed after preview. Re-validate before approving.',409)
            self.checkpoint('Before '+p['intent'][:70]);self.rules=keep;self.rev+=1;self._last_paths={};self.step(0);receipt=dict(applied=True,revision=self.rev,proposal_id=pid,removed=len(idx));self.receipts[pid]=receipt;self._event('policy','Rule(s) removed',p['intent'][:200]);return receipt
        self.check({'rules':p['rules']});self.checkpoint('Before '+p['intent'][:70]);self.rules+=copy.deepcopy(p['rules']);self.rev+=1;self._last_paths={};self.step(0);receipt=dict(applied=True,revision=self.rev,proposal_id=pid);self.receipts[pid]=receipt
        if len(self.receipts)>64:self.receipts.pop(next(iter(self.receipts)))
        self._event('policy','Policy deployed',p['intent'][:200]);return receipt
    def rollback(self,snapshot,revision):
        if revision!=self.rev:raise Problem('State changed before rollback.',409)
        s=next((s for s in self.history if s['id']==snapshot),None)
        if not s:raise Problem('Snapshot no longer retained.',404)
        c=copy.deepcopy(s['config']);self.checkpoint('Before rollback');self.rules=c['rules']
        for k,v in c['links'].items():self.links[k].update(v)
        self.autoheal=c['autoheal'];self.proactive=c['proactive'];self.surge=c['surge'];self.rev+=1;self._last_paths={};self.step(0);self._event('rollback','Snapshot restored',s['label']);return {'restored':True,'revision':self.rev}
    def mutate(self,action,payload):
        if payload.get('revision')!=self.rev:raise Problem('State changed. Refresh before changing the twin.',409)
        if action=='link':
            eid=payload.get('id');up=payload.get('up')
            if eid not in self.links or type(up) is not bool:raise Problem('Choose a known link and boolean up state.')
            self.checkpoint('Before link '+eid);self.links[eid]['up']=up;self._event('fault' if not up else 'restore','Link '+('restored' if up else 'failed'),eid)
        elif action=='settings':
            if set(payload)-{'revision','autoheal','proactive','surge'}:raise Problem('Unknown setting.')
            for k in ('autoheal','proactive'):
                if k in payload and type(payload[k]) is not bool:raise Problem('Settings must be booleans.')
            if 'surge' in payload and (type(payload['surge']) not in (int,float) or not math.isfinite(payload['surge']) or not 0.25<=payload['surge']<=5):raise Problem('Traffic multiplier must be 0.25 through 5.')
            self.checkpoint('Before settings change')
            for k in ('autoheal','proactive','surge'):
                if k in payload:setattr(self,k,payload[k])
            self._event('system','Control settings updated','All changes affect only this visitor digital twin.')
        else:raise Problem('Unknown operation.')
        self.rev+=1;self.step(0);return {'revision':self.rev}
    def step(self,dt=1):
        self.tick+=dt
        for e in self.links.values():e['load']=0.
        rows=[]
        for i,(src,dst,app,base) in enumerate([('h1','h5','video',12),('h2','h6','web',18),('h3','h7','voice',4),('h4','h5','p2p',16),('h6','h2','web',14),('h7','h3','dns',2),('h5','h1','web',10),('h8','h1','web',3)]):
            protocol,port=APPS[app];demand=base*self.surge*(1+0.15*math.sin(self.tick/8+i));f=dict(id=f'f{i+1}',src=src,dst=dst,app=app,protocol=protocol,port=port,demand=round(demand,3));rr=[r for r in self.rules if selector_matches(r,f)];blocked=any(r['action']=='block' for r in rr);cap=min([r['value'] for r in rr if r['action']=='rate_limit']+[demand]);f.update(blocked=blocked,priority=any(r['action']=='prioritize' for r in rr),offered=0 if blocked else min(demand,cap),shaped=0 if blocked else max(0,demand-cap),max_latency=min([r['value'] for r in rr if r['action']=='latency']+[1000]))
            old=self._last_paths.get(f['id']);route=self.route(f)
            if old and not self.autoheal and not self.proactive:route=old
            old_valid=bool(old) and all(self.links[k]['up'] for k in pairs(old))
            latency_rules=[r for r in rr if r['action']=='latency']
            if old_valid and route!=old and self._routing_rev==self.rev and (self.proactive or latency_rules):
                def cost(path):return sum(self.links[k]['delay']+(20*max(self.links[k]['forecast'],self.links[k]['utilization'])**3 if self.proactive else 0)+(0.2*self.links[k]['utilization']/max(.05,1-self.links[k]['utilization']) if latency_rules else 0) for k in pairs(path))
                violated=latency_rules and sum(self.links[k]['delay']+0.2*self.links[k]['utilization']/max(.05,1-self.links[k]['utilization']) for k in pairs(old))*2>f['max_latency']
                if not violated and (self.tick-self._last_reroute.get(f['id'],-999)<5 or cost(route)>=cost(old)*.85):route=old
            if old and old!=route and (self.autoheal or self.proactive):
                self._last_reroute[f['id']]=self.tick
                self._event('healing','Path recomputed',f'{f["id"]}: '+ ' → '.join(old)+' to '+' → '.join(route or ['unreachable']),mode='proactive' if self.proactive and old_valid else 'latency' if latency_rules and old_valid else 'reactive')
            f['path']=route;rows.append(f)
        self._routing_rev=self.rev
        # Aggregate policer budgets apply across every flow matched by each rate-limit rule.
        budgets={i:r['value'] for i,r in enumerate(self.rules) if r['action']=='rate_limit'}
        # Deterministic priority scheduling; allocate no more than residual capacity on any link.
        for f in sorted(rows,key=lambda f:(not f['priority'],f['id'])):
            matched=[i for i in budgets if selector_matches(self.rules[i],f)]
            if not f['blocked']:
                f['offered']=min([f['demand']]+[budgets[i] for i in matched]);f['shaped']=f['demand']-f['offered']
                for i in matched:budgets[i]=max(0,budgets[i]-f['offered'])
            ps=pairs(f['path']);valid=bool(f['path']) and all(self.links[k]['up'] for k in ps)
            available=min([max(0,self.links[k]['capacity']-self.links[k]['load']) for k in ps]+[f['offered']]) if valid else 0
            f['delivered']=min(f['offered'],available);f['dropped']=max(0,f['offered']-f['delivered']);f['blocked_mbps']=f['demand'] if f['blocked'] else 0
            for k in ps:
                if valid:self.links[k]['load']+=f['delivered']
            self._last_paths[f['id']]=f['path']
        for e in self.links.values():
            e['utilization']=e['load']/e['capacity'];hist=self.link_history[e['id']]
            if dt:hist.append(e['utilization'])
            xs=list(hist)[-8:];slope=(xs[-1]-xs[0])/max(1,len(xs)-1) if xs else 0;e['forecast']=min(2,max(0,(sum(xs)/len(xs) if xs else e['utilization'])+5*slope))
        for f in rows:
            if f['blocked'] or not f['path'] or any(not self.links[k]['up'] for k in pairs(f['path'])):f['latency']=None
            else:f['latency']=round(sum(self.links[k]['delay']+0.2*self.links[k]['utilization']/max(0.05,1-self.links[k]['utilization']) for k in pairs(f['path']))*2,3)
            f['loss_pct']=round(100*f['dropped']/max(f['offered'],0.001),2);f['sla_met']=f['latency'] is not None and f['latency']<=f['max_latency'];f['jitter_estimate']=round((f['latency'] or 0)*0.03,3)
        self.flows=rows
        if dt:self.samples.append(dict(tick=self.tick,**self.metrics()))
    def metrics(self):
        fs=self.flows;offered=sum(f['offered'] for f in fs);delivered=sum(f['delivered'] for f in fs);lat=[f['latency'] for f in fs if f.get('latency') is not None]
        return dict(throughput=round(delivered,3),offered=round(offered,3),loss=round(100*(offered-delivered)/max(offered,0.001),3),latency=round(sum(lat)/len(lat),3) if lat else 0,blocked=round(sum(f['blocked_mbps'] for f in fs),3),shaped=round(sum(f['shaped'] for f in fs),3),healthy_links=sum(e['up'] for e in self.links.values()),peak_utilization=round(max(e['utilization'] for e in self.links.values())*100,2))
    def state(self):
        self.last_seen=time.time()
        return dict(mode='deterministic_digital_twin',revision=self.rev,tick=self.tick,links=list(self.links.values()),hosts=HOSTS,flows=self.flows,rules=self.rules,metrics=self.metrics(),history=[{k:v for k,v in s.items() if k!='config'} for s in self.history],audit=list(self.audit),samples=list(self.samples),settings=dict(autoheal=self.autoheal,proactive=self.proactive,surge=self.surge),forecast_method='8-sample moving average + 5-step trend; not an LSTM',forecast_horizon=5)
