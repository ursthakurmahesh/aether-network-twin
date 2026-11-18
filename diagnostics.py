"""Bounded, read-only DNS check. Fixed Google DoH endpoint, never capture data."""
import collections
import datetime
import ipaddress
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

class LookupProblem(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status=status

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise LookupProblem('Resolver redirect refused.', 502)

LOCK=threading.Lock()
CACHE={}
REQUESTS=collections.deque()
SLOTS=threading.BoundedSemaphore(2)
OPENER=urllib.request.build_opener(NoRedirect)

def domain_name(value):
    if not isinstance(value,str) or len(value)>253:
        raise LookupProblem('Enter a public domain name up to 253 characters, not a URL.')
    name=value.strip().rstrip('.').lower()
    if not name.isascii() or not re.fullmatch(r'[a-z0-9.-]+',name):
        raise LookupProblem('Use an ASCII public domain name only, such as example.com. No URLs, ports, paths or IP addresses.')
    labels=name.split('.')
    if len(labels)<2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in labels):
        raise LookupProblem('Domain labels must be 1-63 characters, with no leading/trailing hyphen.')
    if name.endswith(('.local','.localhost','.internal','.lan','.home','.arpa','.test')) or labels[-1].isdigit():
        raise LookupProblem('Private, reverse-lookup and local names are not accepted. Enter a public domain.')
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    raise LookupProblem('IP addresses are not accepted.')

def check_dns(value):
    name=domain_name(value)
    now=time.monotonic()
    with LOCK:
        hit=CACHE.get(name)
        if hit and now-hit[0]<60:
            return dict(hit[1],cached=True)
        while REQUESTS and now-REQUESTS[0]>=60:
            REQUESTS.popleft()
        if len(REQUESTS)>=12:
            raise LookupProblem('DNS check limit reached. Wait one minute before trying again.',429)
        REQUESTS.append(now)
    if not SLOTS.acquire(blocking=False):
        raise LookupProblem('DNS checks are busy. Try again shortly.',429)
    try:
        url='https://dns.google/resolve?'+urllib.parse.urlencode({'name':name,'type':'A','edns_client_subnet':'0.0.0.0/0'})
        request=urllib.request.Request(url,headers={'Accept':'application/dns-json','User-Agent':'AETHER-DNS-check/1.0'})
        try:
            with OPENER.open(request,timeout=5) as response:
                raw=response.read(131073)
            if len(raw)>131072:
                raise LookupProblem('DNS response exceeded the safety limit.',502)
            data=json.loads(raw)
        except LookupProblem:
            raise
        except (OSError,ValueError,urllib.error.URLError):
            raise LookupProblem('Google Public DNS could not be reached or returned invalid data. No result was fabricated. Try again later.',502) from None
        if not isinstance(data,dict) or type(data.get('Status')) is not int or not isinstance(data.get('Answer',[]),list):
            raise LookupProblem('Unexpected DNS API response. No result was fabricated.',502)
        addresses=[]
        for answer in data.get('Answer',[]):
            if isinstance(answer,dict) and answer.get('type')==1:
                try:
                    address=str(ipaddress.IPv4Address(answer.get('data','')))
                    if address not in addresses:addresses.append(address)
                except (ValueError,TypeError):
                    continue
        status=data['Status']
        if status==0 and addresses:
            summary='Public DNS returned IPv4 address records.'
            explanation='The name resolved at Google Public DNS. This does not prove the website is online or your own device can reach it.'
        elif status==0:
            summary='DNS lookup completed, but no IPv4 A answer was returned.'
            explanation='The domain may use IPv6 only or have no A record. This is not the same as a DNS failure.'
        elif status==3:
            summary='Public DNS reports that this name does not exist (NXDOMAIN).'
            explanation='Check the spelling. This describes the public resolver response, not a diagnosis of your local network.'
        else:
            summary='Public DNS returned error code '+str(status)+'.'
            explanation='A DNS error was observed. It can have several causes; compare resolver and application evidence before changing settings.'
        result={'name':name,'query_type':'A','resolver':'Google Public DNS / DNS-over-HTTPS','status':status,'addresses':addresses,'summary':summary,'explanation':explanation,'cached':False,'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'upstream_url':url,'upstream_response':data,'privacy':'Only the entered domain is submitted to Google. Captures are not uploaded.'}
        with LOCK:
            if len(CACHE)>=128:CACHE.pop(next(iter(CACHE)))
            CACHE[name]=(now,result)
        return result
    finally:
        SLOTS.release()
