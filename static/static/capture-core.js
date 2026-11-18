/* AETHER capture reader. Header interpretation adapted from pcap-decoder
 * Copyright (c) 2020 Ben Foxall, MIT. See THIRD_PARTY_NOTICES.md.
 * Protocol analysis, bounds, findings and report logic are AETHER additions.
 * No requests, uploads, execution, payload rendering or persistence. */
(function(root){'use strict';
const LIMIT=20*1024*1024, MAXPACKETS=100000;
function analyze(input){
 const a=input instanceof Uint8Array?input:new Uint8Array(input),v=new DataView(a.buffer,a.byteOffset,a.byteLength);
 if(a.length>LIMIT)throw Error('Capture is larger than 20 MB. Export a smaller time range from Wireshark.');
 if(a.length<24)throw Error('This file is too short to be a classic PCAP capture.');
 const m=v.getUint32(0),le=m===0xd4c3b2a1||m===0x4d3cb2a1,ns=m===0xa1b23c4d||m===0x4d3cb2a1;
 if(m===0x0a0d0d0a)throw Error('PCAPNG is not supported in this first version. In Wireshark choose File > Save As > Wireshark/tcpdump/... - pcap. Renaming the extension does not convert it.');
 if(![0xa1b2c3d4,0xd4c3b2a1,0xa1b23c4d,0x4d3cb2a1].includes(m))throw Error('Not a supported classic PCAP file.');
 if(v.getUint16(4,le)!==2||v.getUint16(6,le)!==4)throw Error('Only classic PCAP version 2.4 is supported.');
 const link=v.getUint32(20,le)&65535;
 if(![1,101,113].includes(link))throw Error('Unsupported capture link type '+link+'. Use Ethernet, raw IP or Linux cooked v1. Raw Wi-Fi/radiotap captures are not supported.');
 const r={format:'Classic PCAP 2.4',linkType:link,packets:0,wireBytes:0,capturedBytes:0,ipv4:0,tcp:0,udp:0,other:0,skipped:0,fragmented:0,truncated:0,malformed:0,dnsQueries:0,dnsResponses:0,dnsErrors:0,resets:0,syn:0,start:null,end:null,hosts:[],flows:[],dns:[],findings:[],warnings:[],timeline:[]};
 const hosts=new Map(),flows=new Map(),dns=new Map(),bins=new Map(),label=(ip)=>{if(!hosts.has(ip))hosts.set(ip,{id:'Device '+(hosts.size+1),address:ip,bytes:0,packets:0});return hosts.get(ip);};
 const get16=(b,o)=>(b[o]<<8)|b[o+1];
 let off=24;
 while(off<a.length){
  if(r.packets>=MAXPACKETS)throw Error('More than 100,000 packets. Export a smaller capture. No partial report was produced.');
  if(off+16>a.length)throw Error('Incomplete packet record header. The capture file may be damaged.');
  const sec=v.getUint32(off,le),frac=v.getUint32(off+4,le),cap=v.getUint32(off+8,le),wire=v.getUint32(off+12,le);off+=16;
  if(frac>=(ns?1e9:1e6)||cap>wire||off+cap>a.length)throw Error('Invalid or incomplete packet record at packet '+(r.packets+1)+'. No partial report was produced.');
  const ts=sec+frac/(ns?1e9:1e6),b=a.subarray(off,off+cap);off+=cap;
  r.packets++;r.wireBytes+=wire;r.capturedBytes+=cap;if(cap<wire)r.truncated++;
  r.start=r.start===null?ts:Math.min(r.start,ts);r.end=r.end===null?ts:Math.max(r.end,ts);
  const bin=Math.floor(ts);bins.set(bin,(bins.get(bin)||0)+wire);
  let p=0,eth=0x0800;
  if(link===1){if(cap<14){r.malformed++;continue;}eth=get16(b,12);p=14;let tags=0;while([0x8100,0x88a8].includes(eth)&&tags++<2){if(p+4>cap)break;eth=get16(b,p+2);p+=4;}}
  if(link===113){if(cap<16){r.malformed++;continue;}eth=get16(b,14);p=16;}
  if(eth!==0x0800||p>=cap||b[p]>>4!==4){r.other++;continue;}
  if(p+20>cap){r.malformed++;continue;}
  const ih=(b[p]&15)*4,total=get16(b,p+2);
  if(ih<20||total<ih||p+ih>cap){r.malformed++;continue;}
  r.ipv4++;const end=Math.min(cap,p+total),src=Array.from(b.subarray(p+12,p+16)).join('.'),dst=Array.from(b.subarray(p+16,p+20)).join('.'),proto=b[p+9];
  const h1=label(src),h2=label(dst);h1.bytes+=wire;h1.packets++;h2.bytes+=wire;h2.packets++;
  // Do not decode transport headers of any fragment, including fragment zero.
  if(get16(b,p+6)&0x3fff){r.fragmented++;continue;}
  p+=ih;
  if(proto!==6&&proto!==17){r.skipped++;continue;}
  const min=proto===6?20:8;if(p+min>end){r.malformed++;continue;}
  const sp=get16(b,p),dp=get16(b,p+2),key=[src,sp,dst,dp,proto].join('|');
  if(!flows.has(key))flows.set(key,{source:h1.id,destination:h2.id,src,dst,sourcePort:sp,destinationPort:dp,protocol:proto===6?'TCP':'UDP',packets:0,bytes:0,resets:0});
  const f=flows.get(key);f.packets++;f.bytes+=wire;
  if(proto===6){r.tcp++;const th=(b[p+12]>>4)*4;if(th<20||p+th>end){r.malformed++;continue;}if(b[p+13]&4){r.resets++;f.resets++;}if((b[p+13]&0x12)===2)r.syn++;continue;}
  r.udp++;const ulen=get16(b,p+4);if(ulen<8||p+ulen>p+total-ih){r.malformed++;continue;}
  if(sp!==53&&dp!==53)continue;
  const de=Math.min(end,p+ulen),d=p+8;if(d+12>de){r.malformed++;continue;}
  const flags=get16(b,d+2),resp=!!(flags&0x8000),rcode=flags&15,qd=get16(b,d+4);
  if(resp){r.dnsResponses++;if(rcode)r.dnsErrors++;}else r.dnsQueries++;
  // Read one uncompressed question only. Never display raw payload or interpret markup.
  let name='',q=d+12,ok=qd>0,labels=0;
  while(ok&&q<de&&labels++<128){const n=b[q++];if(n===0)break;if(n>63||q+n>de){ok=false;break;}const part=Array.from(b.subarray(q,q+n)).map(x=>x>=33&&x<=126?String.fromCharCode(x):'?').join('');name+=(name?'.':'')+part;q+=n;if(name.length>253){ok=false;break;}}
  if(q+4>de||!labels||b[q-1]!==0)ok=false;
  const domain=ok&&name?name:'[question not decoded]',dk=domain+'|'+(resp?rcode:'query');
  if(!dns.has(dk))dns.set(dk,{name:domain,response:resp,rcode:resp?rcode:null,count:0});dns.get(dk).count++;
 }
 r.duration=r.start===null?0:r.end-r.start;r.averageMbps=r.duration>0?r.wireBytes*8/r.duration/1e6:null;
 r.hosts=[...hosts.values()].sort((a,b)=>b.bytes-a.bytes);r.flows=[...flows.values()].sort((a,b)=>b.bytes-a.bytes);r.dns=[...dns.values()].sort((a,b)=>b.count-a.count);
 const entries=[...bins.entries()].sort((a,b)=>a[0]-b[0]);
 if(entries.length){const span=entries.at(-1)[0]-entries[0][0]+1,step=Math.max(1,Math.ceil(span/60)),out=new Map();for(const [t,n]of entries){const k=Math.floor((t-entries[0][0])/step);out.set(k,(out.get(k)||0)+n);}for(let k=0;k<=Math.floor((span-1)/step);k++)r.timeline.push({second:k*step,seconds:step,bytes:out.get(k)||0});}
 if(r.dnsErrors)r.findings.push({title:'Some DNS responses report a failure',evidence:r.dnsErrors+' of '+r.dnsResponses+' observed UDP DNS responses have a non-zero response code.',meaning:'Name resolution failed for those responses. NXDOMAIN (3) can be a typo or nonexistent name; SERVFAIL (2) can have several resolver-side causes.',next:'Inspect the affected names and response codes below. Check spelling first; repeat a lookup on the same authorized device. Do not change a shared DNS server from this evidence alone.'});
 if(r.resets)r.findings.push({title:'TCP resets were observed',evidence:r.resets+' reset-flagged TCP packets out of '+r.tcp+' decoded TCP packets.',meaning:'An endpoint or middlebox ended or rejected a connection. Resets can be normal; they do not by themselves prove an attack or root cause.',next:'Match the listed connection, port and time to the application failure. Check service/application logs before changing a firewall.'});
 if(r.flows.length){const f=r.flows[0];r.findings.push({title:'Largest observed directional connection',evidence:f.source+' to '+f.destination+' using '+f.protocol+' port '+f.destinationPort+' accounts for '+f.bytes+' captured-record original bytes.',meaning:'This is the largest connection in this file, not proof it saturated the link. A port number is only a clue, not verified application identity.',next:'Check whether this transfer was expected. Compare with link capacity and a capture covering the complaint before considering a limit.'});}
 if(!r.dnsErrors&&!r.resets)r.findings.unshift({title:'No DNS error codes or TCP resets found in decoded traffic',evidence:r.dnsResponses+' UDP DNS responses and '+r.tcp+' TCP packets decoded.',meaning:'This does not prove the network is healthy. The file may omit the problem or contain unsupported/encrypted traffic.',next:'Capture the time of the problem on your own authorized device and check application logs. DNS-over-HTTPS and DNS-over-TLS are not decoded.'});
 r.warnings.push('Read-only file analysis. No live capture, router changes, decryption, LLM calls, packet-loss estimate, measured bandwidth capacity or automatic fix.');
 if(r.other)r.warnings.push(r.other+' non-IPv4 or unsupported link payload packets are counted in totals but not transport findings (includes IPv6 and ARP).');
 if(r.fragmented)r.warnings.push(r.fragmented+' IPv4 fragments omitted from transport findings; no IP reassembly.');
 if(r.truncated)r.warnings.push(r.truncated+' records have shortened captured data; protocol findings can be incomplete.');
 if(r.malformed)r.warnings.push(r.malformed+' packets have incomplete/invalid supported headers and were not fully decoded.');
 if(!r.packets)r.warnings.push('The file contains no packet records.');
 r.warnings.push('Both endpoints count the same frame in device totals. Connection rows are directional. Original-byte totals come from capture metadata, not physical-wire overhead. Capture loss and duplicate packets are unknown.');
 return r;
}
function publicReport(r,sample=false){return {title:'AETHER capture evidence report',version:1,syntheticSample:sample,format:r.format,packets:r.packets,wireBytes:r.wireBytes,durationSeconds:r.duration,decodedIPv4:r.ipv4,decodedTCP:r.tcp,decodedUDP:r.udp,dnsResponses:r.dnsResponses,dnsErrors:r.dnsErrors,tcpResets:r.resets,findings:r.findings,warnings:r.warnings,flows:r.flows.slice(0,20).map(({src,dst,...f})=>f),privacy:'IP addresses and queried names omitted. Device aliases and ports remain. Review before sharing.'};}
root.AetherCapture={analyze,publicReport,LIMIT};if(typeof module!=='undefined')module.exports=root.AetherCapture;
})(typeof globalThis!=='undefined'?globalThis:this);
