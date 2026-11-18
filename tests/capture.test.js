'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const C=require('../static/capture-core.js');
// Only extract our deterministic fixture generator, not UI DOM dependencies.
const ui=fs.readFileSync(__dirname+'/../static/capture-ui.js','utf8');
const source=ui.slice(ui.indexOf('function syntheticCapture(){'),ui.indexOf('function display('));
const ctx={Uint8Array,DataView};vm.createContext(ctx);vm.runInContext(source+';this.fixture=syntheticCapture;',ctx);
const sample=new Uint8Array(ctx.fixture());let passed=0;
function test(name,fn){fn();passed++;console.log('PASS '+name);}
function mod(fn){const a=sample.slice();fn(a,new DataView(a.buffer));return a;}
test('fixture facts',()=>{const r=C.analyze(sample);assert.equal(r.packets,22);assert.equal(r.dnsQueries,3);assert.equal(r.dnsResponses,3);assert.equal(r.dnsErrors,3);assert.equal(r.resets,2);assert.equal(r.tcp,16);assert.equal(r.udp,6);assert.equal(r.duration,10.5);assert.equal(r.findings.length,3);});
test('DNS name and NXDOMAIN',()=>{const r=C.analyze(sample);assert.equal(r.dns.find(x=>x.response).rcode,3);assert.equal(r.dns[0].name,'missing.example.invalid');});
test('redacted report',()=>{const r=C.analyze(sample),s=JSON.stringify(C.publicReport(r,true));assert(!s.includes('192.0.2'));assert(!s.includes('198.51.100'));assert(!s.includes('missing.example.invalid'));assert(s.includes('Device '));assert(s.includes('syntheticSample'));});
test('pcapng rejected explicitly',()=>assert.throws(()=>C.analyze(mod((a,v)=>v.setUint32(0,0x0a0d0d0a))),/PCAPNG/));
test('unknown format',()=>assert.throws(()=>C.analyze(new Uint8Array(24)),/Not a supported/));
test('short header',()=>assert.throws(()=>C.analyze(new Uint8Array(5)),/too short/));
test('truncated record fails closed',()=>assert.throws(()=>C.analyze(sample.slice(0,-1)),/incomplete/));
test('dangling record header',()=>{const a=new Uint8Array(sample.length+1);a.set(sample);assert.throws(()=>C.analyze(a),/Incomplete/);});
test('bad captured length',()=>assert.throws(()=>C.analyze(mod((a,v)=>v.setUint32(32,999999,true))),/Invalid/));
test('bad timestamp fraction',()=>assert.throws(()=>C.analyze(mod((a,v)=>v.setUint32(28,1000000,true))),/Invalid/));
test('unsupported link type',()=>assert.throws(()=>C.analyze(mod((a,v)=>v.setUint32(20,127,true))),/link type/));
test('unsupported version',()=>assert.throws(()=>C.analyze(mod((a,v)=>v.setUint16(6,3,true))),/version/));
test('empty valid file',()=>{const r=C.analyze(sample.slice(0,24));assert.equal(r.packets,0);assert.equal(r.averageMbps,null);});
test('big endian header and records',()=>{const a=sample.slice(),v=new DataView(a.buffer);v.setUint32(0,0xa1b2c3d4);for(const p of [4,6]){const n=new DataView(sample.buffer).getUint16(p,true);v.setUint16(p,n);}for(const p of [8,12,16,20])v.setUint32(p,new DataView(sample.buffer).getUint32(p,true));let p=24;while(p<a.length){const n=v.getUint32(p+8,true);for(let j=0;j<16;j+=4)v.setUint32(p+j,new DataView(sample.buffer).getUint32(p+j,true));p+=16+n;}assert.equal(C.analyze(a).packets,22);});
test('nanosecond timestamp variant',()=>{const a=sample.slice(),v=new DataView(a.buffer);v.setUint32(0,0xa1b23c4d,true);let p=24;while(p<a.length){v.setUint32(p+4,v.getUint32(p+4,true)*1000,true);p+=16+v.getUint32(p+8,true);}assert.equal(C.analyze(a).duration,10.5);});
test('fragment omitted from transport',()=>{const a=mod((a,v)=>v.setUint16(40+14+6,0x2000));const r=C.analyze(a);assert.equal(r.fragmented,1);assert.equal(r.dnsQueries,2);});
test('malformed IPv4 handled',()=>{const a=mod(a=>a[40+14]=0x41);assert.equal(C.analyze(a).malformed,1);});
test('oversized capture rejected before parsing',()=>assert.throws(()=>C.analyze(new Uint8Array(C.LIMIT+1)),/20 MB/));
test('bounded random malformed inputs never hang',()=>{for(let n=0;n<300;n++){const a=sample.slice();a[(n*73)%a.length]^=n&255;try{C.analyze(a);}catch(e){assert(e instanceof Error);}}});
fs.writeFileSync(__dirname+'/sample-SYNTHETIC.pcap',sample);
console.log(passed+' capture tests passed');
