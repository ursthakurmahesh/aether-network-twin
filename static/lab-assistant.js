/* Separate from translator. Gemini cannot invoke policy actions. */
(()=>{
'use strict';let reviewed=null,receipt=null,asking=false,reviewing=false;
const el=id=>document.getElementById(id);
function status(s){el('lab-status').textContent=s;}
function enabled(){el('lab-ask').disabled=asking||reviewing||!reviewed||!el('lab-consent').checked;el('lab-review').disabled=asking||reviewing;el('lab-download').disabled=!receipt;}
function node(tag,text){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;return n;}
function snapshotLabel(b){return 'Revision '+b.revision+', model step '+b.tick;}
el('lab-review').onclick=async()=>{if(asking||reviewing)return;reviewing=true;reviewed=null;el('lab-consent').checked=false;enabled();status('Loading a fresh server snapshot...');try{reviewed=await api('lab-context');el('lab-context').textContent=JSON.stringify(reviewed,null,2);el('lab-consent').checked=false;status('Reviewed '+snapshotLabel(reviewed)+'. Snapshot expires after two minutes. Review again after any configuration change.');}catch(e){reviewed=null;status(e.message);}finally{reviewing=false;enabled();}};
el('lab-consent').onchange=enabled;
el('lab-ask').onclick=async()=>{
 if(!reviewed||!el('lab-consent').checked||asking)return;
 asking=true;receipt=null;el('lab-output').replaceChildren();enabled();status('Asking Google Gemini about '+snapshotLabel(reviewed)+'... The simulation continues while it answers.');
 try{
  const result=await api('lab-assistant',{question:el('lab-question').value,consent:true,revision:reviewed.revision});receipt=result;
  const out=el('lab-output'),b=result.snapshot,ev=new Map(b.evidence.map(e=>[e.id,e]));
  out.append(node('h3',result.provider+' / '+result.model),node('p',snapshotLabel(b)+' · '+result.generated_at),node('p',result.analysis.answer));
  for(const h of result.analysis.hypotheses){const card=node('article');card.className='guide-note';card.append(node('h3',h.title),node('p',h.explanation));for(const id of h.evidenceIds){const d=node('details'),sum=node('summary',id+': '+ev.get(id).kind);d.append(sum,node('pre',JSON.stringify(ev.get(id).data,null,2)));card.append(d);}card.append(node('p','Cannot prove: '+h.cannotProve),node('p','Next check: '+h.nextCheck));out.append(card);}
  for(const suggestion of result.analysis.suggestions){const c=b.candidates.find(c=>c.id===suggestion.candidateId);const card=node('div');card.className='guide-note';card.append(node('h3','Optional experiment: '+c.intent),node('p',suggestion.reason));const btn=node('button','Fill intent box - nothing applied');btn.className='secondary';btn.onclick=()=>{el('intent').value=c.intent;el('source').value='offline';el('source').dispatchEvent(new Event('change'));changeTab('overview');status('Filled a local offline intent. Use Validate & preview, inspect trade-offs, then explicitly approve if wanted.');};card.append(btn,node('p','Validated as a candidate at the snapshot revision only. Live preview may reject it if state changed.'));out.append(card);}
  out.append(node('p',result.notice));
  status('Answered for '+snapshotLabel(b)+'. This is a historical snapshot, not a live diagnosis. Review again for newer state.');
 }catch(e){status('No AI answer: '+e.message+' Offline controls are unchanged.');}
 finally{asking=false;enabled();}
};
el('lab-download').onclick=()=>{if(!receipt)return;const blob=new Blob([JSON.stringify(receipt,null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),a=node('a');a.href=url;a.download='aether-lab-assistant-receipt.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
})();
