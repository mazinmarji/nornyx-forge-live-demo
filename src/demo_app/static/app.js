const casesEl=document.querySelector('#cases');
function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));}
function renderCase(c){const stages=(c.timeline||[]).map(s=>`<div class="stage"><strong>${esc(s.stage)}</strong><br>${esc(s.status)}</div>`).join('');return `<article class="case"><div class="case-head"><div><strong>${esc(c.id)}</strong> · ${esc(c.customer)}<div>${esc(c.summary)}</div></div><div class="status ${esc(c.status)}">${esc(c.status)}</div></div><div class="timeline">${stages}</div><div class="reason">${esc(c.decision?.code||'')} ${esc(c.decision?.reason||'')}</div></article>`;}
async function refresh(){const r=await fetch('/api/cases');const d=await r.json();casesEl.innerHTML=d.cases.length?d.cases.reverse().map(renderCase).join(''):'<p>No missions yet.</p>';}
document.querySelector('#runDemo').addEventListener('click',async e=>{e.target.disabled=true;try{await fetch('/api/demo/run',{method:'POST'});await refresh();}finally{e.target.disabled=false;}});
document.querySelector('#refresh').addEventListener('click',refresh);
document.querySelector('#caseForm').addEventListener('submit',async e=>{e.preventDefault();const f=new FormData(e.target);const body=Object.fromEntries(f.entries());await fetch('/api/cases',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});await refresh();});
refresh();
