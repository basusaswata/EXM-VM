/** Full-page correlation map & attack path for a single exposure. */

let diagramExpId=null;
let diagramView='correlation';

function initDiagramFromUrl(){
  const params=new URLSearchParams(location.search);
  const fromUrl=params.get('scanner');
  let p=fromUrl;
  if(!p){try{p=sessionStorage.getItem('em-active-scanner');}catch(e){}}
  if(p){
    const i=SCANNERS.findIndex(s=>s.id===p);
    if(i>=0) activeScanner=i;
  }
  diagramExpId=params.get('exp');
  const v=params.get('view');
  if(v==='attack'||v==='correlation'||v==='mobilization'||v==='connected') diagramView=v;
}

function syncDiagramNavLinks(exp){
  persistScanner();
  const back=document.getElementById('diagramBackLink');
  if(back){
    back.setAttribute('href',triageBackLink(exp?.id));
    back.textContent=exp?'← Back to '+exp.id:'← Back to triage';
  }
  const side=document.getElementById('triageSidebarLink');
  if(side) side.setAttribute('href',triageBackLink(exp?.id));
}

function renderDiagramPage(){
  const host=document.getElementById('diagramPageHost');
  if(!host) return;
  const exp=ALL_EXPOSURES.find(x=>x.id===diagramExpId);
  if(!exp){
    host.innerHTML='<div class="diagram-empty">Exposure not found. <a href="'+triageBackLink()+'">Return to triage queue</a></div>';
    syncDiagramNavLinks(null);
    renderSidebar();
    return;
  }
  const si=SCANNERS.findIndex(s=>s.id===exp.scannerId);
  if(si>=0) activeScanner=si;
  document.documentElement.style.setProperty('--accent',SCANNERS[activeScanner].accent);
  syncDiagramNavLinks(exp);
  renderSidebar();
  document.querySelectorAll('.scanner-list [data-i]').forEach(btn=>{
    btn.onclick=()=>{
      activeScanner=+btn.dataset.i;
      persistScanner();
      location.href='exposure-dashboard.html'+scannerQuery();
    };
  });
  const meta=document.getElementById('diagramExpMeta');
  if(meta){
    meta.innerHTML=`<span class="diagram-exp-id">${esc(exp.id)}</span><span class="diagram-exp-title">${esc(exp.title)}</span><span class="score-badge ${exp.severityClass}">${exp.score.toFixed(1)}</span>`;
  }
  const sub=document.getElementById('diagramPageSub');
  if(sub) sub.textContent=SCANNERS[activeScanner].name+' · '+exp.severity+' · '+exp.owner;
  host.innerHTML=renderDiagramPanelHtml(exp);
  const panel=host.querySelector('.corr-panel');
  if(panel) bindCorrelationPanel(panel,exp.stations,exp,diagramView);
  const chatHost=document.getElementById('aiChatHost');
  if(chatHost){
    chatHost.innerHTML=renderAiExplainChat(exp);
    bindAiExplainChat(chatHost,exp);
  }
}
