/** Cross-scanner connected vulnerability graph — deploy artifact & host bridges. */

const VULN_DEPLOY_CHAINS = {
  'SCA-001': {
    bridges: [
      {id:'vbg-deploy-sca001', kind:'deploy', label:'transaction-router:v4.2.1', sub:'Container image · JFrog Artifactory'},
      {id:'vbg-host-sca001', kind:'host', label:'adc-payments-01', sub:'Payments edge · internet-facing host'}
    ],
    links: [
      {target:'CON-001', via:'vbg-deploy-sca001', rel:'Same log4j-core in image'},
      {target:'SAST-001', via:'vbg-deploy-sca001', rel:'Shared payments-api codebase'},
      {target:'DAST-003', via:'vbg-host-sca001', rel:'Runtime API on same platform'},
      {target:'NET-015', via:'vbg-host-sca001', rel:'Citrix ADC OS vuln on host'}
    ],
    deployToHost: {from:'vbg-deploy-sca001', to:'vbg-host-sca001', rel:'Deployed to'}
  },
  'CON-001': {
    bridges: [
      {id:'vbg-deploy-con001', kind:'deploy', label:'transaction-router:v4.2.1', sub:'Image layer · log4j-core'},
      {id:'vbg-host-con001', kind:'host', label:'adc-payments-01', sub:'Running workload'}
    ],
    links: [
      {target:'SCA-001', via:'vbg-deploy-con001', rel:'SCA origin in source repo'},
      {target:'NET-015', via:'vbg-host-con001', rel:'Host OS / ADC vulnerability'}
    ],
    deployToHost: {from:'vbg-deploy-con001', to:'vbg-host-con001', rel:'Runs on'}
  },
  'NET-015': {
    bridges: [
      {id:'vbg-host-net015', kind:'host', label:'adc-payments-01', sub:'Citrix ADC · payments edge'},
      {id:'vbg-deploy-net015', kind:'deploy', label:'transaction-router:v4.2.1', sub:'Co-located app workload'}
    ],
    links: [
      {target:'SCA-001', via:'vbg-deploy-net015', rel:'Log4Shell in deployed component'},
      {target:'CON-001', via:'vbg-deploy-net015', rel:'Same image · Trivy match'},
      {target:'DAST-003', via:'vbg-host-net015', rel:'Internet-facing API path'}
    ],
    deployToHost: {from:'vbg-deploy-net015', to:'vbg-host-net015', rel:'Hosted on'}
  },
  'NET-001': {
    bridges: [{id:'vbg-host-net001', kind:'host', label:'pay-db-prod-04', sub:'Database tier · OpenSSL'}],
    links: [{target:'CON-009', via:'vbg-host-net001', rel:'OpenSSL sidecar on same host'}]
  },
  'SAST-001': {
    bridges: [
      {id:'vbg-deploy-sast001', kind:'deploy', label:'payments-api', sub:'Source → deploy artifact'},
      {id:'vbg-host-sast001', kind:'host', label:'api-gateway-prod', sub:'Runtime cluster'}
    ],
    links: [
      {target:'SCA-001', via:'vbg-deploy-sast001', rel:'Shared dependency surface'},
      {target:'DAST-003', via:'vbg-host-sast001', rel:'Same /charge path at runtime'}
    ],
    deployToHost: {from:'vbg-deploy-sast001', to:'vbg-host-sast001', rel:'Shipped to'}
  },
  'DAST-003': {
    bridges: [{id:'vbg-host-dast003', kind:'host', label:'api.acmepay.com', sub:'Internet-facing API'}],
    links: [
      {target:'SAST-001', via:'vbg-host-dast003', rel:'Static code on same path'},
      {target:'SCA-001', via:'vbg-host-dast003', rel:'Loaded vulnerable component'}
    ]
  }
};

const VULN_LANES=[
  {id:'origin', label:'Origin finding', x:0, w:220, color:'#7c3aed'},
  {id:'deploy', label:'Deploy artifact', x:220, w:210, color:'#0891b2'},
  {id:'host', label:'Runtime host', x:430, w:210, color:'#2563eb'},
  {id:'surface', label:'Cross-scanner correlations', x:640, w:420, color:'#ea580c'}
];

function scannerAccent(sid){
  return SCANNERS.find(s=>s.id===sid)?.accent||'#64748b';
}

function isCrossScannerPair(origin, target){
  return !!origin&&!!target&&target.scannerId&&origin.scannerId!==target.scannerId;
}

function buildConnectedVulnGraph(e){
  const nodes=[], edges=[], seenE=new Set();
  const addNode=(n)=>{ if(!nodes.some(x=>x.id===n.id)) nodes.push(n); };
  const addEdge=(from,to,label,type='correlate')=>{
    if(!from||!to) return;
    edges.push({from,to,label:label||'',type});
  };

  addNode({id:e.id, kind:'finding', exp:e, center:true, scannerId:e.scannerId, lane:'origin'});
  seenE.add(e.id);

  const chain=VULN_DEPLOY_CHAINS[e.id];
  const crossScannerLinks=[];
  if(chain){
    chain.links.forEach(l=>{
      const t=ALL_EXPOSURES.find(x=>x.id===l.target);
      if(t&&isCrossScannerPair(e,t)) crossScannerLinks.push(l);
    });
  }

  if(chain&&crossScannerLinks.length){
    chain.bridges.forEach(b=>addNode({id:b.id, kind:b.kind, label:b.label, sub:b.sub, lane:b.kind}));
    const deploy=chain.bridges.find(b=>b.kind==='deploy');
    const host=chain.bridges.find(b=>b.kind==='host');
    if(deploy) addEdge(e.id, deploy.id, 'Introduced in component', 'origin');
    if(chain.deployToHost) addEdge(chain.deployToHost.from, chain.deployToHost.to, chain.deployToHost.rel, 'deploy');
    else if(deploy&&host) addEdge(deploy.id, host.id, 'Runs on', 'deploy');
    crossScannerLinks.forEach(l=>{
      const t=ALL_EXPOSURES.find(x=>x.id===l.target);
      if(!t||seenE.has(t.id)) return;
      addNode({id:t.id, kind:'finding', exp:t, scannerId:t.scannerId, lane:'surface'});
      seenE.add(t.id);
      addEdge(l.via, t.id, l.rel, 'surface');
    });
  }

  (e.crossLinks||[]).forEach(c=>{
    if(seenE.has(c.id)) return;
    const t=ALL_EXPOSURES.find(x=>x.id===c.id);
    if(!t||!isCrossScannerPair(e,t)) return;
    addNode({id:t.id, kind:'finding', exp:t, scannerId:t.scannerId, lane:'surface'});
    seenE.add(c.id);
    addEdge(e.id, c.id, c.desc||`Correlated · ${c.by}`, 'cross');
  });

  const referenced=new Set([e.id]);
  edges.forEach(ed=>{ referenced.add(ed.from); referenced.add(ed.to); });
  const pruned=nodes.filter(n=>referenced.has(n.id));
  const prunedIds=new Set(pruned.map(n=>n.id));
  const prunedEdges=edges.filter(ed=>prunedIds.has(ed.from)&&prunedIds.has(ed.to));

  const correlatedCount=Math.max(0, [...seenE].filter(id=>id!==e.id).length);
  const scanners=[...new Set([...seenE].map(id=>ALL_EXPOSURES.find(x=>x.id===id)?.scannerId).filter(Boolean))];
  const maxScore=Math.max(...[...seenE].map(id=>ALL_EXPOSURES.find(x=>x.id===id)?.score||0), e.score||0);

  const narrative=correlatedCount
    ? (chain&&crossScannerLinks.length
      ? `Cross-scanner correlation chain: this finding links to ${correlatedCount} related exposure${correlatedCount===1?'':'s'} from other scanner silos via shared deploy artifacts and runtime hosts — remediate at the origin to collapse the cluster.`
      : `These findings are correlated across scanner silos (shared asset, code path, or runtime context) — treat as one incident spanning ${scanners.length} scanner type${scanners.length===1?'':'s'}.`)
    : `No correlated findings from other scanners for ${e.id} yet — links appear when the same component, host, or code path is observed across scanner tools.`;

  return {
    nodes:pruned,
    edges:prunedEdges,
    narrative,
    count:seenE.size,
    correlatedCount,
    hasCorrelations:correlatedCount>0,
    scanners:scanners.length,
    maxScore
  };
}

function layoutVulnGraph(graph, centerId){
  const W=1060, H=440, pad=36;
  const placed=new Map();
  const byLane={origin:[], deploy:[], host:[], surface:[]};

  graph.nodes.forEach(n=>{
    if(n.center) byLane.origin.push(n);
    else if(n.kind==='deploy') byLane.deploy.push(n);
    else if(n.kind==='host') byLane.host.push(n);
    else byLane.surface.push(n);
  });

  const laneCenterX={origin:130, deploy:325, host:535, surface:820};
  const placeCol=(list,x,w,h)=>{
    const count=list.length||1;
    const gap=Math.min(96, (H-pad*2-Math.max(...list.map(()=>h),h))/(Math.max(count-1,1)));
    const total=(count-1)*gap+h;
    let y=pad+(H-pad*2-total)/2+h/2;
    list.forEach(node=>{
      placed.set(node.id,{x,y,n:node,w,h});
      y+=gap;
    });
  };

  placeCol(byLane.origin, laneCenterX.origin, 196, byLane.origin[0]?.center?108:92);
  placeCol(byLane.deploy, laneCenterX.deploy, 188, 86);
  placeCol(byLane.host, laneCenterX.host, 188, 86);
  placeCol(byLane.surface, laneCenterX.surface, 196, 92);

  if(placed.size===1){
    const p=[...placed.values()][0];
    p.x=W/2; p.y=H/2;
  }
  return {placed, W, H, pad};
}

function vulnEdgePath(a,b,offset=0){
  const dx=b.x-a.x, dy=b.y-a.y;
  const dist=Math.hypot(dx,dy)||1;
  const nx=-dy/dist, ny=dx/dist;
  const x1=a.x+(a.w||0)/2*Math.sign(dx||1), y1=a.y+offset*ny*0.3;
  const x2=b.x-(b.w||0)/2*Math.sign(dx||1), y2=b.y+offset*ny*0.3;
  const cx1=x1+dx*0.35, cy1=y1+offset*ny*8;
  const cx2=x2-dx*0.35, cy2=y2+offset*ny*8;
  return `M ${x1} ${y1} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${x2} ${y2}`;
}

function vulnGraphNodeHtml(n){
  if(n.kind==='deploy'){
    return `<div class="vg-node vg-node--bridge vg-node--deploy" data-vg-id="${esc(n.id)}">
      <div class="vg-bridge-icon">${icon('container',20)}</div>
      <div class="vg-bridge-body">
        <span class="vg-bridge-kind">Deploy artifact</span>
        <span class="vg-bridge-label">${esc(n.label)}</span>
        <span class="vg-bridge-sub">${esc(n.sub||'')}</span>
      </div>
    </div>`;
  }
  if(n.kind==='host'){
    return `<div class="vg-node vg-node--bridge vg-node--host" data-vg-id="${esc(n.id)}">
      <div class="vg-bridge-icon">${icon('server',20)}</div>
      <div class="vg-bridge-body">
        <span class="vg-bridge-kind">Runtime host</span>
        <span class="vg-bridge-label">${esc(n.label)}</span>
        <span class="vg-bridge-sub">${esc(n.sub||'')}</span>
      </div>
    </div>`;
  }
  const ex=n.exp;
  const sc=SCANNERS.find(s=>s.id===ex.scannerId);
  const accent=scannerAccent(ex.scannerId);
  const flags=[ex.kev?'<span class="vg-flag vg-flag--kev">KEV</span>':'',ex.internet?'<span class="vg-flag vg-flag--net">Internet</span>':''].filter(Boolean).join('');
  return `<div class="vg-node vg-node--finding ${n.center?'is-center':''}" data-vuln-id="${esc(ex.id)}" data-vg-id="${esc(ex.id)}" tabindex="0" role="button" style="--vg-accent:${accent}">
    <div class="vg-finding-accent"></div>
    <div class="vg-finding-head">
      <span class="vg-finding-scanner">${icon(sc?.icon||'shield',15)} ${esc(sc?.short?.split('·')[0]?.trim()||'Finding')}</span>
      <span class="vg-finding-score ${ex.severityClass}">${ex.score.toFixed(1)}</span>
    </div>
    <span class="vg-finding-id">${esc(ex.id)}${ex.cve?` · ${esc(ex.cve)}`:''}</span>
    <span class="vg-finding-title">${esc(ex.title)}</span>
    ${flags?`<div class="vg-finding-flags">${flags}</div>`:''}
  </div>`;
}

function renderConnectedVulnGraph(e){
  const graph=buildConnectedVulnGraph(e);
  if(!graph.hasCorrelations){
    const sc=SCANNERS.find(s=>s.id===e.scannerId);
    return `
    <div class="vuln-graph-wrap vuln-graph-wrap--empty" data-vuln-graph data-center="${esc(e.id)}">
      <div class="vg-top">
        <p class="vg-narrative">${graph.narrative}</p>
        <div class="vg-kpis">
          <div class="vg-kpi"><span class="vg-kpi-val">0</span><span class="vg-kpi-lbl">Cross-scanner links</span></div>
          <div class="vg-kpi"><span class="vg-kpi-val">${esc(sc?.short?.split('·')[0]?.trim()||e.scannerName||'Origin')}</span><span class="vg-kpi-lbl">This scanner only</span></div>
          <div class="vg-kpi vg-kpi--risk"><span class="vg-kpi-val">${e.score.toFixed(1)}</span><span class="vg-kpi-lbl">Exposure score</span></div>
        </div>
      </div>
      <div class="vuln-graph-empty">
        <p>No correlated vulnerabilities from other scanners were found for <strong>${esc(e.id)}</strong>.</p>
        <p class="vuln-graph-empty-hint">Correlations appear when another scanner reports the same component, deploy artifact, runtime host, or code path — see the correlation map for full asset context.</p>
        <a class="diagram-nav-btn diagram-nav-btn--corr" href="${diagramLink(e.id,'correlation')}">View correlation map →</a>
      </div>
    </div>`;
  }

  const {placed,W,H,pad}=layoutVulnGraph(graph,e.id);
  const uid=e.id.replace(/[^a-zA-Z0-9]/g,'');

  const laneBands=VULN_LANES.map((lane,i)=>{
    const rx=lane.x+8, rw=lane.w-16;
    return `<rect x="${rx}" y="${pad-8}" width="${rw}" height="${H-pad*2+16}" rx="14" class="vg-lane vg-lane--${lane.id}" fill="url(#vg-lane-${lane.id}-${uid})"/>
      <text x="${rx+rw/2}" y="${pad+10}" text-anchor="middle" class="vg-lane-label">${esc(lane.label)}</text>`;
  }).join('');

  const edgeGroups={};
  graph.edges.forEach((ed,i)=>{
    const a=placed.get(ed.from), b=placed.get(ed.to);
    if(!a||!b) return;
    const key=ed.type||'correlate';
    if(!edgeGroups[key]) edgeGroups[key]=[];
    const d=vulnEdgePath(a,b,(i%3-1)*12);
    const mx=(a.x+b.x)/2, my=(a.y+b.y)/2-6;
    const lbl=ed.label.length>32?ed.label.slice(0,30)+'…':ed.label;
    const lw=Math.max(44,lbl.length*5.2);
    edgeGroups[key].push(`
      <path d="${d}" class="vg-edge vg-edge--${key}" data-edge-from="${esc(ed.from)}" data-edge-to="${esc(ed.to)}" marker-end="url(#vg-arrow-${key}-${uid})"/>
      ${lbl?`<g class="vg-edge-label" data-edge-from="${esc(ed.from)}" data-edge-to="${esc(ed.to)}">
        <rect x="${mx-lw/2}" y="${my-10}" width="${lw}" height="18" rx="9" class="vg-edge-label-bg"/>
        <text x="${mx}" y="${my+3}" text-anchor="middle" class="vg-edge-label-text">${esc(lbl)}</text>
      </g>`:''}`);
  });

  const edgeSvg=Object.entries(edgeGroups).map(([k,v])=>`<g class="vg-edges vg-edges--${k}">${v.join('')}</g>`).join('');

  const nodeEls=[...placed.values()].map(({x,y,n,w,h})=>{
    return `<foreignObject x="${x-w/2}" y="${y-h/2}" width="${w}" height="${h}" class="vg-fo" data-vg-id="${esc(n.id)}">
      <div xmlns="http://www.w3.org/1999/xhtml">${vulnGraphNodeHtml(n)}</div>
    </foreignObject>`;
  }).join('');

  const kpis=`
    <div class="vg-kpis">
      <div class="vg-kpi"><span class="vg-kpi-val">${graph.correlatedCount}</span><span class="vg-kpi-lbl">Cross-scanner links</span></div>
      <div class="vg-kpi"><span class="vg-kpi-val">${graph.scanners}</span><span class="vg-kpi-lbl">Scanner types</span></div>
      <div class="vg-kpi vg-kpi--risk"><span class="vg-kpi-val">${graph.maxScore.toFixed(1)}</span><span class="vg-kpi-lbl">Peak score</span></div>
    </div>`;

  const legend=`
    <div class="vg-legend">
      <span><i class="vg-leg vg-leg--origin"></i> Origin scanner</span>
      <span><i class="vg-leg vg-leg--deploy"></i> Shared deploy path</span>
      <span><i class="vg-leg vg-leg--surface"></i> Other scanner</span>
      <span><i class="vg-leg vg-leg--cross"></i> Direct correlation</span>
    </div>`;

  return `
    <div class="vuln-graph-wrap" data-vuln-graph data-center="${esc(e.id)}">
      <div class="vg-top">
        <p class="vg-narrative">${graph.narrative}</p>
        ${kpis}
      </div>
      ${legend}
      <div class="vg-canvas-shell">
        <div class="diagram-zoom-controls" data-zoom-controls data-zoom-target="connected">
          <button type="button" data-zoom="out" aria-label="Zoom connected graph out">−</button>
          <button type="button" data-zoom="in" aria-label="Zoom connected graph in">+</button>
          <button type="button" data-zoom-reset aria-label="Reset connected graph zoom">Reset</button>
        </div>
        <div class="diagram-zoom-canvas vg-zoom-canvas" data-zoom-canvas="connected">
          <svg class="vuln-graph-svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" xmlns="http://www.w3.org/2000/svg" aria-label="Connected vulnerabilities for ${esc(e.id)}">
            <defs>
              ${VULN_LANES.map(l=>`<linearGradient id="vg-lane-${l.id}-${uid}" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stop-color="${l.color}" stop-opacity=".09"/>
                <stop offset="100%" stop-color="${l.color}" stop-opacity=".02"/>
              </linearGradient>`).join('')}
              <marker id="vg-arrow-origin-${uid}" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto"><path d="M0,0 L9,4.5 L0,9 Z" fill="#7c3aed"/></marker>
              <marker id="vg-arrow-deploy-${uid}" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto"><path d="M0,0 L9,4.5 L0,9 Z" fill="#0891b2"/></marker>
              <marker id="vg-arrow-surface-${uid}" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto"><path d="M0,0 L9,4.5 L0,9 Z" fill="#ea580c"/></marker>
              <marker id="vg-arrow-cross-${uid}" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto"><path d="M0,0 L9,4.5 L0,9 Z" fill="#64748b"/></marker>
              <filter id="vg-glow-${uid}" x="-20%" y="-20%" width="140%" height="140%">
                <feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="#0891b2" flood-opacity=".15"/>
              </filter>
            </defs>
            <g class="vg-lanes">${laneBands}</g>
            <g class="vg-edge-layer">${edgeSvg}</g>
            <g class="vg-node-layer" filter="url(#vg-glow-${uid})">${nodeEls}</g>
          </svg>
        </div>
      </div>
      <div class="vuln-graph-detail vg-detail-panel" data-vuln-detail>
        <p class="vuln-graph-detail-placeholder">Hover or select a correlated finding from another scanner to highlight the shared deploy → host → surface path.</p>
      </div>
    </div>`;
}

function pathEdgeKeys(graph, fromId, toId){
  if(!fromId||!toId||fromId===toId) return new Set();
  const adj={};
  graph.edges.forEach(ed=>{
    if(!adj[ed.from]) adj[ed.from]=[];
    adj[ed.from].push({to:ed.to, key:`${ed.from}|${ed.to}`});
  });
  const q=[[fromId,[]]], seen=new Set([fromId]);
  while(q.length){
    const [cur,path]=q.shift();
    if(cur===toId) return new Set(path);
    (adj[cur]||[]).forEach(({to,key})=>{
      if(seen.has(to)) return;
      seen.add(to);
      q.push([to,[...path,key]]);
    });
  }
  return new Set();
}

function bindConnectedVulnGraph(panel, e){
  const wrap=panel.querySelector('[data-vuln-graph]');
  const detail=panel.querySelector('[data-vuln-detail]');
  if(!wrap) return;
  const graph=buildConnectedVulnGraph(e);
  const centerId=e.id;

  const highlight=(nodeId)=>{
    const pathKeys=nodeId&&nodeId!==centerId?pathEdgeKeys(graph,centerId,nodeId):new Set();
    const pathNodes=new Set([centerId]);
    pathKeys.forEach(k=>{ const [a,b]=k.split('|'); pathNodes.add(a); pathNodes.add(b); });
    if(nodeId) pathNodes.add(nodeId);

    wrap.querySelectorAll('.vg-node--finding').forEach(n=>{
      const id=n.dataset.vulnId;
      n.classList.toggle('is-selected',id===nodeId);
      n.classList.toggle('is-dim',nodeId&&id!==nodeId&&id!==centerId);
    });
    wrap.querySelectorAll('.vg-edge, .vg-edge-label').forEach(el=>{
      const from=el.dataset.edgeFrom, to=el.dataset.edgeTo;
      const key=`${from}|${to}`;
      const on=nodeId&&(from===nodeId||to===nodeId||pathKeys.has(key));
      el.classList.toggle('is-highlight',!!on);
      el.classList.toggle('is-dim',!!nodeId&&!on);
    });
    wrap.querySelectorAll('.vg-fo').forEach(fo=>{
      const id=fo.dataset.vgId;
      fo.classList.toggle('is-dim',!!nodeId&&!pathNodes.has(id));
    });
  };

  const showDetail=(exp)=>{
    if(!exp||!detail) return;
    highlight(exp.id);
    const sc=SCANNERS.find(s=>s.id===exp.scannerId);
    const chain=VULN_DEPLOY_CHAINS[e.id];
    const pathHint=chain&&graph.hasCorrelations
      ?`Cross-scanner path: component → deploy → host → ${graphCountSurface(exp.id)} correlated finding(s)`
      : 'Direct cross-scanner correlation';
    detail.innerHTML=`
      <div class="vg-detail-card">
        <div class="vg-detail-head">
          <span class="vg-detail-icon" style="color:${scannerAccent(exp.scannerId)}">${icon(sc?.icon||'shield',18)}</span>
          <div>
            <div class="vg-detail-title-row"><strong>${esc(exp.id)}</strong><span class="score-badge ${exp.severityClass}">${exp.score.toFixed(1)}</span></div>
            <div class="vg-detail-scanner">${esc(sc?.name||exp.scannerName)}</div>
          </div>
        </div>
        <p class="vg-detail-desc">${esc(exp.title)}</p>
        <p class="vg-detail-meta">${esc(exp.asset)} · ${esc(exp.owner)} · ${esc(exp.sla)}</p>
        <p class="vg-detail-path">${pathHint}</p>
        <div class="vg-detail-actions">
          <a class="diagram-nav-btn diagram-nav-btn--connected" href="${diagramLink(exp.id,'connected')}">Recenter graph →</a>
          <a class="diagram-nav-btn diagram-nav-btn--corr" href="${diagramLink(exp.id,'correlation')}">Correlation map</a>
          <a class="diagram-nav-btn diagram-nav-btn--attack" href="${triageBackLink(exp.id)}">Triage queue</a>
        </div>
      </div>`;
  };

  function graphCountSurface(id){
    const g=buildConnectedVulnGraph(ALL_EXPOSURES.find(x=>x.id===id)||e);
    return g.correlatedCount;
  }

  wrap.querySelectorAll('.vg-node--finding[data-vuln-id]').forEach(node=>{
    const id=node.dataset.vulnId;
    const exp=ALL_EXPOSURES.find(x=>x.id===id);
    if(!exp) return;
    const activate=()=>showDetail(exp);
    node.onclick=activate;
    node.onmouseenter=()=>highlight(id);
    node.onmouseleave=()=>{ if(!wrap.querySelector('.vg-node--finding.is-selected')) highlight(null); };
    node.onkeydown=ev=>{if(ev.key==='Enter'||ev.key===' '){ev.preventDefault();activate();}};
    if(exp.id===e.id) activate();
  });
}
