
function bpPill(state){
  const m={
    merged:{cls:'bp-ok',label:'Merged'},
    precaught:{cls:'bp-warn',label:'Pre-PR catch'},
    blocked:{cls:'bp-bad',label:'Blocked at PR'},
    passed:{cls:'bp-ok',label:'✓ Passed'},
    failed:{cls:'bp-bad',label:'✗ Failed'}
  };
  const x=m[state]||{cls:'bp-neutral',label:state};
  return `<span class="bp-pill ${x.cls}">${esc(x.label)}</span>`;
}

function renderBpChain(bp,sid){
  if(sid==='sca'&&bp.dependencyChain){
    const links=bp.dependencyChain.map((name,i)=>{
      const vuln=i===bp.dependencyChain.length-1;
      return `<span class="bp-chain-link ${vuln?'bp-chain-vuln':''}">${esc(name)}</span>`;
    }).join('<span class="bp-chain-sep">›</span>');
    return `<div class="bp-extra"><div class="bp-extra-label">Dependency chain</div><div class="bp-chain">${links}</div><div class="bp-mono">${esc(bp.manifestFile)} → resolved <strong>${esc(bp.resolvedVersion)}</strong></div></div>`;
  }
  if(sid==='container'&&bp.baseImageLineage){
    const links=bp.baseImageLineage.map(row=>{
      const vuln=row.layer===bp.vulnerableLayer;
      return `<span class="bp-chain-link ${vuln?'bp-chain-vuln':''}" title="${esc(row.layer)} layer">${esc(row.name)}</span>`;
    }).join('<span class="bp-chain-sep">›</span>');
    return `<div class="bp-extra"><div class="bp-extra-label">Base image lineage · vuln in <strong>${esc(bp.vulnerableLayer)}</strong> layer</div><div class="bp-chain">${links}</div>${bp.note?`<div class="bp-mono">${esc(bp.note)}</div>`:''}</div>`;
  }
  return '';
}

function renderBuildPipelineCard(e){
  const bp=e.buildPipeline;
  if(!bp) return '';
  const sid=e.scannerId;
  const stages=[
    {icon:'git',title:'Source repo',mono:`${bp.repo.name} · ${bp.repo.branch} · ${bp.repo.commitShort} · ${bp.repo.author} · ${bpAge(bp.repo.ageHours)}`,pill:null},
    {icon:'git',title:'PR / merge status',mono:bp.prStatus.detail+(bp.prStatus.prNumber?` · PR #${bp.prStatus.prNumber}`:''),pill:bpPill(bp.prStatus.state)},
    {icon:'server',title:'Build',mono:`${bp.build.buildId} · ${bpBuildEnvLine(bp.build)} · ${bpAge(bp.build.ageHours)}${bp.build.note?' · '+bp.build.note:''}`,pill:bpPill(bp.build.status)},
    {icon:'package',title:'Artifact',mono:`${bp.artifact.name}${bp.artifact.version?':'+bp.artifact.version:''} · ${bp.artifact.registry} · digest ${bp.artifact.digest}`,pill:null},
    {icon:'container',title:'Registry / artifact store',mono:`${bp.registry.name} · ${bp.registry.path} · ${bp.registry.scanStatus}`,pill:null},
    {icon:'cloud',title:'Deployment trail',mono:`${bp.deployment.tool} ${bp.deployment.app} → ${bp.deployment.cluster} ns ${bp.deployment.namespace} · ${bp.deployment.podCount} pods · ${bp.deployment.syncedAgo}`,pill:null}
  ];
  if(sid!=='container'&&bp.reachability){
    const r=bp.reachability;
    stages.push({icon:'shield',title:'Reachability',mono:r.confirmed?`${r.sensor}: ${r.entryPoint} · ${r.callsPerDay}`:`Not confirmed in prod — ${r.callsPerDay||'sensor offline'}`,pill:bpPill(r.confirmed?'passed':'blocked')});
  }
  const flow=stages.map((st,i)=>`
    <div class="bp-stage">
      <div class="bp-stage-rail">${i>0?'<div class="bp-connector"></div>':''}<div class="bp-dot">${icon(st.icon,14)}</div></div>
      <div class="bp-stage-body">
        <div class="bp-stage-head"><span class="bp-stage-title">${esc(st.title)}</span>${st.pill||''}</div>
        <div class="bp-mono">${esc(st.mono)}</div>
      </div>
    </div>`).join('');
  return `<div class="station-card bp-wide bp-pipeline-card" data-pipeline-card>
    <div class="station-head">${icon('container',14)}<span>Build Pipeline</span></div>
    <div class="bp-flow">${flow}</div>
    ${renderBpChain(bp,sid)}
  </div>`;
}

function renderBuildPipelineDetail(e){
  return renderBuildPipelineCard(e).replace('data-pipeline-card','');
}

function renderStationCards(e){
  const parts=[];
  e.stations.forEach(s=>{
    if(s.k==='buildPipeline') return;
    if(s.k==='asset'&&e.buildPipeline){
      parts.push(`<div class="station-card ${s.scm?'scm-station':''}"><div class="station-head">${icon(s.icon,14)}<span>${esc(s.name)}</span></div>${s.lines.map(l=>`<div class="station-line">${esc(l)}</div>`).join('')}</div>`);
      parts.push(renderBuildPipelineCard(e));
      return;
    }
    parts.push(`<div class="station-card ${s.scm?'scm-station':''} ${s.k==='runtime'?'runtime-station':''}"><div class="station-head">${icon(s.icon,14)}<span>${esc(s.name)}</span></div>${s.lines.map(l=>`<div class="station-line">${esc(l)}</div>`).join('')}</div>`);
  });
  return `<div class="station-grid station-grid-extended">${parts.join('')}</div>`;
}

function stationCountLabel(e){
  const n=e.stations.filter(s=>s.k!=='buildPipeline').length+(e.buildPipeline?1:0);
  return `${n} sources`;
}
