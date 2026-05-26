#!/usr/bin/env python3
"""Assemble exposure-dashboard.html from seeds + templates."""
from pathlib import Path

ROOT = Path(__file__).parent
seeds = (ROOT / "_exposure-seeds.js").read_text().replace("window.EXPOSURE_SEEDS", "const EXPOSURE_SEEDS")

APP_JS_BODY = r'''
const SCANNERS = [
  {id:'network',name:'Network / Infrastructure',short:'Tenable · Qualys · Rapid7',icon:'server',accent:'#2563eb',scannerLabel:'Network / Infrastructure Scanner'},
  {id:'sca',name:'SCA — Software Composition',short:'Snyk · Mend · Black Duck',icon:'package',accent:'#0891b2',scannerLabel:'SCA Scanner'},
  {id:'sast',name:'SAST — Static App Security',short:'Checkmarx · Semgrep · Veracode',icon:'code',accent:'#7c3aed',scannerLabel:'SAST Scanner'},
  {id:'dast',name:'DAST & API Security',short:'Burp · ZAP · Salt · Noname',icon:'api',accent:'#ea580c',scannerLabel:'DAST / API Scanner'},
  {id:'container',name:'Container & Image',short:'Trivy · Aqua · Sysdig',icon:'container',accent:'#0d9488',scannerLabel:'Container Scanner'},
  {id:'iac',name:'IaC — Infrastructure as Code',short:'Checkov · KICS · tfsec',icon:'cloud',accent:'#4f46e5',scannerLabel:'IaC Scanner'},
  {id:'cspm',name:'CSPM / CNAPP',short:'Wiz · Orca · Prisma · Defender',icon:'graph',accent:'#16a34a',scannerLabel:'CSPM / CNAPP'},
  {id:'easm',name:'EASM — External Surface',short:'Censys · Randori · Xpanse',icon:'globe',accent:'#be123c',scannerLabel:'EASM Scanner'},
  {id:'secrets',name:'Secrets Scanner',short:'GitGuardian · TruffleHog · GHAS',icon:'key',accent:'#dc2626',scannerLabel:'Secrets Scanner'}
];

const CROSS_LINKS = {
  'SCA-001':[{id:'CON-001',by:'Container Scanner',desc:'Same Log4Shell in image transaction-router:v4.2.1'},{id:'SAST-001',by:'SAST Scanner',desc:'Related code path in payments-api'}],
  'CON-001':[{id:'SCA-001',by:'SCA Scanner',desc:'Same log4j-core — cheapest fix via SCA auto-PR'}],
  'SAST-001':[{id:'SCA-001',by:'SCA Scanner',desc:'Shared payments platform dependency surface'},{id:'DAST-003',by:'DAST Scanner',desc:'Same /charge path exploitable at runtime'}],
  'SAST-003':[{id:'SEC-001',by:'Secrets Scanner',desc:'Hard-coded key in same module'}],
  'SEC-001':[{id:'SAST-003',by:'SAST Scanner',desc:'Secret surfaced in static analysis'}],
  'SEC-006':[{id:'CON-006',by:'Container Scanner',desc:'Secret embedded in image layer'}],
  'CON-006':[{id:'SEC-006',by:'Secrets Scanner',desc:'Credential in build context'}],
  'NET-001':[{id:'CON-009',by:'Container Scanner',desc:'OpenSSL sidecar image on same host'}],
  'DAST-003':[{id:'SAST-001',by:'SAST Scanner',desc:'Same payments-api code path'}]
};

const ICONS = {
  server:`<path d="M4 6a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v4H4V6Z"/><path d="M4 14h16v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-4Z"/>`,
  package:`<path d="m21 16-9 5-9-5V8l9-5 9 5v8Z"/><path d="M12 22V12"/>`,
  code:`<path d="m16 18 6-6-6-6"/><path d="m8 6-6 6 6 6"/><path d="m14.5 4-5 16"/>`,
  api:`<path d="M4 13h5"/><path d="M15 13h5"/><path d="m9 7 3 12 3-12"/>`,
  container:`<path d="M4 7h16v10H4z"/><path d="M4 11h16"/>`,
  cloud:`<path d="M17.5 19H7a5 5 0 1 1 1.1-9.9 7 7 0 0 1 13.4 2.9 3.5 3.5 0 0 1-4 7Z"/>`,
  graph:`<circle cx="6" cy="18" r="2"/><circle cx="18" cy="6" r="2"/><path d="M8 6h8M8 18h8M6 8v8M18 8v8M8 8l8 8"/>`,
  globe:`<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/>`,
  key:`<circle cx="7.5" cy="14.5" r="3.5"/><path d="m10 12 9-9 2 2-1.5 1.5L21 8l-2 2"/>`,
  shield:`<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/>`,
  git:`<path d="M15 6 3 6a3 3 0 0 0-3 3v12a3 3 0 0 0 3 3h12a3 3 0 0 0 3-3V9a3 3 0 0 0-3-3h-4"/><path d="M9 6V3a3 3 0 0 1 6 0v3"/>`,
  chev:`<path d="m9 18 6-6-6-6"/>`
};

const SCM_SCANNERS = new Set(['sca','sast','secrets','container']);
const SCM_PLATFORM = { sca:'GitHub', sast:'GitHub', secrets:'GitHub · GitLab', container:'GitHub Actions → registry' };

function deriveRepo(asset){
  const a=String(asset);
  if (a.includes(' repo')) return a.replace(/\s*repo$/i,'').trim();
  if (a.includes(':')) return a.split(':')[0].trim();
  if (a.includes('/')) return a.split('/').pop().trim();
  return a.replace(/\s*\([^)]*\)/g,'').trim();
}

function scmFileHint(seed, sid){
  const t=seed.title.toLowerCase();
  if (sid==='sast') return t.includes('injection')?'src/.../ChargeController.java':t.includes('xss')?'templates/profile.html':'src/main/...';
  if (sid==='sca') return t.includes('log4')?'pom.xml · log4j-core':'package-lock.json / go.mod';
  if (sid==='secrets') return seed.asset.includes('.py')?seed.asset:seed.asset.includes('workflow')?'.github/workflows/deploy.yml':seed.asset.includes('gist')?'external gist':`.env · ${seed.asset}`;
  if (sid==='container') return seed.asset.includes(':')?`image ${seed.asset}`:'Dockerfile · CI build context';
  return 'manifest / lockfile';
}

function buildScmStation(seed, sid){
  const repo=deriveRepo(seed.asset);
  const orgRepo=`payments-platform/${repo}`.replace(/\/+/g,'/');
  const branch=seed.status==='In progress'?'fix/'+seed.id.toLowerCase():'main';
  const commit=`${seed.id.replace('-','').slice(0,6)}a2f91 · pushed 2d ago`;
  return {
    k:'scm', name:'SCM context', icon:'git', scm:true,
    lines:[
      `Platform: ${SCM_PLATFORM[sid]}`,
      `Repository: ${orgRepo}`,
      `Branch: ${branch} · branch protection on`,
      `Commit / ref: ${commit}`,
      `Path scanned: ${scmFileHint(seed, sid)}`,
      `Trigger: ${seed.tool} · PR gate / push`,
      `CODEOWNERS → ${seed.owner}`
    ]
  };
}

function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;');}
function statusLabel(s){return s==='Compensating control'?'com-ctl':s;}
function icon(name,size=17){return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">${ICONS[name]||ICONS.shield}</svg>`;}

function band(score){if(score>=8)return 'Critical';if(score>=6)return 'High';if(score>=3)return 'Medium';return 'Low';}
function bandClass(b){return ({Critical:'sev-critical',High:'sev-high',Medium:'sev-medium',Low:'sev-low'}[b]);}

const RUNTIME_BY_SCANNER = {
  network:'CrowdStrike Falcon · healthy',
  sca:'Runtime SBOM · package loaded in prod',
  sast:'RASP off · EDR on runner only',
  dast:'WAF rule · partial virtual patch',
  container:'Falco · Sysdig runtime sensor',
  iac:'Drift check · policy guardrail',
  cspm:'CWPP · agentless + Defender',
  easm:'Perimeter IDS · threat feed only',
  secrets:'N/A — rotation required'
};

function buildScoring(seed){
  const s=seed.score;
  const kev=seed.kev?2.0:1.0;
  const epss=seed.kev?0.94:0.42;
  const reach=seed.internet?1.4:1.0;
  const crit=s>=8?2.0:s>=6?1.5:1.0;
  const ctrl=seed.status==='Compensating control'?1.5:seed.status==='Patched'?2.0:1.2;
  const base=5.0;
  const mult=(base*kev*epss*reach*crit/ctrl).toFixed(1);
  return {
    base, result:s.toFixed(1),
    expr:`Base ${base} × KEV ${kev} × EPSS ${epss} × Reach ${reach} × Crit ${crit} ÷ Controls ${ctrl} = ${s.toFixed(1)}`,
    pills:[
      {l:'KEV match',w:seed.kev?'×2.0':'×1.0'},
      {l:'EPSS',w:`×${epss}`},
      {l:'Reach',w:`×${reach}`},
      {l:'Asset crit',w:`×${crit}`},
      {l:'Controls',w:`÷${ctrl}`}
    ]
  };
}

function buildStations(seed, sid){
  const a=seed.asset;
  const net=seed.internet?'Yes — internet-facing':'No — internal only';
  const repo=deriveRepo(a);
  const bp=PIPELINE_SCANNERS.has(sid)?buildBuildPipeline(seed,sid):null;
  const assetLines=PIPELINE_SCANNERS.has(sid)
    ? [`Service / artifact: ${a}`,`Repo trail: see Build Pipeline`,`Environment: prod · correlated via CI/CD`]
    : SCM_SCANNERS.has(sid)
    ? [`Repository (SCM): ${repo}`,`Artifact / service: ${a}`,`Scan scope: default branch + PRs`,`Deployed artifact: prod · correlated via CI`]
    : [`Host / asset: ${a}`,`OS / stack: per CMDB record`,`Location: us-east-1 · prod VPC`,`IP: 10.42.${(seed.id.charCodeAt(4)%200)+.18}.0/24`,net];
  const runtimeLines=[
    `EDR: ${RUNTIME_BY_SCANNER[sid]||'CrowdStrike · Defender'}`,
    `Behavioral rule: ${seed.kev?'IOA template match pending':'No exploit fired'}`,
    `WAF: ${seed.internet?'Coverage on edge ALB':'Not in path'}`,
    `NDR: ${seed.internet?'East-west sensor':'N/A internal'}`
  ];
  if(sid==='container'&&bp){
    runtimeLines.push(`Running: ${bp.artifact.digest} · ${bp.deployment.podCount} pods`);
    runtimeLines.push(`Cluster: ${bp.deployment.cluster} · ${bp.deployment.namespace}`);
    if(bp.reachability){
      const r=bp.reachability;
      runtimeLines.push(r.confirmed?`${r.sensor}: ${r.entryPoint} · ${r.callsPerDay}`:'Reachability: not confirmed in prod');
    }
  }
  const stations=[
    {k:'asset',name:'Asset graph',icon:PIPELINE_SCANNERS.has(sid)?'server':SCM_SCANNERS.has(sid)?'git':'server',lines:assetLines},
    ...(PIPELINE_SCANNERS.has(sid)&&bp?[{k:'buildPipeline',name:'Build Pipeline',icon:'container',isPipeline:true,lines:[`Build ID: ${bp.build.buildId}`,`Environment: ${bp.build.envLabel||bp.build.environment}`,`${bp.build.system} · ${bp.build.agentPool||'agents'} · ${bp.build.region||'—'}`]}]:[]),
    ...(SCM_SCANNERS.has(sid)&&!PIPELINE_SCANNERS.has(sid)?[buildScmStation(seed, sid)]:[]),
    {k:'identity',name:'Identity graph',icon:'shield',lines:[`Service accounts: 2 attached`,`IAM / role: app-runtime-prod`,`Blast radius: S3 read · RDS connect`,`Privileged: ${seed.score>=8?'elevated':'standard'}`]},
    {k:'threat',name:'Threat intel',icon:'shield',lines:[`KEV: ${seed.kev?'Listed · active exploitation':'Not in KEV catalog'}`,`EPSS: ${seed.kev?'0.94':'0.42'} · trending`,`Exploit: ${seed.kev||seed.score>=8?'Public PoC · Metasploit module':'Theoretical only'}`,`Campaign: ${seed.kev?'CISA AA24-131A ref':'None linked'}`]},
    {k:'ownership',name:'Ownership',icon:'git',lines:PIPELINE_SCANNERS.has(sid)||SCM_SCANNERS.has(sid)
      ?[`Owning team: ${seed.owner}`,`CODEOWNERS: /${repo}/** → ${seed.owner}`,`Last author: svc-ci-bot · human: on-call`,`PagerDuty · Slack: #${seed.owner.toLowerCase().replace(/[^a-z0-9]+/g,'-').slice(0,18)}`]
      :[`Team: ${seed.owner}`,`Lead: on-call rotation`,`PagerDuty: ${seed.owner.replace(/ .*/,'').toUpperCase().slice(0,4)}-primary`,`Slack: #${seed.owner.toLowerCase().replace(/[^a-z0-9]+/g,'-').slice(0,20)}`]},
    {k:'business',name:'Business context',icon:'shield',lines:[`App tier: ${seed.score>=8?'Tier 0 — revenue':'Tier 2 — internal'}`,`Data class: ${seed.internet?'PII · payment adjacent':'Internal ops'}`,`Compliance: ${seed.owner.includes('Payment')?'PCI DSS in scope':'SOX logging'}`,`Customer-facing: ${seed.internet?'Yes':'No'}`]},
    {k:'runtime',name:'Runtime controls',icon:'shield',lines:runtimeLines}
  ];
  return stations;
}

function buildOutcomes(seed, sid){
  const o=[];
  const ticket={type:'Patch / change ticket',dest:'Jira',owner:seed.owner,sla:seed.score>=9?'P0':seed.score>=7?'P1':'P2',auto:'Semi'};
  if(sid==='secrets'||seed.title.toLowerCase().includes('secret')||seed.title.toLowerCase().includes('key')){
    o.push({type:'Rotation runbook',dest:'Vault · IAM',owner:seed.owner,sla:'P0',auto:'Auto'});
    o.push({type:'Usage audit + IR',dest:'SIEM · case mgmt',owner:'Incident Response',sla:'P0',auto:'Manual'});
  } else if(sid==='sca'||sid==='sast'){
    o.push({type:'Auto-fix PR',dest:'GitHub',owner:seed.owner,sla:'PR cycle',auto:'Auto'});
    o.push(ticket);
  } else if(sid==='dast'||sid==='network'||sid==='container'){
    o.push({type:'Compensating control',dest:'WAF · EDR · NDR',owner:'SecOps',sla:'P1',auto:'Semi'});
    o.push(ticket);
  } else {
    o.push(ticket);
    if(seed.status==='Compensating control'||seed.score>=7)
      o.push({type:'EDR containment policy',dest:'CrowdStrike console',owner:'SecOps',sla:'P1',auto:'Semi'});
  }
  if(seed.score>=8.5) o.push({type:'Exec visibility',dest:'Risk dashboard',owner:'GRC',sla:'Weekly',auto:'Auto'});
  return o.slice(0,3);
}

function buildTimeline(seed, sid){
  const id=seed.id;
  const repo=deriveRepo(seed.asset);
  const bp=PIPELINE_SCANNERS.has(sid)?buildBuildPipeline(seed,sid):null;
  return [
    ...(bp?[{t:'Build pipeline correlated',d:'2 days ago',by:`${bp.build.system} · ${bp.build.buildId}`}]:[]),
    ...(SCM_SCANNERS.has(sid)&&!PIPELINE_SCANNERS.has(sid)?[{t:'SCM scan completed',d:'2 days ago',by:`${SCM_PLATFORM[sid]} · ${repo}`}]:[]),
    {t:'Scanner detected',d:'2 days ago',by:seed.tool},
    {t:'Correlated & scored',d:'2 days ago',by:'Exposure pipeline'},
    {t:`Ticket ${id.replace('-','')}-4521 opened`,d:'2 days ago',by:'Mobilization'},
    ...(seed.status==='Compensating control'?[{t:'WAF / EDR rule pushed',d:'1 day ago',by:'SecOps'}]:[]),
    ...(seed.status==='In progress'?[{t:'Patch in staging',d:'4h ago',by:seed.owner}]:[]),
    ...(seed.status==='Patched'?[{t:'Verified fixed in prod',d:'1 day ago',by:seed.owner}]:[])
  ];
}

function enrich(seed, scannerId){
  const sc=SCANNERS.find(x=>x.id===scannerId);
  const b=band(seed.score);
  return {...seed,scannerId,scannerName:sc.scannerLabel,accent:sc.accent,
    severity:b,severityClass:bandClass(b),
    crossLinks:CROSS_LINKS[seed.id]||[],
    scoring:buildScoring(seed),stations:buildStations(seed,scannerId),
    buildPipeline:PIPELINE_SCANNERS.has(scannerId)?buildBuildPipeline(seed,scannerId):null,
    outcomes:buildOutcomes(seed,scannerId),timeline:buildTimeline(seed,scannerId),
    scmRepo:SCM_SCANNERS.has(scannerId)?deriveRepo(seed.asset):null};
}

const ALL_EXPOSURES=[];
Object.keys(EXPOSURE_SEEDS).forEach(sid=>{
  EXPOSURE_SEEDS[sid].forEach(seed=>ALL_EXPOSURES.push(enrich(seed,sid)));
});

let activeScanner=0, expandedId=null, focusRow=0;
let filters={q:'',sev:new Set(),status:new Set(),owner:new Set(),kev:false,internet:false};

const app=document.getElementById('app');
const listEl=document.getElementById('exposureList');
const scannerList=document.getElementById('scannerList');

function getFiltered(){
  const sid=SCANNERS[activeScanner].id;
  return ALL_EXPOSURES.filter(e=>{
    if(e.scannerId!==sid) return false;
    if(filters.kev&&!e.kev) return false;
    if(filters.internet&&!e.internet) return false;
    if(filters.sev.size&&!filters.sev.has(e.severity)) return false;
    if(filters.status.size&&!filters.status.has(e.status)) return false;
    if(filters.owner.size&&!filters.owner.has(e.owner)) return false;
    if(filters.q){
      const q=filters.q.toLowerCase();
      const hay=`${e.title} ${e.cve||''} ${e.asset} ${e.scmRepo||''} ${e.owner} ${e.id}`.toLowerCase();
      if(!hay.includes(q)) return false;
    }
    return true;
  }).sort((a,b)=>b.score-a.score);
}

function renderSidebar(){
  scannerList.innerHTML=SCANNERS.map((s,i)=>`
    <button class="scanner-btn ${i===activeScanner?'active':''}" data-i="${i}" type="button" role="option" aria-selected="${i===activeScanner}">
      <span class="scanner-icon" style="color:${s.accent};background:color-mix(in srgb, ${s.accent} 14%, var(--panel-2))">${icon(s.icon)}</span>
      <span style="min-width:0"><span class="scanner-title">${esc(s.name)}</span><span class="scanner-sub">${esc(s.short)}</span></span>
    </button>`).join('');
  scannerList.querySelectorAll('.scanner-btn').forEach(btn=>{
    btn.onclick=()=>{activeScanner=+btn.dataset.i;expandedId=null;focusRow=0;render();};
  });
}

function summaryCounts(rows, total){
  const c={Critical:0,High:0,Medium:0,Low:0};
  rows.forEach(r=>c[r.severity]++);
  return `Showing ${rows.length} of ${total} exposures · ${c.Critical} Critical, ${c.High} High, ${c.Medium} Medium`;
}

function truncate(s,n){const t=String(s);return t.length<=n?t:t.slice(0,n-1)+'…';}
function stationBoxClass(s){
  if(!s) return '';
  if(s.isPipeline||s.k==='buildPipeline') return 'is-pipeline';
  if(s.k==='runtime') return 'is-runtime';
  return '';
}

const CORR_BOX_W=118,CORR_BOX_H=40,CORR_HUB_R=50;
const CORR_TOP_GAP=26;

function corrTopLayout(hasPipeline){
  if(!hasPipeline) return {W:860,H:360,cx:430,cy:188,topY:44,botY:298,topXs:[100,270,440,610],botXs:[220,430,640],topDims:null};
  const topW=108,buildW=124,topH=54,buildH=60,gap=CORR_TOP_GAP;
  const total=4*topW+buildW+4*gap;
  const W=Math.max(1120,total+120);
  const cx=W/2,cy=196,topY=46,botY=306;
  let x=(W-total)/2+topW/2;
  const topXs=[];
  const topDims=[];
  for(let i=0;i<5;i++){
    const isBuild=i===2;
    const w=isBuild?buildW:topW;
    const h=isBuild?buildH:topH;
    topXs.push(x);
    topDims.push({w,h});
    x+=w/2+gap+w/2;
  }
  const botXs=[W*0.26,W*0.5,W*0.74];
  return {W,H:388,cx,cy,topY,botY,topXs,botXs,topDims};
}

function corrBoxAnchor(bx,by,w,h,tcx,tcy){
  const cx=bx+w/2,cy=by+h/2,dx=tcx-cx,dy=tcy-cy;
  if(Math.abs(dx)<1e-6&&Math.abs(dy)<1e-6) return {x:cx,y:cy};
  const scale=Math.min(Math.abs(w/2/dx),Math.abs(h/2/dy));
  return {x:cx+dx*scale,y:cy+dy*scale};
}

function corrHubAnchor(cx,cy,r,tx,ty){
  const dx=tx-cx,dy=ty-cy,len=Math.hypot(dx,dy)||1;
  return {x:cx+(dx/len)*r,y:cy+(dy/len)*r};
}

function corrSpokePath(hx,hy,bx,by){
  const mx=(hx+bx)/2,my=(hy+by)/2;
  return `M ${hx} ${hy} Q ${mx} ${my} ${bx} ${by}`;
}

function corrShortLabel(name){
  return String(name).replace(/ graph$/i,'').replace(/^Business /,'Business ');
}

function renderCorrBox(cx,cy,label,boxCls,wrapAttrs,opts){
  const w=opts?.w||CORR_BOX_W,h=opts?.h||CORR_BOX_H;
  const sub=opts?.sub||'',sub2=opts?.sub2||'';
  const x=cx-w/2,y=cy-h/2;
  const subCls=sub||sub2?' has-sub':'';
  return `<g class="corr-box-wrap" ${wrapAttrs}>
    <foreignObject x="${x}" y="${y}" width="${w}" height="${h}">
      <div xmlns="http://www.w3.org/1999/xhtml" class="corr-box ${boxCls}${subCls}">
        <span class="corr-box-label">${esc(label)}</span>
        ${sub?`<span class="corr-box-sub">${esc(sub)}</span>`:''}
        ${sub2?`<span class="corr-box-sub2">${esc(sub2)}</span>`:''}
      </div>
    </foreignObject>
  </g>`;
}

function renderCorrelationGraph(e){
  const byKey={};
  e.stations.forEach((s,i)=>{byKey[s.k]={...s,idx:i};});
  const uid=e.id.replace(/[^a-zA-Z0-9]/g,'');
  const hasPipeline=PIPELINE_SCANNERS.has(e.scannerId)&&!!byKey.buildPipeline;
  const layout=corrTopLayout(hasPipeline);
  const {W,H,cx,cy,topY,botY,topXs,botXs,topDims}=layout;
  const title=truncate(e.title,20);
  const bpHint=hasPipeline?bpBuildGraphHint(e.buildPipeline):null;

  const topSlots=hasPipeline?[
    {label:'Source',boxCls:'is-source',attrs:'data-finding="1" tabindex="0" role="button" aria-label="Source"'},
    {label:'Asset',station:byKey.asset},
    {label:'Build',station:byKey.buildPipeline,pipelineHint:bpHint},
    {label:'Identity',station:byKey.identity},
    {label:'Runtime',station:byKey.runtime}
  ]:[
    {label:'Source',boxCls:'is-source',attrs:'data-finding="1" tabindex="0" role="button" aria-label="Source"'},
    {label:'Asset',station:byKey.asset},
    {label:'Identity',station:byKey.identity},
    {label:'Runtime',station:byKey.runtime}
  ];
  const botSlots=[
    {label:'Ownership',station:byKey.ownership},
    {label:'Threat intel',station:byKey.threat},
    {label:'Business context',station:byKey.business}
  ];

  const flowLines=[];
  for(let i=0;i<topXs.length-1;i++){
    const w0=topDims?topDims[i].w:CORR_BOX_W;
    const w1=topDims?topDims[i+1].w:CORR_BOX_W;
    flowLines.push(`<line class="corr-flow-line" x1="${topXs[i]+w0/2+6}" y1="${topY}" x2="${topXs[i+1]-w1/2-6}" y2="${topY}" marker-end="url(#corr-flow-${uid})"/>`);
  }

  const allPts=[
    ...topXs.map((x,i)=>({x,y:topY,w:topDims?topDims[i].w:CORR_BOX_W,h:topDims?topDims[i].h:CORR_BOX_H})),
    ...botXs.map(x=>({x,y:botY,w:CORR_BOX_W,h:CORR_BOX_H}))
  ];
  const spokes=allPts.map(pt=>{
    const hub=corrHubAnchor(cx,cy,CORR_HUB_R,pt.x,pt.y);
    const box=corrBoxAnchor(pt.x-pt.w/2,pt.y-pt.h/2,pt.w,pt.h,cx,cy);
    const isRuntime=pt.y===topY&&pt.x===topXs[topXs.length-1];
    const cls=isRuntime?'corr-spoke is-runtime':'corr-spoke';
    return `<path class="${cls}" d="${corrSpokePath(hub.x,hub.y,box.x,box.y)}" marker-end="url(#corr-spoke-${uid})"/>`;
  }).join('');

  const topBoxes=topSlots.map((slot,i)=>{
    const hint=slot.pipelineHint;
    const label=hint?.label||(slot.station?corrShortLabel(slot.station.name):slot.label);
    const boxCls=slot.station?stationBoxClass(slot.station):slot.boxCls;
    const attrs=slot.station
      ?`data-station-idx="${slot.station.idx}" tabindex="0" role="button" aria-label="${esc(slot.station.name)}${hint?.sub?' · '+hint.sub:''}"`
      :slot.attrs;
    const opts=topDims?{w:topDims[i].w,h:topDims[i].h,sub:hint?.sub||'',sub2:hint?.sub2||''}:{};
    return renderCorrBox(topXs[i],topY,label,boxCls,attrs,opts);
  }).join('');

  const botBoxes=botSlots.map((slot,i)=>{
    const st=slot.station;
    const label=st?corrShortLabel(st.name):slot.label;
    const boxCls=st?stationBoxClass(st):'';
    const attrs=st?`data-station-idx="${st.idx}" tabindex="0" role="button" aria-label="${esc(st.name)}"`:'';
    return renderCorrBox(botXs[i],botY,label,boxCls,attrs);
  }).join('');

  const hubFo=`<foreignObject x="${cx-52}" y="${cy-52}" width="104" height="104">
    <div xmlns="http://www.w3.org/1999/xhtml" class="corr-hub-inner">
      <div class="corr-hub-label">Exposure</div>
      <div class="corr-hub-score">${e.score.toFixed(1)}</div>
      <div class="corr-hub-title">${esc(title)}</div>
      <div class="corr-hub-sub">${esc(e.id)}</div>
    </div>
  </foreignObject>`;

  return `<svg class="corr-graph" viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg" aria-label="Correlation graph for ${esc(e.id)}">
    <defs>
      <marker id="corr-flow-${uid}" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z" fill="var(--correlation)"/></marker>
      <marker id="corr-spoke-${uid}" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7 Z" fill="var(--correlation)" opacity=".8"/></marker>
      <filter id="corr-glow-${uid}" x="-50%" y="-50%" width="200%" height="200%"><feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="#2563eb" flood-opacity=".1"/></filter>
      <clipPath id="corr-hub-clip-${uid}"><circle cx="${cx}" cy="${cy}" r="${CORR_HUB_R-2}"/></clipPath>
    </defs>
    <g class="corr-spokes">${spokes}</g>
    <g filter="url(#corr-glow-${uid})">
      <circle cx="${cx}" cy="${cy}" r="${CORR_HUB_R}" fill="var(--panel)" stroke="var(--correlation)" stroke-width="2"/>
      <circle cx="${cx}" cy="${cy}" r="${CORR_HUB_R-8}" class="corr-hub-ring" stroke-width="1"/>
    </g>
    <g class="corr-flow">${flowLines.join('')}</g>
    <g class="corr-boxes">${topBoxes}${botBoxes}</g>
    <g clip-path="url(#corr-hub-clip-${uid})">${hubFo}</g>
  </svg>`;
}

function bindCorrelationPanel(panel, stations, exposure){
  const detailEl=panel.querySelector('.corr-node-detail');
  const sc=SCANNERS.find(x=>x.id===exposure.scannerId);
  const clearSel=()=>panel.querySelectorAll('.corr-box-wrap').forEach(w=>w.classList.remove('selected'));
  const showStation=(idx)=>{
    const s=stations[idx];
    if(!s||!detailEl) return;
    clearSel();
    panel.querySelector(`.corr-box-wrap[data-station-idx="${idx}"]`)?.classList.add('selected');
    if(s.isPipeline||s.k==='buildPipeline'){
      detailEl.innerHTML=`<div class="bp-detail-wrap">${renderBuildPipelineDetail(exposure)}</div>`;
      return;
    }
    const scm=stations.find(x=>x.scm);
    const extra=idx>=0&&stations[idx]?.k==='asset'&&scm&&!exposure.buildPipeline
      ?`<div class="station-line" style="margin-top:8px;font-weight:700;color:var(--accent)">${esc(scm.name)}</div>${scm.lines.map(l=>`<div class="station-line">${esc(l)}</div>`).join('')}`
      :'';
    detailEl.innerHTML=`
      <div class="station-head">${icon(s.icon,14)}<span>${esc(s.name)}</span></div>
      ${s.lines.map(l=>`<div class="station-line">${esc(l)}</div>`).join('')}${extra}`;
  };
  const showFinding=()=>{
    if(!detailEl) return;
    clearSel();
    panel.querySelector('.corr-box-wrap[data-finding]')?.classList.add('selected');
    detailEl.innerHTML=`
      <div class="station-head">${icon(sc?.icon||'shield',14)}<span>Source</span></div>
      <div class="station-line">${esc(exposure.tool)}</div>
      <div class="station-line">${esc(exposure.title)}</div>
      <div class="station-line">${exposure.cve?esc(exposure.cve):`Severity: ${esc(exposure.severity)}`}</div>`;
  };
  const bindWrap=(wrap,fn)=>{
    wrap.onclick=fn;
    wrap.onkeydown=ev=>{if(ev.key==='Enter'||ev.key===' '){ev.preventDefault();fn();}};
  };
  panel.querySelectorAll('.corr-box-wrap[data-station-idx]').forEach(w=>{
    bindWrap(w,()=>showStation(+w.dataset.stationIdx));
  });
  const finding=panel.querySelector('.corr-box-wrap[data-finding]');
  if(finding) bindWrap(finding,showFinding);
  const assetIdx=stations.findIndex(s=>s.k==='asset');
  if(assetIdx>=0) showStation(assetIdx);
  else if(stations.length) showStation(0);
  else showFinding();
  panel.querySelectorAll('[data-corr-view]').forEach(btn=>{
    btn.onclick=()=>{
      const v=btn.dataset.corrView;
      panel.querySelectorAll('[data-corr-view]').forEach(b=>b.classList.toggle('on',b.dataset.corrView===v));
      panel.querySelector('.corr-graph-panel').hidden=v!=='graph';
      panel.querySelector('.corr-cards-panel').hidden=v!=='cards';
    };
  });
}

function renderDetail(e){
  const corrSub=e.buildPipeline?` · pipeline: ${esc(e.buildPipeline.repo.name)}`:e.scmRepo?` · SCM: ${esc(e.scmRepo)}`:'';
  const pills=e.scoring.pills.map(p=>`<span class="score-pill">${esc(p.l)} <strong>${esc(p.w)}</strong></span>`).join('');
  const outs=e.outcomes.map(o=>`
    <div class="outcome-card">
      <div class="outcome-type">${esc(o.type)}</div>
      <a class="outcome-dest" href="#">${esc(o.dest)}</a>
      <div class="outcome-meta">${esc(o.owner)} · ${esc(o.sla)} · <span class="auto-pill">${esc(o.auto)}</span></div>
    </div>`).join('');
  const tl=e.timeline.map(t=>`
    <div class="tl-item"><div class="tl-dot"></div><div><strong>${esc(t.t)}</strong> — ${esc(t.d)}<span class="tl-sub">${esc(t.by)}</span></div></div>`).join('');
  const cross=e.crossLinks.length?`<div class="cross-links-strip"><span class="cross-links-label">Also found by</span>${e.crossLinks.map(c=>{
    const t=ALL_EXPOSURES.find(x=>x.id===c.id);
    const scanner=SCANNERS.find(s=>s.id===t?.scannerId);
    return `<button type="button" class="cross-link-btn" data-jump="${c.id}">${icon(scanner?.icon||'shield',14)}<span class="cross-id">${c.id}</span><span class="cross-by">${esc(c.by)}</span><span class="cross-desc">${esc(c.desc||t?.title||'')}</span></button>`;
  }).join('')}</div>`:'';
  return `
    <div class="detail-panel" id="detail-${e.id}">
      <div class="detail-head">
        <div>
          <div class="detail-title">${esc(e.title)}</div>
          <div class="detail-meta">${e.cve?`<span>${esc(e.cve)}</span> · `:''}<span>${esc(e.scannerName)}</span> · <span>${esc(e.tool)}</span> · <span class="${e.severityClass}">${e.severity}</span></div>
          ${cross}
        </div>
        <div class="detail-score-block">
          <div class="detail-score ${e.severityClass}">${e.score.toFixed(1)}</div>
          <div class="detail-expr">${esc(e.scoring.expr)}</div>
        </div>
        <button type="button" class="detail-close" aria-label="Close detail" data-close>&times;</button>
      </div>
      <div class="detail-section corr-panel" data-exp-id="${e.id}">
        <div class="corr-section-head">
          <h4>Correlation breakdown (${stationCountLabel(e)}${corrSub})</h4>
          <div class="corr-view-toggle">
            <button type="button" class="corr-view-btn on" data-corr-view="graph">Graph</button>
            <button type="button" class="corr-view-btn" data-corr-view="cards">Cards</button>
          </div>
        </div>
        <div class="corr-graph-wrap corr-graph-panel">${renderCorrelationGraph(e)}<div class="corr-node-detail"></div></div>
        <div class="corr-cards-panel" hidden>${e.buildPipeline?renderStationCards(e):`<div class="station-grid">${e.stations.map(s=>`<div class="station-card ${s.scm?'scm-station':''}"><div class="station-head">${icon(s.icon,14)}<span>${esc(s.name)}</span></div>${s.lines.map(l=>`<div class="station-line">${esc(l)}</div>`).join('')}</div>`).join('')}</div>`}</div>
      </div>
      <div class="detail-section"><h4>Scoring formula</h4><div class="formula-chain">${pills}<span class="formula-eq">= ${e.score.toFixed(1)}</span></div></div>
      <div class="detail-section"><h4>Mobilization plan</h4><div class="outcome-row">${outs}</div></div>
      <div class="detail-section"><h4>Activity</h4><div class="timeline">${tl}</div></div>
    </div>`;
}

function renderList(){
  const sid=SCANNERS[activeScanner].id;
  const total=ALL_EXPOSURES.filter(e=>e.scannerId===sid).length;
  const rows=getFiltered();
  document.getElementById('summaryLine').textContent=summaryCounts(rows,total);
  document.getElementById('mainTitle').textContent='Exposure triage queue';
  document.getElementById('mainSub').textContent=SCANNERS[activeScanner].name+' — prioritized after correlation & scoring';
  document.documentElement.style.setProperty('--accent',SCANNERS[activeScanner].accent);

  listEl.innerHTML=rows.map((e,i)=>{
    const open=expandedId===e.id;
    const slaCls=e.sla.includes('Overdue')?'sla-overdue':e.sla.includes('h left')?'sla-urgent':'';
    return `
    <div class="exp-wrap ${open?'open':''}" data-id="${e.id}">
      <div class="exp-row ${i===focusRow?'focused':''}" role="button" tabindex="0" aria-expanded="${open}" aria-label="Exposure ${e.id} score ${e.score}" data-row="${e.id}">
        <span class="score-badge ${e.severityClass}">${e.score.toFixed(1)}</span>
        <span class="col-title">${esc(e.title)}</span>
        <span class="col-asset">${esc(e.asset)}${e.scmRepo?`<span class="col-scm">${esc(e.scmRepo)} · SCM</span>`:''}</span>
        <span class="col-kev">${e.kev?'<span class="kev-pill">KEV</span>':''}</span>
        <span class="col-owner">${esc(e.owner)}</span>
        <span class="col-status"><span class="status-pill status-${e.status.replace(/\s+/g,'-').toLowerCase()}" title="${esc(e.status)}">${esc(statusLabel(e.status))}</span></span>
        <span class="col-sla ${slaCls}">${esc(e.sla)}</span>
        <span class="col-chev">${icon('chev',16)}</span>
      </div>
      ${open?renderDetail(e):''}
    </div>`;
  }).join('') || '<div class="empty">No exposures match filters.</div>';

  listEl.querySelectorAll('.exp-row').forEach(row=>{
    const id=row.dataset.row;
    const toggle=()=>{expandedId=expandedId===id?null:id;renderList();};
    row.onclick=toggle;
    row.onkeydown=ev=>{if(ev.key==='Enter'||ev.key===' '){ev.preventDefault();toggle();}};
  });
  listEl.querySelectorAll('[data-close]').forEach(b=>b.onclick=()=>{expandedId=null;renderList();});
  listEl.querySelectorAll('[data-jump]').forEach(b=>b.onclick=()=>{
    const t=ALL_EXPOSURES.find(x=>x.id===b.dataset.jump);
    if(!t) return;
    activeScanner=SCANNERS.findIndex(s=>s.id===t.scannerId);
    expandedId=t.id; render();
  });
  listEl.querySelectorAll('.corr-panel').forEach(panel=>{
    const exp=ALL_EXPOSURES.find(x=>x.id===panel.dataset.expId);
    if(exp) bindCorrelationPanel(panel, exp.stations, exp);
  });
}

function renderChips(){
  const sid=SCANNERS[activeScanner].id;
  const rows=ALL_EXPOSURES.filter(e=>e.scannerId===sid);
  const owners=[...new Set(rows.map(r=>r.owner))].sort();
  const chipHost=document.getElementById('filterChips');
  const mk=(label,set,val)=>`<button type="button" class="chip ${set.has(val)?'on':''}" data-kind="${label}" data-val="${esc(val)}" title="${label==='status'?esc(val):''}">${esc(label==='status'?statusLabel(val):val)}</button>`;
  chipHost.innerHTML=`
    <span class="chip-group">Severity ${['Critical','High','Medium','Low'].map(s=>mk('sev',filters.sev,s)).join('')}</span>
    <span class="chip-group">Status ${['Open','In progress','Compensating control','Patched','Risk accepted'].map(s=>mk('status',filters.status,s)).join('')}</span>
    <span class="chip-group">Owner ${owners.slice(0,5).map(o=>mk('owner',filters.owner,o)).join('')}</span>
    <button type="button" class="chip toggle ${filters.kev?'on':''}" data-toggle="kev">KEV only</button>
    <button type="button" class="chip toggle ${filters.internet?'on':''}" data-toggle="internet">Internet-facing</button>
    <button type="button" class="chip clear" data-clear>Clear filters</button>`;
  chipHost.querySelectorAll('.chip[data-kind]').forEach(c=>{
    c.onclick=()=>{
      const kind=c.dataset.kind; const val=c.dataset.val;
      const set=filters[kind];
      if(set.has(val)) set.delete(val); else set.add(val);
      renderChips(); renderList();
    };
  });
  chipHost.querySelectorAll('[data-toggle]').forEach(c=>{
    c.onclick=()=>{filters[c.dataset.toggle]=!filters[c.dataset.toggle]; renderChips(); renderList();};
  });
  chipHost.querySelectorAll('[data-clear]').forEach(c=>{
    c.onclick=()=>{filters={q:'',sev:new Set(),status:new Set(),owner:new Set(),kev:false,internet:false};
      document.getElementById('searchInput').value=''; renderChips(); renderList();};
  });
}

function render(){renderSidebar();renderChips();renderList();}

document.getElementById('searchInput').oninput=e=>{filters.q=e.target.value;renderList();};
document.getElementById('themeToggle').onclick=()=>{
  const t=app.dataset.theme==='dark'?'light':'dark';
  app.dataset.theme=t; document.documentElement.dataset.theme=t;
  try{localStorage.setItem('em-theme',t);}catch(e){}
};
try{const s=localStorage.getItem('em-theme');if(s){app.dataset.theme=s;document.documentElement.dataset.theme=s;}}catch(e){}

document.addEventListener('keydown',e=>{
  const rows=getFiltered();
  if(!rows.length) return;
  if(e.key==='Escape'){expandedId=null;renderList();return;}
  if(e.key==='ArrowDown'){e.preventDefault();focusRow=Math.min(focusRow+1,rows.length-1);if(expandedId)expandedId=rows[focusRow].id;renderList();return;}
  if(e.key==='ArrowUp'){e.preventDefault();focusRow=Math.max(focusRow-1,0);if(expandedId)expandedId=rows[focusRow].id;renderList();return;}
  if(e.key==='Enter'&&document.activeElement?.classList.contains('exp-row')){
    const id=document.activeElement.dataset.row; expandedId=expandedId===id?null:id; renderList();
  }
});

render();
'''

APP_JS = (
    (ROOT / "_build-pipeline.js").read_text()
    + "\n"
    + (ROOT / "_pipeline-ui.js").read_text()
    + "\n"
    + APP_JS_BODY
)

CSS = open(ROOT / "_dashboard_css.txt").read() if (ROOT / "_dashboard_css.txt").exists() else ""

# inline CSS if file missing - write css in same script
if not CSS:
    CSS = (ROOT / "exposure-dashboard.css").read_text() if (ROOT / "exposure-dashboard.css").exists() else ""

HTML = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Exposure Management · Analyst Dashboard</title>
<style>
{CSS}
</style>
</head>
<body>
<div class="app" id="app" data-theme="light">
<aside class="sidebar" aria-label="Scanner filter">
<div class="brand"><h1>Exposure Management</h1><a class="sibling-link" href="vulnerability-scanner-journey-explorer_4.html">← Process view</a></div>
<div class="scanner-list" id="scannerList" role="listbox"></div>
<div class="sidebar-footer"><button class="theme-toggle" id="themeToggle" type="button">Toggle dark mode</button></div>
</aside>
<main class="main">
<div class="disclaimer" role="note"><strong>All exposures, scores, owners, and remediation data shown are illustrative examples only.</strong> This dashboard is for visualization purposes and does not reflect real findings.</div>
<header class="topbar"><div><h2 id="mainTitle">Exposure triage queue</h2><p id="mainSub"></p></div></header>
<div class="filter-bar">
<input type="search" id="searchInput" placeholder="Filter by CVE, asset, owner…" aria-label="Filter exposures"/>
<div class="filter-chips" id="filterChips"></div>
<div class="summary-line" id="summaryLine"></div>
</div>
<div class="list-head" aria-hidden="true">
<span>Score</span><span>Finding</span><span>Asset</span><span></span><span>Owner</span><span>Status</span><span>SLA</span><span></span>
</div>
<div class="list-scroll" id="exposureList" role="list" aria-label="Exposure list"></div>
</main>
</div>
<script>
{seeds}
{APP_JS}
</script>
</body>
</html>
'''

# Write CSS file first
if not (ROOT / "exposure-dashboard.css").exists():
    pass

(ROOT / "exposure-dashboard.html").write_text(HTML)
print("Wrote exposure-dashboard.html", len(HTML), "bytes")
