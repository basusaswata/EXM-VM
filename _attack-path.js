/** Horizontal attack-path graph (lateral-movement style) per exposure. */

function pathHash(s){
  let h=0;
  for(let i=0;i<s.length;i++) h=((h<<5)-h+s.charCodeAt(i))|0;
  return Math.abs(h);
}

function shortHost(e){
  const h=e.host||e.asset;
  if(!h) return 'asset';
  return String(h).split('.')[0].slice(0,22);
}

function shortAsset(e){
  const a=String(e.asset);
  if(a.length<=28) return a;
  return a.slice(0,26)+'…';
}

function buildAttackPath(e){
  const h=pathHash(e.id);
  const meta=seedMeta(e);
  const host=shortHost(e);
  const crown=e.scannerId==='network'?'rds-payments-primary':e.scannerId==='sca'||e.scannerId==='container'?'cardholder-data-store':e.scannerId==='cspm'?'pci-audit-logs':e.scannerId==='secrets'?'prod-aws-account':'payments-ledger';
  const crownLabel=e.scannerId==='network'?'RDS payments':e.scannerId==='dast'?'Customer PII API':e.scannerId==='sast'?'Ledger DB':e.scannerId==='iac'?'PCI S3 bucket':e.scannerId==='easm'?'Shadow admin API':e.scannerId==='secrets'?'IAM admin plane':'Crown jewel';

  const mk=(id,type,icon,label,sub,stage,info,evidence)=>({id,type,icon,label,sub,stage,info,evidence});

  if(e.scannerId==='network'){
    const svc=`svc-${host.replace(/^pay-/,'').slice(0,10)}`;
    const nodes=[
      mk('ap0','entry','globe','Public Internet','0.0.0.0','Reconnaissance','Entry point for opportunistic and targeted scans against acmepay perimeter.',[`Scanner: ${e.tool}`,`${e.discovered} discovery`]),
      mk('ap1','exposed','server',host,meta.ip||'10.42.x.x','Initial Access',`Vulnerable host where ${e.cve||'finding'} was detected.`,[`${e.cve||e.title}`,`Plugin ${meta.plugin||'—'}`,`KEV: ${e.kev?'yes':'no'}`]),
      mk('ap2','actor','user',svc,`TENANT\\${svc}`,'Credential Access',`Service account running on ${host} — lateral movement pivot.`,[`Instance profile attached`,`${2+(h%3)} wildcards in policy`]),
      mk('ap3','group','shield','Domain Admins','AD security group','Privilege Escalation','Group membership path discovered via bloodhound-style graph.',[`'${svc}' effective admin path`,`Hop count: ${2+(h%2)}`]),
      mk('ap4','crown','database',crownLabel.split(' ')[0]||'RDS',meta.ip?.replace(/\d+$/,'200')||'10.10.10.200','Impact',`Tier-0 datastore reachable after host compromise.`,[`CMDB: ${meta.cmdb}`,`Tier 0 · PCI in scope`]),
      mk('ap5','exit','globe','Data exfiltration','HTTPS egress','Exfiltration','Outbound channel if attacker establishes C2 or bulk export.',[`DLP: ${e.internet?'alerting':'monitoring'}`,`NetFlow to external`])
    ];
    const narrative=`An attacker on the <strong>public internet</strong> can reach <strong>${esc(host)}</strong> by exploiting <strong>${esc(e.cve||e.title)}</strong>, harvest credentials for <strong>${esc(svc)}</strong>, escalate via privileged groups, and access <strong>${esc(crownLabel)}</strong> for data exfiltration over HTTPS.`;
    return {narrative, nodes, edges:edgeChain(nodes,['Scan / exploit','Control service','Member of','Lateral move','Query / export','HTTPS exfil']),findings:1+(e.crossLinks?.length||0)};
  }

  if(e.scannerId==='sca'){
    const repo=deriveRepo(e.asset);
    const img=e.assetDeploy||e.asset.split(':').pop()||'app-image';
    const nodes=[
      mk('ap0','entry','globe','Threat actor','Supply chain','Reconnaissance','Attacker targets dependency in software supply chain.',[`EPSS ${(e.epss??0.9).toFixed(2)}`]),
      mk('ap1','exposed','git',repo,`${ORG}/${repo}`,'Dependency flaw',`Vulnerable package introduced in source — ${e.cve||'CVE'}.`,[`${e.cve||e.title}`,`Reachable in call graph`]),
      mk('ap2','actor','flow','CI build',e.buildPipeline?.build?.buildId||`build-${1200+(h%800)}`,'Build','Pipeline packages vulnerable dependency into artifact.',[`${e.buildPipeline?.build?.system||'Jenkins'}`,`Commit ${e.commit||'—'}`]),
      mk('ap3','resource','container',img,e.buildPipeline?.artifact?.digest?.slice(0,18)||'sha256:…','Deploy artifact','Image running in production cluster.',[`${e.buildPipeline?.deployment?.cluster||'eks-prod-use1'}`,`${e.buildPipeline?.deployment?.podCount||12} pods`]),
      mk('ap4','crown','database',crownLabel,'In-cluster','Impact',`Loaded vulnerable library serves payment traffic.`,[`Runtime SBOM match`,`Jira ${e.jira||meta.jira}`]),
      mk('ap5','exit','zap','Exploit attempt','KEV / EPSS','Exploitation',`Active exploitation risk if JNDI or RCE chain succeeds.`,[`KEV: ${e.kev?'listed':'—'}`,`WAF ${e.internet?'compensating':''}`])
    ];
    const narrative=`An attacker can chain <strong>${esc(e.cve||'the vulnerable dependency')}</strong> from <strong>${esc(repo)}</strong> through the <strong>CI/CD pipeline</strong> into <strong>${esc(img)}</strong> running in prod, then reach <strong>${esc(crownLabel)}</strong> via the payments API path.`;
    return {narrative, nodes, edges:edgeChain(nodes,['Poison dep','Merge / build','Push image','Deploy pods','Invoke vuln lib','Exploit / exfil']),findings:1+(e.crossLinks?.length||0)};
  }

  if(e.scannerId==='sast'){
    const repo=deriveRepo(e.asset);
    const file=e.title.includes('·')?e.title.split('·').pop().trim():'src/.../handler.java';
    const nodes=[
      mk('ap0','entry','globe','Internet client',e.internet?'ALB path':'Internal','Initial access','User-controlled input reaches vulnerable sink.',[`${e.tool} rule hit`]),
      mk('ap1','exposed','git',repo,`${ORG}/${repo}`,'Code flaw',`Static flaw in ${file}.`,[`PR #${e.pr||1100+(h%200)}`,`Commit ${e.commit||'—'}`]),
      mk('ap2','actor','code',shortAsset(e),e.internet?'prod':'staging','Deployed service','Vulnerable code path ships to runtime.',[`Branch: main → prod`,`Contrast / IAST optional`]),
      mk('ap3','resource','api','/api/v1/charge','payments-api','Exploit path',`HTTP entry invokes taint sink thousands of times per day.`,[`Taint: source → sink`,`~${2400+(h%800)} calls/day`]),
      mk('ap4','crown','database',crownLabel,'Tier 0','Impact',`Successful exploitation yields query or modify on ledger data.`,[`${e.jira||meta.jira}`,`Owner: ${e.owner}`]),
      mk('ap5','exit','shield','WAF / RASP',e.internet?'Edge control':'N/A','Compensating',`Runtime control may block exploit until patch lands.`,[`Virtual patch optional`])
    ];
    const narrative=`An attacker can send crafted input to <strong>${esc(shortAsset(e))}</strong>, trigger the flaw in <strong>${esc(file)}</strong> on <strong>${esc(repo)}</strong>, and reach <strong>${esc(crownLabel)}</strong> through the production API path.`;
    return {narrative, nodes, edges:edgeChain(nodes,['HTTP request','Merged PR','Deploy','Invoke sink','SQL/XXE impact','Blocked?']),findings:1+(e.crossLinks?.length||0)};
  }

  if(e.scannerId==='dast'){
    const url=e.asset.startsWith('http')?e.asset.replace(/^https?:\/\//,'').split('/')[0]:shortAsset(e);
    const path=e.asset.includes('/')?('/'+e.asset.split('/').slice(3).join('/').slice(0,40)):e.title.includes('·')?e.title.split('·')[1]?.trim():'/api/...';
    const nodes=[
      mk('ap0','entry','globe','Public Internet','Attacker','Reconnaissance','External probe discovers exploitable behavior.',[`${e.tool} live test`]),
      mk('ap1','exposed','globe',url,path.slice(0,36),'Exploit surface',`${e.title} confirmed against running app.`,[`Live exploit proof`,`Internet-facing: ${e.internet?'yes':'no'}`]),
      mk('ap2','actor','api','API gateway','Apigee / ALB','AuthZ bypass',`Gateway routes to backend with weak authorization.`,[`Shadow API check`,`BOLA / authz`]),
      mk('ap3','resource','server','payments-api','K8s service','Backend','Microservice executes vulnerable handler.',[`Owner: ${e.owner}`,`${e.jira||''}`]),
      mk('ap4','crown','database',crownLabel,'Customer data','Impact',`Successful attack reads or mutates customer records.`,[`PCI / PII tags`,`P1 SLA`]),
      mk('ap5','exit','shield','WAF rule',e.internet?'Virtual patch':'Policy','Containment',`Edge control can block pattern while code fix ships.`,[`SecOps runbook`])
    ];
    const narrative=`An attacker on the <strong>internet</strong> can exploit <strong>${esc(e.title)}</strong> at <strong>${esc(path)}</strong> on <strong>${esc(url)}</strong>, pivot through the API tier, and access <strong>${esc(crownLabel)}</strong>.`;
    return {narrative, nodes, edges:edgeChain(nodes,['Probe','Exploit','Route','Backend call','Data access','WAF block']),findings:1+(e.crossLinks?.length||0)};
  }

  if(e.scannerId==='container'){
    const repo=deriveRepo(e.asset);
    const img=shortAsset(e);
    const nodes=[
      mk('ap0','entry','git',repo,`${ORG}/${repo}`,'Build context','Image built from repo — vuln introduced in layer.',[`Dockerfile / CI`,`Commit ${e.commit||'—'}`]),
      mk('ap1','exposed','container',img.split(':')[0]||img,e.buildPipeline?.artifact?.digest?.slice(0,20)||'image:tag','Vulnerable image',`${e.cve||e.title} in running image.`,[`Registry scan`,`Layer: app`]),
      mk('ap2','actor','container','JFrog prod',e.buildPipeline?.artifact?.registry||'registry','Registry','Artifact promoted to prod registry.',[`Digest pinned`]),
      mk('ap3','resource','cloud',e.buildPipeline?.deployment?.cluster||'eks-prod-use1',e.buildPipeline?.deployment?.namespace||'payments','Runtime','Pods execute vulnerable image.',[`${e.buildPipeline?.deployment?.podCount||12} pods`,`Falco watch`]),
      mk('ap4','crown','database',crownLabel,'In-cluster','Impact',`Compromised workload reaches sensitive volumes or APIs.`,[`CNAPP path length ${2+(h%2)}`]),
      mk('ap5','exit','zap','C2 / exfil',e.internet?'Egress':'Lateral','Post-exploit',`Outbound from cluster if runtime compromised.`,[`NetworkPolicy gap?`])
    ];
    const narrative=`An attacker who compromises <strong>${esc(img)}</strong> (built from <strong>${esc(repo)}</strong>) can escape the container boundary, move through <strong>${esc(e.buildPipeline?.deployment?.cluster||'the prod cluster')}</strong>, and reach <strong>${esc(crownLabel)}</strong>.`;
    return {narrative, nodes, edges:edgeChain(nodes,['Build','Scan fail','Push','Deploy','Privilege / API','Exfil']),findings:1+(e.crossLinks?.length||0)};
  }

  if(e.scannerId==='iac'){
    const repo=deriveRepo(e.asset);
    const nodes=[
      mk('ap0','entry','git',repo,`terraform/…`,'Misconfig in code',`Policy violation in IaC before apply.`,[`${e.tool}`,`PR gate`]),
      mk('ap1','exposed','code','tf module',shortAsset(e).slice(0,24),'Plan / apply',`Terraform plans risky change to ${shortAsset(e).slice(0,30)}.`,[`Checkov / tfsec`]),
      mk('ap2','actor','cloud','prod-payments','112233445566','Target account',`Change targets production payments account.`,[`Account criticality: high`]),
      mk('ap3','resource','database',shortAsset(e).replace(/^arn:aws:[^:]+::/,'').slice(0,22),'Cloud resource','Deployed resource exposes data or ingress.',[`Drift: ${h%3?'none':'possible'}`]),
      mk('ap4','crown','database',crownLabel,'PCI scope','Impact',`Public exposure or weak encryption on crown-jewel store.`,[`Blast radius: internet`]),
      mk('ap5','exit','shield','Policy guard','CI block','Prevent','Pipeline can block apply before deploy.',[`OPA / Sentinel`])
    ];
    const narrative=`If <strong>${esc(e.title)}</strong> in <strong>${esc(repo)}</strong> is applied, an attacker could reach <strong>${esc(crownLabel)}</strong> via <strong>${esc(shortAsset(e).slice(0,40))}</strong> in the production account.`;
    return {narrative, nodes, edges:edgeChain(nodes,['Commit','Plan','Apply','Misconfig live','Data exposure','Guardrail']),findings:1};
  }

  if(e.scannerId==='cspm'){
    const nodes=[
      mk('ap0','entry','globe','Internet','0.0.0.0/0','Initial access','Public exposure or toxic combination entry.',[`CNAPP graph`]),
      mk('ap1','exposed','cloud',shortAsset(e).slice(0,20),'AWS resource','Misconfiguration',`${e.title} — posture finding.`,[`Toxic combo: ${h%2?'yes':'review'}`]),
      mk('ap2','actor','user','over-priv role','IAM *:*','Identity','Role bridges resources in attack graph.',[`IAM analyzer`]),
      mk('ap3','resource','server','workload','EKS / EC2','Lateral','Compute can reach datastore via network + identity.',[`Attack path len ${3+(h%3)}`]),
      mk('ap4','crown','database',crownLabel,'Data plane','Impact',`Crown-jewel data store at end of graph path.`,[`${e.jira||meta.jira}`]),
      mk('ap5','exit','shield','Auto-remediate','Lambda','Containment',`Runbook can isolate SG or policy while ticket open.`,[`Wiz / Prisma`])
    ];
    const narrative=`An attacker can abuse <strong>${esc(e.title)}</strong> on <strong>${esc(shortAsset(e))}</strong>, chain IAM and network edges in the cloud graph, and reach <strong>${esc(crownLabel)}</strong>.`;
    return {narrative, nodes, edges:edgeChain(nodes,['Discover','Exploit misconfig','Assume role','Pivot','Read data','Remediate']),findings:1+(e.crossLinks?.length||0)};
  }

  if(e.scannerId==='easm'){
    const nodes=[
      mk('ap0','entry','globe','Internet','Scanner','Discovery',`Outside-in discovery of exposed asset.`,[`EASM / Randori`]),
      mk('ap1','exposed','globe',shortHost(e),e.internet?'Public':'Unknown',`Exposed service`,`Asset not in CMDB or forgotten surface.`,[`Shadow IT confidence: medium`]),
      mk('ap2','actor','user','attacker','Opportunistic','Exploitation',`Known CVE or weak auth on exposed service.`,[`${e.cve||'misconfig'}`]),
      mk('ap3','resource','server','internal-bridge','VPN / peer','Pivot',`May bridge to internal acmepay network.`,[`WHOIS / CT logs`]),
      mk('ap4','crown','database',crownLabel,'Internal API','Impact',`Reach internal admin or payment APIs.`,[`Attribution pending`]),
      mk('ap5','exit','shield','Takedown','Brand / Net','Response',`Perimeter block or decommission asset.`,[`SecOps + owner`])
    ];
    const narrative=`An external attacker can discover <strong>${esc(shortHost(e))}</strong>, exploit the exposure, and pivot toward <strong>${esc(crownLabel)}</strong> — often via shadow infrastructure.`;
    return {narrative, nodes, edges:edgeChain(nodes,['OSINT','Scan','Exploit','Bridge','Internal API','Takedown']),findings:1};
  }

  if(e.scannerId==='secrets'){
    const repo=deriveRepo(e.asset);
    const nodes=[
      mk('ap0','entry','git',repo,'History / branch','Leak origin',`Secret committed to version control.`,[`${e.tool}`,`Valid: live`]),
      mk('ap1','exposed','git','leaked key','AKIA… / token','Credential',`Credential maps to cloud or SaaS principal.`,[`Rotation SLA: urgent`]),
      mk('ap2','actor','user','svc-deploy-prod','IAM user','Identity',`Principal has broad permissions.`,[`AdminAccess: ${h%2?'yes':'review'}`]),
      mk('ap3','resource','cloud','AWS APIs','us-east-1','API abuse',`Attacker invokes APIs with stolen key.`,[`CloudTrail audit`]),
      mk('ap4','crown','database',crownLabel,'Data exfil','Impact',`Read S3, RDS, or secrets manager.`,[`P0 incident`]),
      mk('ap5','exit','shield','Revoke + rotate','Vault','Remediation',`Only fix is revocation — no virtual patch.`,[`Pre-receive block`])
    ];
    const narrative=`An attacker with the leaked secret from <strong>${esc(repo)}</strong> can authenticate as <strong>production IAM</strong>, invoke cloud APIs, and exfiltrate from <strong>${esc(crownLabel)}</strong>.`;
    return {narrative, nodes, edges:edgeChain(nodes,['Commit secret','Clone repo','Use key','API calls','Exfil','Rotate']),findings:1};
  }

  const nodes=[
    mk('ap0','entry','globe','Entry','Attacker','Start','Attack path entry.',[]),
    mk('ap1','exposed','server',shortHost(e),meta.ip||'—','Vulnerability',e.title,[]),
    mk('ap2','crown','database',crownLabel,'Target','Impact','Critical asset.',[])
  ];
  return {narrative:`Attack path for <strong>${esc(e.title)}</strong> on <strong>${esc(shortHost(e))}</strong>.`,nodes,edges:edgeChain(nodes,['Step 1','Step 2']),findings:1};
}

function edgeChain(nodes,labels){
  const edges=[];
  for(let i=0;i<nodes.length-1;i++){
    edges.push({from:nodes[i].id,to:nodes[i+1].id,label:labels[i]||'Next'});
  }
  return edges;
}

function apNodeClass(type){
  if(type==='exposed') return 'ap-node-exposed';
  if(type==='crown') return 'ap-node-crown';
  if(type==='entry'||type==='exit') return 'ap-node-edge';
  return 'ap-node-mid';
}

function apHexPoints(cx,cy,r){
  const pts=[];
  for(let i=0;i<6;i++){
    const a=Math.PI/180*(60*i-30);
    pts.push(`${(cx+r*Math.cos(a)).toFixed(1)},${(cy+r*Math.sin(a)).toFixed(1)}`);
  }
  return pts.join(' ');
}

function renderAttackPathSvg(e,path){
  const nodes=path.nodes;
  const edges=path.edges;
  const gap=148;
  const r=34;
  const y=118;
  const stageY=52;
  const labelY=168;
  const W=Math.max(920,80+gap*(nodes.length-1)+80);
  const H=220;
  const uid=e.id.replace(/[^a-zA-Z0-9]/g,'');

  const positions={};
  nodes.forEach((n,i)=>{
    positions[n.id]={x:90+i*gap,y,cy:y};
  });

  const edgeSvg=edges.map(ed=>{
    const a=positions[ed.from],b=positions[ed.to];
    if(!a||!b) return '';
    const x1=a.x+r+8,x2=b.x-r-8;
    const mx=(x1+x2)/2;
    return `<g class="ap-edge">
      <line x1="${x1}" y1="${a.y}" x2="${x2}" y2="${b.y}" marker-end="url(#ap-arrow-${uid})"/>
      <text x="${mx}" y="${a.y-10}" class="ap-edge-label">${esc(ed.label)}</text>
    </g>`;
  }).join('');

  const nodeSvg=nodes.map(n=>{
    const p=positions[n.id];
    const cls=apNodeClass(n.type);
    const crown=n.type==='crown'?`<text x="${p.x}" y="${p.y-44}" class="ap-crown-mark" text-anchor="middle">♛</text>`:'';
    const stageLabel=n.stage?esc(n.stage.length>22?n.stage.slice(0,21)+'…':n.stage):'';
    const stageWarn=['Credential Access','Privilege Escalation','Exploitation','Identity'].some(s=>(n.stage||'').includes(s));
    const stage=n.stage?`<g class="ap-stage${stageWarn?' ap-stage-warn':''}"><rect x="${p.x-54}" y="${stageY}" width="108" height="20" rx="10"/><text x="${p.x}" y="${stageY+14}" text-anchor="middle">${stageLabel}</text></g>`:'';
    return `<g class="ap-node ${cls}" data-ap-node="${n.id}" tabindex="0" role="button" aria-label="${esc(n.label)}">
      ${stage}
      ${crown}
      <polygon points="${apHexPoints(p.x,p.y,r)}" class="ap-hex"/>
      <foreignObject x="${p.x-22}" y="${p.y-22}" width="44" height="44">
        <div xmlns="http://www.w3.org/1999/xhtml" class="ap-hex-icon">${icon(n.icon,22)}</div>
      </foreignObject>
      <text x="${p.x}" y="${labelY}" class="ap-node-label" text-anchor="middle">${esc(n.label)}</text>
      <text x="${p.x}" y="${labelY+14}" class="ap-node-sub" text-anchor="middle">${esc(n.sub||'')}</text>
    </g>`;
  }).join('');

  return `<svg class="attack-path-svg" viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg" aria-label="Attack path for ${esc(e.id)}">
    <defs>
      <marker id="ap-arrow-${uid}" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z" fill="#64748b"/></marker>
    </defs>
    <g class="ap-edges">${edgeSvg}</g>
    <g class="ap-nodes">${nodeSvg}</g>
  </svg>`;
}

function renderAttackPathView(e){
  const path=buildAttackPath(e);
  return `
    <div class="attack-path-view" data-exp-id="${e.id}">
      <div class="attack-path-summary">
        <div class="attack-path-summary-text">
          <span class="attack-path-ai-badge">AI</span>
          <p class="attack-path-narrative">${path.narrative}</p>
        </div>
        <button type="button" class="attack-path-findings-btn" data-findings-jump="${e.id}">View Findings (${path.findings})</button>
      </div>
      <div class="ap-hub-wrap" data-ap-resize-wrap>
        <div class="diagram-zoom-controls" data-zoom-controls data-zoom-target="attack-path">
          <button type="button" data-zoom="out" aria-label="Zoom attack path out">−</button>
          <button type="button" data-zoom="in" aria-label="Zoom attack path in">+</button>
          <button type="button" data-zoom-reset aria-label="Reset attack path zoom">Reset</button>
        </div>
        <div class="diagram-zoom-canvas attack-path-graph-scroll" data-zoom-canvas="attack-path">
          ${renderAttackPathSvg(e,path)}
        </div>
      </div>
      <div class="viz-resize-handle" data-ap-resize-handle role="separator" aria-orientation="horizontal" aria-label="Resize attack path diagram" tabindex="0"></div>
      <div class="attack-path-legend">
        <span class="ap-legend-item"><span class="ap-legend-swatch ap-legend-exposed"></span> Exposed asset</span>
        <span class="ap-legend-item"><span class="ap-legend-swatch ap-legend-crown"></span> Critical asset</span>
      </div>
      <div class="attack-path-info">
        <div class="attack-path-info-tabs"><span class="ap-info-tab on">Information</span></div>
        <div class="attack-path-info-body" data-ap-info>
          <p class="ap-info-placeholder">Select a step in the attack path to see technique context and evidence.</p>
        </div>
      </div>
    </div>`;
}

function renderAttackPathNodeInfo(node){
  const ev=(node.evidence||[]).map(x=>`<li>${esc(x)}</li>`).join('');
  return `
    <h5 class="ap-info-title">${esc(node.label)}</h5>
    <p class="ap-info-stage"><strong>Stage:</strong> ${esc(node.stage||'—')}</p>
    <p class="ap-info-desc">${esc(node.info||'')}</p>
    ${ev?`<div class="ap-info-evidence"><strong>Evidence</strong><ul>${ev}</ul></div>`:''}`;
}

function bindAttackPathPanel(panel,e){
  const view=panel.querySelector('.attack-path-view');
  if(!view) return;
  const path=buildAttackPath(e);
  const infoEl=view.querySelector('[data-ap-info]');
  const selectNode=(nodeId)=>{
    const node=path.nodes.find(n=>n.id===nodeId);
    if(!node||!infoEl) return;
    view.querySelectorAll('.ap-node').forEach(g=>g.classList.toggle('selected',g.dataset.apNode===nodeId));
    infoEl.innerHTML=renderAttackPathNodeInfo(node);
  };
  view.querySelectorAll('.ap-node').forEach(g=>{
    const fn=()=>selectNode(g.dataset.apNode);
    g.onclick=fn;
    g.onkeydown=ev=>{if(ev.key==='Enter'||ev.key===' '){ev.preventDefault();fn();}};
  });
  if(path.nodes[1]) selectNode(path.nodes[1].id);
  view.querySelector('[data-findings-jump]')?.addEventListener('click',()=>{
    if(infoEl){
      infoEl.innerHTML=`
        <h5 class="ap-info-title">Scanner finding</h5>
        <p class="ap-info-desc">${esc(e.tool)} — ${esc(e.title)}</p>
        <div class="ap-info-evidence"><strong>Evidence</strong><ul>
          <li>${e.cve?esc(e.cve):`Severity: ${esc(e.severity)}`}</li>
          <li>Exposure ${esc(e.id)} · score ${e.score.toFixed(1)}</li>
          ${(e.crossLinks||[]).map(c=>`<li>Also: ${esc(c.id)} (${esc(c.by)})</li>`).join('')}
        </ul></div>`;
      view.querySelectorAll('.ap-node').forEach(g=>g.classList.remove('selected'));
    }
    const hub=panel.querySelector('.corr-hub-wrap');
    hub?.scrollIntoView({behavior:'smooth',block:'nearest'});
    const finding=panel.querySelector('.corr-hub-wrap .corr-box-wrap[data-finding]');
    finding?.click();
  });
}
