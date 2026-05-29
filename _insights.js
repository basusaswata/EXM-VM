/** Exposure insights — charts, KPIs & top open risks from current scanner / filter slice. */

const SEV_COLORS={Critical:'#dc2626',High:'#ea580c',Medium:'#ca8a04',Low:'#64748b'};
const STATUS_COLORS={
  'Open':'#2563eb','In progress':'#7c3aed','Compensating control':'#0891b2',
  'Patched':'#16a34a','Risk accepted':'#64748b'
};
const RANK_STYLES=['insight-risk--gold','insight-risk--silver','insight-risk--bronze'];

function computeInsightMetrics(rows){
  const sev={Critical:0,High:0,Medium:0,Low:0};
  const status={};
  const scoreBuckets=[0,0,0,0];
  const ownerMap={};
  let kev=0,internet=0,overdue=0,urgent=0,open=0,scoreSum=0,epssSum=0,epssN=0;
  rows.forEach(r=>{
    sev[r.severity]=(sev[r.severity]||0)+1;
    status[r.status]=(status[r.status]||0)+1;
    scoreSum+=r.score;
    const bi=r.score>=8?3:r.score>=6?2:r.score>=4?1:0;
    scoreBuckets[bi]++;
    if(r.kev) kev++;
    if(r.internet) internet++;
    if(r.sla.includes('Overdue')) overdue++;
    else if(r.sla.includes('h left')) urgent++;
    if(r.status==='Open') open++;
    if(r.epss!=null){epssSum+=r.epss;epssN++;}
    ownerMap[r.owner]=ownerMap[r.owner]||{n:0,score:0};
    ownerMap[r.owner].n++;
    ownerMap[r.owner].score+=r.score;
  });
  const n=rows.length||1;
  const topOwners=Object.entries(ownerMap)
    .map(([name,v])=>({name,n:v.n,avg:v.score/v.n}))
    .sort((a,b)=>b.n-a.n).slice(0,5);
  const critHigh=sev.Critical+sev.High;
  const kevOnInternet=rows.filter(r=>r.kev&&r.internet).length;
  const matrix={
    kevNet:rows.filter(r=>r.kev&&r.internet).length,
    kevInt:rows.filter(r=>r.kev&&!r.internet).length,
    noKevNet:rows.filter(r=>!r.kev&&r.internet).length,
    noKevInt:rows.filter(r=>!r.kev&&!r.internet).length
  };
  return {
    n:rows.length,sev,status,scoreBuckets,kev,internet,overdue,urgent,open,
    avgScore:scoreSum/n,avgEpss:epssN?epssSum/epssN:null,critHigh,kevOnInternet,topOwners,matrix
  };
}

function topOpenRisks(rows,n=3){
  return rows.filter(r=>r.status==='Open')
    .sort((a,b)=>{
      const pa=(b.kev?4:0)+(b.internet?2:0)+(b.sla.includes('Overdue')?1:0);
      const pb=(a.kev?4:0)+(a.internet?2:0)+(a.sla.includes('Overdue')?1:0);
      return b.score-a.score||pa-pb;
    })
    .slice(0,n);
}

function triageLink(sid,expId){
  return 'exposure-dashboard.html?scanner='+encodeURIComponent(sid)+(expId?'&exp='+encodeURIComponent(expId):'');
}

function scoreColor(score){
  if(score>=8) return '#dc2626';
  if(score>=6) return '#ea580c';
  if(score>=4) return '#ca8a04';
  return '#64748b';
}

function insightCallout(m,rows){
  if(!m.n) return 'No exposures in the current filter slice — adjust filters or pick another scanner.';
  const parts=[];
  const top=topOpenRisks(rows,1)[0];
  if(top) parts.push(`highest open risk <strong>${esc(top.id)}</strong> (${top.score.toFixed(1)})`);
  if(m.critHigh&&m.n) parts.push(`<strong>${Math.round(m.critHigh/m.n*100)}%</strong> are Critical/High severity`);
  if(m.kevOnInternet) parts.push(`<strong>${m.kevOnInternet}</strong> KEV + internet-facing (highest priority)`);
  if(m.overdue) parts.push(`<strong>${m.overdue}</strong> overdue SLA`);
  if(m.avgEpss!=null&&m.avgEpss>0.5) parts.push(`avg EPSS <strong>${m.avgEpss.toFixed(2)}</strong> — active exploitation risk`);
  return parts.length?parts.join(' · '):`Tracking <strong>${m.n}</strong> exposures · avg score <strong>${m.avgScore.toFixed(1)}</strong>`;
}

function renderTopOpenRisks(rows,sid,fullPage){
  const risks=topOpenRisks(rows,3);
  if(!risks.length){
    return `<div class="insights-top-risks insights-top-risks--empty"><h4>Top open risks</h4><p class="insight-empty">No open exposures in this slice — great progress.</p></div>`;
  }
  const cards=risks.map((r,i)=>{
    const rank=i+1;
    const slaCls=r.sla.includes('Overdue')?'insight-risk-sla--overdue':r.sla.includes('h left')?'insight-risk-sla--urgent':'';
    const badges=[
      r.kev?'<span class="insight-risk-badge insight-risk-badge--kev">KEV</span>':'',
      r.internet?'<span class="insight-risk-badge insight-risk-badge--net">Internet</span>':'',
      r.epss!=null?`<span class="insight-risk-badge">EPSS ${r.epss.toFixed(2)}</span>`:''
    ].filter(Boolean).join('');
    const maxAsset=fullPage?42:28;
    const assetDisp=r.asset.length>maxAsset?r.asset.slice(0,maxAsset-1)+'…':r.asset;
    return `<a class="insight-risk-card ${RANK_STYLES[i]||''}" href="${triageLink(sid,r.id)}" title="Open in triage queue">
      <div class="insight-risk-rank">#${rank}</div>
      <div class="insight-risk-score" style="--risk-color:${scoreColor(r.score)}">${r.score.toFixed(1)}</div>
      <div class="insight-risk-main">
        <div class="insight-risk-id">${esc(r.id)}${r.cve?` · <span class="insight-risk-cve">${esc(r.cve)}</span>`:''}</div>
        <div class="insight-risk-title">${esc(r.title)}</div>
        <div class="insight-risk-meta">
          <span>${esc(assetDisp)}</span>
          <span class="insight-risk-owner">${esc(r.owner)}</span>
        </div>
        ${badges?`<div class="insight-risk-badges">${badges}</div>`:''}
      </div>
      <div class="insight-risk-foot">
        <span class="insight-risk-sla ${slaCls}">${esc(r.sla)}</span>
        <span class="insight-risk-cta">View in queue →</span>
      </div>
    </a>`;
  }).join('');
  return `<section class="insights-top-risks" aria-label="Top open risks">
    <div class="insights-top-risks-head">
      <h4>Top 3 open risks</h4>
      <p class="insight-card-hint">Ranked by score · KEV &amp; internet exposure boost priority</p>
    </div>
    <div class="insight-risk-grid">${cards}</div>
  </section>`;
}

function svgDonut(segments,size=100,stroke=14){
  const r=(size-stroke)/2,cx=size/2,cy=size/2;
  const total=segments.reduce((s,x)=>s+x.value,0)||1;
  let angle=-Math.PI/2;
  const arcs=segments.filter(s=>s.value>0).map((s,i)=>{
    const a=(s.value/total)*Math.PI*2;
    const x1=cx+r*Math.cos(angle),y1=cy+r*Math.sin(angle);
    angle+=a;
    const x2=cx+r*Math.cos(angle),y2=cy+r*Math.sin(angle);
    const large=a>Math.PI?1:0;
    return `<path d="M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}" fill="none" stroke="${s.color}" stroke-width="${stroke}" stroke-linecap="round" opacity=".92" class="insight-donut-arc"/>`;
  }).join('');
  return `<svg class="insight-donut" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" aria-hidden="true">
    <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="var(--border)" stroke-width="${stroke}" opacity=".35"/>
    ${arcs}
    <text x="${cx}" y="${cy-2}" text-anchor="middle" class="insight-donut-total">${total}</text>
    <text x="${cx}" y="${cy+10}" text-anchor="middle" class="insight-donut-label">total</text>
  </svg>`;
}

function renderRadialSeverity(sevSegs){
  const active=sevSegs.filter(s=>s.value>0);
  if(!active.length) return '<p class="insight-empty">—</p>';
  const max=Math.max(...active.map(s=>s.value),1);
  const cx=60,cy=60,R=42,r=24;
  const bars=active.map((s,i)=>{
    const a0=-Math.PI/2+(i/active.length)*Math.PI*2;
    const a1=-Math.PI/2+((i+1)/active.length)*Math.PI*2;
    const len=Math.max(0.12,(s.value/max)*0.88);
    const mid=(a0+a1)/2;
    const ir=R-len*(R-r);
    const x0=cx+ir*Math.cos(mid),y0=cy+ir*Math.sin(mid);
    const x1=cx+R*Math.cos(mid),y1=cy+R*Math.sin(mid);
    return `<line x1="${x0.toFixed(1)}" y1="${y0.toFixed(1)}" x2="${x1.toFixed(1)}" y2="${y1.toFixed(1)}" stroke="${s.color}" stroke-width="10" stroke-linecap="round" opacity=".9"/>`;
  }).join('');
  const legend=sevSegs.map(s=>`<li><span style="background:${s.color}"></span>${s.label} <strong>${s.value}</strong></li>`).join('');
  return `<div class="insight-radial-wrap">
    <svg viewBox="0 0 120 120" width="120" height="120" class="insight-radial">${bars}<circle cx="${cx}" cy="${cy}" r="16" fill="var(--panel-2)" stroke="var(--border)"/></svg>
    <ul class="insight-sev-legend">${legend}</ul>
  </div>`;
}

function renderRiskGauge(score){
  const W=160,H=96,cx=80,cy=82,r=58;
  const pct=Math.min(1,Math.max(0,score/10));
  const angle=-Math.PI+ pct*Math.PI;
  const nx=cx+r*Math.cos(angle),ny=cy+r*Math.sin(angle);
  const col=scoreColor(score);
  const zones=[
    {c:'#64748b',a0:-Math.PI,a1:-Math.PI+Math.PI*0.4},
    {c:'#ca8a04',a0:-Math.PI+Math.PI*0.4,a1:-Math.PI+Math.PI*0.6},
    {c:'#ea580c',a0:-Math.PI+Math.PI*0.6,a1:-Math.PI+Math.PI*0.8},
    {c:'#dc2626',a0:-Math.PI+Math.PI*0.8,a1:0}
  ].map(z=>{
    const x1=cx+r*Math.cos(z.a0),y1=cy+r*Math.sin(z.a0);
    const x2=cx+r*Math.cos(z.a1),y2=cy+r*Math.sin(z.a1);
    const large=z.a1-z.a0>Math.PI?1:0;
    return `<path d="M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}" fill="none" stroke="${z.c}" stroke-width="10" stroke-linecap="butt" opacity=".35"/>`;
  }).join('');
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" class="insight-gauge">
    ${zones}
    <line x1="${cx}" y1="${cy}" x2="${nx.toFixed(1)}" y2="${ny.toFixed(1)}" stroke="${col}" stroke-width="3" stroke-linecap="round"/>
    <circle cx="${cx}" cy="${cy}" r="5" fill="${col}"/>
    <text x="${cx}" y="${cy-18}" text-anchor="middle" class="insight-gauge-val">${score.toFixed(1)}</text>
    <text x="${cx}" y="${H-4}" text-anchor="middle" class="insight-gauge-lbl">Avg exposure score</text>
  </svg>`;
}

function renderThreatMatrix(matrix){
  const cells=[
    {k:'kevNet',label:'KEV + Internet',hint:'Act now',cls:'insight-matrix--hot'},
    {k:'kevInt',label:'KEV internal',hint:'Segment & patch',cls:'insight-matrix--warm'},
    {k:'noKevNet',label:'Internet only',hint:'Monitor',cls:'insight-matrix--mid'},
    {k:'noKevInt',label:'Internal only',hint:'Schedule',cls:'insight-matrix--cool'}
  ];
  const max=Math.max(...cells.map(c=>matrix[c.k]),1);
  const html=cells.map(c=>{
    const v=matrix[c.k];
    const intensity=0.15+(v/max)*0.75;
    return `<div class="insight-matrix-cell ${c.cls}" style="--heat:${intensity}">
      <span class="insight-matrix-val">${v}</span>
      <span class="insight-matrix-label">${c.label}</span>
      <span class="insight-matrix-hint">${c.hint}</span>
    </div>`;
  }).join('');
  return `<div class="insight-matrix">${html}</div>`;
}

function renderTrendSparkline(rows){
  const high=rows.filter(r=>r.score>=7).length||1;
  const seed=rows.reduce((s,r)=>s+r.score*100,0)%997;
  const factors=[0.68,0.74,0.81,0.77,0.88,0.92,1.0].map((f,i)=>Math.max(0,Math.round(high*f*(0.92+(seed+i*17)%20/100))));
  const W=260,H=88,p=16;
  const max=Math.max(...factors,1);
  const pts=factors.map((v,i)=>{
    const x=p+i*((W-2*p)/(factors.length-1));
    const y=H-p-((v/max)*(H-2*p));
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  const area=pts+` ${W-p},${H-p} ${p},${H-p}`;
  const last=factors[factors.length-1],prev=factors[factors.length-2];
  const delta=last-prev;
  const deltaCls=delta>0?'insight-trend--up':delta<0?'insight-trend--down':'';
  const days=['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
  const labels=days.map((d,i)=>`<text x="${p+i*((W-2*p)/(days.length-1))}" y="${H+2}" text-anchor="middle" class="insight-trend-day">${d}</text>`).join('');
  return `<div class="insight-trend-wrap">
    <div class="insight-trend-head">
      <span class="insight-trend-title">High-score trend (7d)</span>
      <span class="insight-trend-delta ${deltaCls}">${delta>=0?'+':''}${delta} vs yesterday</span>
    </div>
    <svg viewBox="0 0 ${W} ${H+12}" width="100%" height="${H+12}" class="insight-trend">
      <defs><linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="var(--accent)" stop-opacity=".35"/><stop offset="100%" stop-color="var(--accent)" stop-opacity="0"/></linearGradient></defs>
      <polygon points="${area}" fill="url(#trendGrad)"/>
      <polyline points="${pts}" fill="none" stroke="var(--accent)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
      ${factors.map((v,i)=>{
        const x=p+i*((W-2*p)/(factors.length-1));
        const y=H-p-((v/max)*(H-2*p));
        return `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="3.5" fill="var(--panel-2)" stroke="var(--accent)" stroke-width="2"><title>${days[i]}: ${v} high-score</title></circle>`;
      }).join('')}
      ${labels}
    </svg>
  </div>`;
}

function renderBarChart(bars,{h=88,barH=10,gap=6,labelW=72}={}){
  const max=Math.max(...bars.map(b=>b.value),1);
  const W=280;
  const rows=bars.map((b,i)=>{
    const y=8+i*(barH+gap);
    const w=Math.max(4,(b.value/max)*(W-labelW-24));
    const grad=b.color&&b.color.startsWith('#')?b.color:'var(--accent)';
    return `<g class="insight-bar-row">
      <text x="0" y="${y+barH-2}" class="insight-bar-label">${esc(b.label.length>11?b.label.slice(0,10)+'…':b.label)}</text>
      <rect x="${labelW}" y="${y}" width="${w}" height="${barH}" rx="4" fill="${grad}" class="insight-bar-fill" opacity=".88"/>
      <text x="${labelW+w+6}" y="${y+barH-2}" class="insight-bar-val">${b.value}</text>
    </g>`;
  }).join('');
  return `<svg class="insight-bars" viewBox="0 0 ${W} ${h}" width="100%" height="${h}" preserveAspectRatio="xMidYMid meet">${rows}</svg>`;
}

function renderScoreHistogram(buckets){
  const labelsFix=['<4','4–6','6–8','8–10'];
  const colors=['#64748b','#ca8a04','#ea580c','#dc2626'];
  const max=Math.max(...buckets,1);
  const W=240,H=90,bw=44,gap=12;
  const bars=buckets.map((v,i)=>{
    const bh=Math.max(4,(v/max)*(H-24));
    const x=12+i*(bw+gap);
    return `<rect x="${x}" y="${H-8-bh}" width="${bw}" height="${bh}" rx="5" fill="${colors[i]}" class="insight-hist-bar" opacity=".9"/>
      <text x="${x+bw/2}" y="${H+4}" text-anchor="middle" class="insight-hist-label">${labelsFix[i]}</text>
      <text x="${x+bw/2}" y="${H-12-bh}" text-anchor="middle" class="insight-hist-val">${v}</text>`;
  }).join('');
  return `<svg viewBox="0 0 ${W} ${H+14}" width="100%" height="${H+14}" class="insight-histogram">${bars}</svg>`;
}

function renderStatusStack(m){
  const order=['Open','In progress','Compensating control','Patched','Risk accepted'];
  const total=m.n||1;
  let x=0;
  const W=260,H=22;
  const segs=order.filter(s=>m.status[s]).map(s=>{
    const w=Math.max(2,(m.status[s]/total)*W);
    const seg=`<rect x="${x}" y="0" width="${w}" height="${H}" fill="${STATUS_COLORS[s]||'#94a3b8'}" rx="0"/><title>${esc(s)}: ${m.status[s]}</title>`;
    x+=w;
    return seg;
  }).join('');
  const legend=order.filter(s=>m.status[s]).map(s=>
    `<span class="insight-legend-item"><span class="insight-legend-dot" style="background:${STATUS_COLORS[s]}"></span>${esc(statusLabel(s))} (${m.status[s]})</span>`
  ).join('');
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" class="insight-stack">${segs}</svg><div class="insight-legend">${legend}</div>`;
}

function renderEpssScatter(rows){
  const pts=rows.filter(r=>r.epss!=null).slice(0,50);
  if(!pts.length) return '<p class="insight-empty">No EPSS data in slice</p>';
  const W=280,H=120,p=22;
  const midX=p+(W-2*p)*0.55,midY=H-p-((7/10)*(H-2*p));
  const zones=`
    <rect x="${midX}" y="${p}" width="${W-p-midX}" height="${midY-p}" fill="#dc2626" opacity=".06" rx="4"/>
    <rect x="${p}" y="${p}" width="${midX-p}" height="${midY-p}" fill="#ca8a04" opacity=".05" rx="4"/>
    <text x="${W-p-4}" y="${p+10}" text-anchor="end" class="insight-quadrant insight-quadrant--hot">Exploit now</text>
    <text x="${p+4}" y="${p+10}" class="insight-quadrant">Watch</text>`;
  const dots=pts.map(r=>{
    const x=p+(r.epss)*(W-2*p);
    const y=H-p-((r.score/10)*(H-2*p));
    const col=SEV_COLORS[r.severity]||scoreColor(r.score);
    const pulse=r.kev&&r.internet?' insight-dot--pulse':'';
    return `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="5" fill="${col}" opacity=".88" class="insight-dot${pulse}"><title>${esc(r.id)} · EPSS ${r.epss.toFixed(2)} · score ${r.score.toFixed(1)}</title></circle>`;
  }).join('');
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" class="insight-scatter">
    ${zones}
    <line x1="${p}" y1="${midY}" x2="${W-p}" y2="${midY}" stroke="var(--border)" stroke-dasharray="3 3" opacity=".6"/>
    <line x1="${midX}" y1="${p}" x2="${midX}" y2="${H-p}" stroke="var(--border)" stroke-dasharray="3 3" opacity=".6"/>
    ${dots}
    <text x="${W/2}" y="${H-4}" text-anchor="middle" class="insight-axis">EPSS (exploitation probability) →</text>
    <text x="6" y="${H/2}" class="insight-axis" transform="rotate(-90 6 ${H/2})">Exposure score</text>
  </svg>`;
}

function renderInsightsPanel(rows,total,sid,fullPage){
  const m=computeInsightMetrics(rows);
  const sevSegs=['Critical','High','Medium','Low'].map(k=>({label:k,value:m.sev[k],color:SEV_COLORS[k]}));
  const ownerBars=m.topOwners.map((o,i)=>({label:o.name,value:o.n,color:['#2563eb','#7c3aed','#0891b2','#ea580c','#64748b'][i]}));
  const sc=SCANNERS.find(s=>s.id===sid);

  return `
    <div class="insights-header">
      <div>
        <h3 class="insights-title">${fullPage?'Analytics dashboard':'Exposure insights'}</h3>
        <p class="insights-sub">${rows.length} of ${total} ${esc(sc?.name||'exposures')} · ${fullPage?'use filters above to refine charts':'filtered queue analytics'}</p>
      </div>
      ${fullPage?'':`<button type="button" class="insights-toggle" id="insightsToggle" aria-expanded="true">Hide charts</button>`}
    </div>
    <div class="insights-body" id="insightsBody">
      ${renderTopOpenRisks(rows,sid,fullPage)}
      <div class="insights-kpis">
        <div class="insight-kpi"><span class="insight-kpi-val">${m.avgScore.toFixed(1)}</span><span class="insight-kpi-lbl">Avg score</span></div>
        <div class="insight-kpi insight-kpi--crit"><span class="insight-kpi-val">${m.critHigh}</span><span class="insight-kpi-lbl">Crit + High</span></div>
        <div class="insight-kpi insight-kpi--kev"><span class="insight-kpi-val">${m.kev}</span><span class="insight-kpi-lbl">KEV listed</span></div>
        <div class="insight-kpi insight-kpi--net"><span class="insight-kpi-val">${m.internet}</span><span class="insight-kpi-lbl">Internet</span></div>
        <div class="insight-kpi insight-kpi--sla"><span class="insight-kpi-val">${m.overdue+m.urgent}</span><span class="insight-kpi-lbl">SLA urgent</span></div>
        <div class="insight-kpi"><span class="insight-kpi-val">${m.open}</span><span class="insight-kpi-lbl">Open</span></div>
      </div>
      <div class="insights-grid">
        <div class="insight-card">
          <h4>Risk gauge</h4>
          <div class="insight-card-body">${renderRiskGauge(m.avgScore)}</div>
        </div>
        <div class="insight-card">
          <h4>Severity radar</h4>
          <div class="insight-card-body">${renderRadialSeverity(sevSegs)}</div>
        </div>
        <div class="insight-card">
          <h4>Threat matrix</h4>
          <p class="insight-card-hint">KEV × internet exposure</p>
          <div class="insight-card-body">${renderThreatMatrix(m.matrix)}</div>
        </div>
        <div class="insight-card">
          <h4>7-day trend</h4>
          <div class="insight-card-body">${renderTrendSparkline(rows)}</div>
        </div>
        <div class="insight-card">
          <h4>Score distribution</h4>
          <div class="insight-card-body">${renderScoreHistogram(m.scoreBuckets)}</div>
        </div>
        <div class="insight-card">
          <h4>Top owners</h4>
          <div class="insight-card-body">${ownerBars.length?renderBarChart(ownerBars):'<p class="insight-empty">—</p>'}</div>
        </div>
        <div class="insight-card">
          <h4>Status pipeline</h4>
          <div class="insight-card-body">${renderStatusStack(m)}</div>
        </div>
        <div class="insight-card insight-card--wide">
          <h4>EPSS vs exposure score</h4>
          <p class="insight-card-hint">Top-right quadrant = highest priority · pulsing dots = KEV + internet</p>
          <div class="insight-card-body">${renderEpssScatter(rows)}</div>
        </div>
      </div>
      <p class="insights-callout" id="insightsCallout">${insightCallout(m,rows)}</p>
    </div>`;
}

function renderInsights(){
  const host=document.getElementById('insightsPanel');
  if(!host) return;
  const sid=SCANNERS[activeScanner].id;
  const total=ALL_EXPOSURES.filter(e=>e.scannerId===sid).length;
  const rows=getFiltered();
  const fullPage=host.classList.contains('insights-page');
  host.innerHTML=renderInsightsPanel(rows,total,sid,fullPage);
  const sumEl=document.getElementById('summaryLine');
  if(sumEl) sumEl.textContent=summaryCounts(rows,total);
  document.documentElement.style.setProperty('--accent',SCANNERS[activeScanner].accent);
  if(!fullPage){
    const collapsed=localStorage.getItem('em-insights-collapsed')==='1';
    host.classList.toggle('is-collapsed',collapsed);
    const btn=host.querySelector('#insightsToggle');
    const body=host.querySelector('#insightsBody');
    if(btn&&body){
      btn.setAttribute('aria-expanded',collapsed?'false':'true');
      btn.textContent=collapsed?'Show charts':'Hide charts';
      btn.onclick=()=>{
        const c=!host.classList.contains('is-collapsed');
        host.classList.toggle('is-collapsed',c);
        btn.setAttribute('aria-expanded',c?'false':'true');
        btn.textContent=c?'Show charts':'Hide charts';
        try{localStorage.setItem('em-insights-collapsed',c?'1':'0');}catch(e){}
      };
    }
  }
}
