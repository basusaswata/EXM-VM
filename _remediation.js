/** Remediation / patch suggestion panel (demo — no real patch integration). */

function buildRemediationSuggestion(e){
  const meta=seedMeta(e);
  const repo=deriveRepo(e.asset);
  const h=pathHash(e.id);

  if(e.scannerId==='sca'){
    const pkg=e.title.toLowerCase().includes('log4j')?'log4j-core':'dependency';
    const ver=e.title.toLowerCase().includes('log4j')?'2.14.1 → 2.17.2':'bump to fixed version';
    return {
      title:'Dependency patch',
      summary:`Upgrade ${pkg} in ${repo} and redeploy the production artifact.`,
      steps:[
        `Bump ${pkg} ${ver} in pom.xml / lockfile`,
        `Open auto-fix PR #${e.pr||(1240+(h%80))} → ${ORG}/${repo}`,
        e.buildPipeline?`Rebuild ${e.buildPipeline.artifact.version} · ${e.buildPipeline.build.system}`:'Run CI build + SBOM scan',
        `Promote to ${e.buildPipeline?.deployment?.cluster||'eks-prod-use1'} via ArgoCD`
      ],
      action:'Apply patch',
      actionDetail:`Queues dependency bump PR and ${e.buildPipeline?'pipeline rebuild':'CI validation'}.`,
      auto:'Auto PR'
    };
  }
  if(e.scannerId==='sast'){
    const file=e.title.includes('·')?e.title.split('·').pop().trim():'vulnerable sink';
    return {
      title:'Code fix',
      summary:`Remediate static finding in source before next deploy.`,
      steps:[
        `Fix ${file} — use parameterized queries / sanitization`,
        `Semgrep rule suppress only if false positive confirmed`,
        `PR review → merge to main`,
        `Verify with Contrast IAST on ${shortAsset(e)}`
      ],
      action:'Apply patch',
      actionDetail:'Opens fix PR with suggested code change (demo).',
      auto:'Semi-auto'
    };
  }
  if(e.scannerId==='network'){
    return {
      title:'OS / vendor patch',
      summary:`Apply vendor fix for ${e.cve||e.title} on ${shortHost(e)}.`,
      steps:[
        e.cve?`Install vendor patch for ${e.cve}`:'Apply configuration hardening',
        `Maintenance window · ${meta.jira||e.jira}`,
        `CrowdStrike IOA template watch post-patch`,
        `Rescan with ${e.tool} to close ${e.id}`
      ],
      action:'Apply patch',
      actionDetail:'Schedules patch job via Tanium / WSUS runbook (demo).',
      auto:'Semi-auto'
    };
  }
  if(e.scannerId==='container'){
    return {
      title:'Image rebuild',
      summary:`Rebuild ${shortAsset(e)} with patched layers and roll pods.`,
      steps:[
        `Update Dockerfile / base image digest`,
        `Trigger ${e.buildPipeline?.build?.system||'GitHub Actions'} rebuild`,
        `Push to registry · pin digest in Helm/ArgoCD`,
        `Rolling restart · ${e.buildPipeline?.deployment?.podCount||12} pods`
      ],
      action:'Apply patch',
      actionDetail:'Queues image rebuild and staged deploy (demo).',
      auto:'Auto rebuild'
    };
  }
  if(e.scannerId==='dast'){
    return {
      title:'App + edge fix',
      summary:`Close exploitable path on ${shortAsset(e)}.`,
      steps:[
        `Patch handler for ${e.title.slice(0,40)}`,
        `Deploy to ${e.internet?'prod':'staging'} after regression tests`,
        e.internet?'Enable WAF virtual patch until code ships':'Validate internal-only route',
        `Re-run ${e.tool} probe to confirm`
      ],
      action:'Apply patch',
      actionDetail:'Creates change ticket + optional WAF rule (demo).',
      auto:'Manual'
    };
  }
  if(e.scannerId==='iac'){
    return {
      title:'IaC policy fix',
      summary:`Correct misconfiguration in Terraform before apply.`,
      steps:[
        `Update module per Checkov/tfsec suggestion`,
        `PR to ${ORG}/${repo||'infra'}`,
        `Plan/apply in prod-payments after approval`,
        `Drift scan confirms prod matches code`
      ],
      action:'Apply patch',
      actionDetail:'Opens PR with HCL fix snippet (demo).',
      auto:'Auto PR'
    };
  }
  if(e.scannerId==='cspm'){
    return {
      title:'Cloud posture fix',
      summary:`Remediate ${e.title.slice(0,50)} in AWS prod account.`,
      steps:[
        `Apply least-privilege / encryption policy`,
        `Run approved module or Lambda runbook`,
        `Validate attack path broken in CNAPP graph`,
        `Close ${meta.jira||e.jira} after rescan`
      ],
      action:'Apply patch',
      actionDetail:'Triggers posture auto-remediation runbook (demo).',
      auto:'Auto-fix'
    };
  }
  if(e.scannerId==='secrets'){
    return {
      title:'Secret rotation',
      summary:`Revoke leaked credential and rotate immediately.`,
      steps:[
        `Revoke key in IAM / Vault`,
        `Issue new dynamic credential`,
        `Audit CloudTrail for abuse`,
        `Enable pre-receive hook block`
      ],
      action:'Apply patch',
      actionDetail:'Starts rotation workflow P0 (demo).',
      auto:'Auto rotate'
    };
  }
  if(e.scannerId==='easm'){
    return {
      title:'Surface reduction',
      summary:`Remove or restrict exposed ${shortHost(e)}.`,
      steps:[
        `Confirm owner via WHOIS / CMDB`,
        `Firewall, decom, or move behind VPN`,
        `Update EASM inventory`,
        `Perimeter rescan in 24h`
      ],
      action:'Apply patch',
      actionDetail:'Creates takedown / firewall change request (demo).',
      auto:'Manual'
    };
  }
  return {
    title:'Remediation',
    summary:`Address ${e.title.slice(0,60)} per ${e.owner} runbook.`,
    steps:[`Assign ${meta.jira||e.jira}`,`Implement fix`,`Validate with ${e.tool}`,`Close exposure`],
    action:'Apply patch',
    actionDetail:'Queues standard remediation workflow (demo).',
    auto:'Semi-auto'
  };
}

function renderRemediationPanel(e){
  const r=buildRemediationSuggestion(e);
  const steps=r.steps.map(s=>`<li>${esc(s)}</li>`).join('');
  return `
    <aside class="corr-remediation-panel" data-remediation aria-label="Remediation suggestion">
      <div class="corr-remediation-head">
        ${icon('shield',16)}
        <span>Patch suggestion</span>
        <span class="corr-remediation-auto">${esc(r.auto)}</span>
      </div>
      <h6 class="corr-remediation-title">${esc(r.title)}</h6>
      <p class="corr-remediation-summary">${esc(r.summary)}</p>
      <ol class="corr-remediation-steps">${steps}</ol>
      <button type="button" class="corr-apply-patch-btn" data-apply-patch data-exp-id="${e.id}">
        ${icon('flow',14)}<span>${esc(r.action)}</span>
      </button>
      <p class="corr-remediation-status" data-patch-status hidden role="status"></p>
      <p class="corr-remediation-note">${esc(r.actionDetail)} Demo only — no changes applied.</p>
    </aside>`;
}

function bindRemediationPanel(panel,e){
  const btn=panel.querySelector('[data-apply-patch]');
  const status=panel.querySelector('[data-patch-status]');
  if(!btn||btn.dataset.bound==='1') return;
  btn.dataset.bound='1';
  const r=buildRemediationSuggestion(e);
  btn.addEventListener('click',()=>{
    if(btn.disabled) return;
    btn.disabled=true;
    btn.classList.add('is-busy');
    btn.querySelector('span').textContent='Queuing…';
    if(status){
      status.hidden=false;
      status.className='corr-remediation-status is-pending';
      status.textContent='Submitting patch request…';
    }
    window.setTimeout(()=>{
      btn.classList.remove('is-busy');
      btn.classList.add('is-done');
      btn.querySelector('span').textContent='Patch queued';
      if(status){
        status.className='corr-remediation-status is-success';
        status.innerHTML=`<strong>${esc(e.id)}</strong> · ${esc(r.title)} queued for ${esc(e.owner)} · ${esc(e.jira||seedMeta(e).jira)}`;
      }
    },900);
  });
}
