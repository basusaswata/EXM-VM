/** Dummy AI explainability chat (no LLM — canned contextual replies). */

function aiChatSuggestions(e){
  return [
    'Why is this exposure prioritized?',
    'Explain the attack path',
    'What should we fix first?',
    e.crossLinks?.length ? `How does ${e.crossLinks[0].id} relate?` : 'What is the blast radius?'
  ];
}

function aiChatInitialMessage(e){
  const pathTitle=attackPathSectionTitle(e.scannerId);
  return `I'm reviewing <strong>${esc(e.id)}</strong> (${esc(e.title)}). This ${esc(pathTitle.toLowerCase())} shows score <strong>${e.score.toFixed(1)}</strong> with ${e.kev ? 'KEV match' : 'no KEV'}${e.internet ? ' on an internet-facing path' : ''}. Ask about scoring, remediation, or any step in the diagrams.`;
}

function aiChatReply(e, raw){
  const q=String(raw||'').toLowerCase().trim();
  const host=shortHost(e);
  const meta=seedMeta(e);
  const links=(e.crossLinks||[]).map(c=>`${c.id} (${c.by})`).join(', ');

  if(!q) return 'Type a question or pick a suggested prompt below.';

  if(/score|priorit|why.*high|severity|rank/.test(q)){
    return `Exposure <strong>${esc(e.id)}</strong> is <strong>${e.score.toFixed(1)}</strong> (${esc(e.severity)}) because correlation weighted ${e.kev ? '<strong>KEV</strong>, ' : ''}${e.internet ? '<strong>internet reachability</strong>, ' : ''}asset criticality, and ${esc(e.scoring.expr)}. ${e.kev ? 'CISA KEV listing pushes this above CVSS-only backlog items.' : 'Without KEV, reachability and business tier drive rank.'}`;
  }
  if(/attack path|lateral|movement|chain|step/.test(q)){
    const scaNote=e.scannerId==='sca'
      ? ' For SCA, the attack path is <strong>internet → app → loaded component → impact</strong>. Repo/CI/build is where the dependency was <em>introduced</em> — see the correlation map and origin asset, not this lateral path.'
      : '';
    return `The lateral path starts at the exposed entry (${esc(host)}), moves through identity and pivot points, and ends at a crown-jewel target. Click hex nodes in the attack path diagram for stage-specific evidence. ${e.cve ? `Root issue: <strong>${esc(e.cve)}</strong>.` : ''}${scaNote}`;
  }
  if(/fix|remediat|patch|mitigat|what should|first/.test(q)){
    const fix=e.status==='Patched' ? 'Rescan shows clean — maintain regression tests.'
      : e.status==='Compensating control' ? 'Virtual patch is active; schedule permanent fix in next change window.'
      : `Assign to <strong>${esc(e.owner)}</strong> (${esc(e.jira || meta.jira)}). Target SLA: ${esc(e.sla)}.`;
    return `Recommended order: (1) confirm exploitability in prod, (2) ${fix} (3) validate with ${esc(e.tool)} rescan. ${e.buildPipeline ? 'Rebuild and promote artifact via the linked CI/CD pipeline.' : ''}`;
  }
  if(/correlat|hub|station|asset|build|identity/.test(q)){
    return `The correlation map links the scanner <strong>finding</strong> to <strong>asset</strong>${e.buildPipeline ? ', <strong>build pipeline</strong>' : ''}, <strong>identity</strong>, <strong>runtime</strong>, plus ownership, threat intel, and business context. Click any box to see station-level detail below the hub.`;
  }
  if(e.crossLinks?.length && (/cross|related|also found/.test(q) || e.crossLinks.some(c=>q.includes(c.id.toLowerCase())))){
    return `Related exposures: <strong>${esc(links)}</strong>. These share the same payments platform storyline — triage as one incident to avoid duplicate work.`;
  }
  if(/blast|radius|impact|crown|data/.test(q)){
    return `Blast radius includes ${esc(host)} and downstream Tier-0 dependencies (payments data, PCI-scoped stores). Identity paths amplify impact if service accounts have broad IAM or AD membership.`;
  }
  if(/kev|epss|cve|exploit/.test(q)){
    return `${e.cve ? `<strong>${esc(e.cve)}</strong> — ` : ''}KEV: ${e.kev ? '<strong>listed</strong>' : 'not listed'}. EPSS: ${e.epss != null ? e.epss.toFixed(2) : 'n/a'}. CVSS: ${e.cvss != null ? e.cvss : 'n/a'}. ${e.kev ? 'Treat as imminent patching candidate.' : 'Prioritize by reachability and asset tier.'}`;
  }
  if(/lsa|secret|credential|password/.test(q)){
    return `LSA secrets and cached credentials let an attacker escalate from a single host compromise to domain-wide access. Rotate service accounts, restrict lateral RDP/SMB, and verify EDR coverage on the path nodes.`;
  }
  if(/owner|jira|ticket|sla/.test(q)){
    return `Owner: <strong>${esc(e.owner)}</strong>. Ticket: <strong>${esc(e.jira || meta.jira)}</strong>. SLA: ${esc(e.sla)}. Status: ${esc(e.status)}.`;
  }

  const sc=SCANNERS.find(x=>x.id===e.scannerId);
  return `For <strong>${esc(e.id)}</strong> (${esc(sc?.name || e.scannerName)}), I can explain scoring, the correlation map, attack path steps, remediation order, or related findings. Try: "Why is this exposure prioritized?" or "Explain the attack path."`;
}

function renderAiExplainChat(e){
  const chips=aiChatSuggestions(e).map(s=>`<button type="button" class="ai-chat-chip" data-ai-chip>${esc(s)}</button>`).join('');
  return `
    <div class="ai-chat-dock ai-chat-dock--fixed" data-ai-chat>
      <button type="button" class="ai-chat-fab" data-ai-toggle aria-expanded="false" aria-controls="ai-chat-panel-${e.id}">
        <span class="ai-chat-fab-icon">${icon('zap',18)}</span>
        <span class="ai-chat-fab-label">Ask AI</span>
      </button>
      <div class="ai-chat-panel" id="ai-chat-panel-${e.id}" data-ai-panel hidden>
        <header class="ai-chat-header">
          <div class="ai-chat-header-title">
            <span class="attack-path-ai-badge">AI</span>
            <span>Explainability</span>
          </div>
          <button type="button" class="ai-chat-close" data-ai-close aria-label="Close chat">&times;</button>
        </header>
        <div class="ai-chat-messages" data-ai-messages role="log" aria-live="polite"></div>
        <div class="ai-chat-chips" data-ai-chips>${chips}</div>
        <form class="ai-chat-form" data-ai-form>
          <input type="text" class="ai-chat-input" data-ai-input placeholder="Ask about this exposure…" autocomplete="off" aria-label="Chat message"/>
          <button type="submit" class="ai-chat-send" aria-label="Send message">${icon('flow',16)}</button>
        </form>
        <p class="ai-chat-disclaimer">Demo assistant — scripted replies only, no live model.</p>
      </div>
    </div>`;
}

function aiChatAppendMessage(container, role, html){
  const row=document.createElement('div');
  row.className=`ai-chat-msg ai-chat-msg--${role}`;
  row.innerHTML=`<div class="ai-chat-bubble">${html}</div>`;
  container.appendChild(row);
  container.scrollTop=container.scrollHeight;
}

function aiChatShowTyping(container){
  const row=document.createElement('div');
  row.className='ai-chat-msg ai-chat-msg--assistant ai-chat-msg--typing';
  row.dataset.typing='1';
  row.innerHTML='<div class="ai-chat-bubble"><span class="ai-chat-dots"><span></span><span></span><span></span></span></div>';
  container.appendChild(row);
  container.scrollTop=container.scrollHeight;
  return row;
}

function bindAiExplainChat(root, e){
  const dock=root?.matches?.('[data-ai-chat]')?root:root?.querySelector?.('[data-ai-chat]');
  if(!dock||dock.dataset.bound==='1') return;
  dock.dataset.bound='1';

  const fab=dock.querySelector('[data-ai-toggle]');
  const chatPanel=dock.querySelector('[data-ai-panel]');
  const messages=dock.querySelector('[data-ai-messages]');
  const form=dock.querySelector('[data-ai-form]');
  const input=dock.querySelector('[data-ai-input]');
  if(!fab||!chatPanel) return;
  let seeded=false;

  const isOpen=()=>dock.classList.contains('is-open');

  const setOpen=(open)=>{
    dock.classList.toggle('is-open',open);
    chatPanel.classList.toggle('is-open',open);
    if(open){
      chatPanel.removeAttribute('hidden');
      fab.setAttribute('aria-expanded','true');
      if(!seeded&&messages){
        seeded=true;
        aiChatAppendMessage(messages,'assistant',aiChatInitialMessage(e));
      }
      setTimeout(()=>input?.focus(),80);
    }else{
      chatPanel.setAttribute('hidden','');
      fab.setAttribute('aria-expanded','false');
    }
  };

  const sendUser=(text)=>{
    const t=String(text||'').trim();
    if(!t||!messages) return;
    aiChatAppendMessage(messages,'user',esc(t));
    const typing=aiChatShowTyping(messages);
    window.setTimeout(()=>{
      typing.remove();
      aiChatAppendMessage(messages,'assistant',aiChatReply(e,t));
    }, 520 + Math.min(t.length * 8, 400));
  };

  dock.addEventListener('click',(ev)=>{
    if(ev.target.closest('[data-ai-close]')){
      ev.preventDefault();
      ev.stopPropagation();
      setOpen(false);
      return;
    }
    if(ev.target.closest('[data-ai-toggle]')){
      ev.preventDefault();
      ev.stopPropagation();
      setOpen(!isOpen());
      return;
    }
    const chip=ev.target.closest('[data-ai-chip]');
    if(chip){
      ev.preventDefault();
      setOpen(true);
      sendUser(chip.textContent);
    }
  });

  form?.addEventListener('submit',ev=>{
    ev.preventDefault();
    const t=input.value;
    input.value='';
    sendUser(t);
  });

  document.querySelectorAll('[data-ai-open]').forEach(btn=>{
    btn.addEventListener('click',(ev)=>{
      ev.preventDefault();
      setOpen(true);
    });
  });

  if(!window.__emAiChatEscapeInit){
    window.__emAiChatEscapeInit=true;
    document.addEventListener('keydown',(ev)=>{
      if(ev.key!=='Escape') return;
      const openDock=document.querySelector('[data-ai-chat].is-open');
      if(!openDock) return;
      const panel=openDock.querySelector('[data-ai-panel]');
      const toggle=openDock.querySelector('[data-ai-toggle]');
      openDock.classList.remove('is-open');
      panel?.classList.remove('is-open');
      panel?.setAttribute('hidden','');
      toggle?.setAttribute('aria-expanded','false');
    });
  }
}
