// Instrumentation for the control-provenance audit.
//
// Loaded BEFORE the app script via addInitScript, so it can intercept the two
// mechanisms the UI uses to attach behaviour:
//
//   1. el.addEventListener('click', fn)      -- 171 call sites in app.js
//   2. el.onclick = fn  and onclick="..."   -- inline attributes
//
// Why hook the prototype rather than grep app.js: updateTeamBadges() builds ids
// as `${team}Badge`, so a source-text grep for literal ids reports those badges
// as dead. Hooking EventTarget.prototype.addEventListener records what was
// actually attached to whatever elements really exist, so dynamic construction
// is visible. That class of false positive is what made the grep list a
// lower bound rather than a finding.
//
// Records, per element (keyed by a stable per-element ordinal, because ids are
// not unique and often absent):
//   - attached listener types
//   - whether it sits inside a delegated ancestor that has a listener
//
// __calls (from stub.js) remains the ground truth for "did the backend get
// called", so provenance here is never inferred -- it is only used to report
// *why* a control did nothing.

(() => {
  const attached = new Map(); // Element -> Set<string> of event types
  const ordinal = new WeakMap();
  let next = 0;

  const keyOf = (el) => {
    if (!ordinal.has(el)) ordinal.set(el, next++);
    return `${el.tagName.toLowerCase()}#${ordinal.get(el)}`;
  };

  const label = (el) => {
    if (!el || !el.tagName) return 'unknown';
    const id = el.id ? `#${el.id}` : '';
    const cls = (typeof el.className === 'string' && el.className.trim())
      ? `.${el.className.trim().split(/\s+/).slice(0, 2).join('.')}`
      : '';
    const txt = (el.textContent || '').trim().slice(0, 40).replace(/\s+/g, ' ');
    return `${el.tagName.toLowerCase()}${id}${cls}${txt ? ` "${txt}"` : ''}`;
  };

  const add = (el, type) => {
    if (!el || typeof el.addEventListener !== 'function') return;
    if (!attached.has(el)) attached.set(el, new Set());
    attached.get(el).add(type);
  };

  // 1. addEventListener -- hooked on the prototype so it is seen no matter
  //    which element (static or dynamically built) receives it.
  const origAdd = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function (type, ...rest) {
    try { add(this, String(type)); } catch { /* never break the app */ }
    return origAdd.call(this, type, ...rest);
  };

  // 2. on* property assignment (onclick = fn, oninput = fn, ...)
  for (const type of ['click', 'input', 'change', 'submit', 'focus', 'blur', 'keydown', 'keyup']) {
    const prop = `on${type}`;
    const desc = Object.getOwnPropertyDescriptor(EventTarget.prototype, prop);
    if (!desc || !desc.set) continue;
    Object.defineProperty(EventTarget.prototype, prop, {
      ...desc,
      set(v) { if (v) { try { add(this, type); } catch { /* ignore */ } } return desc.set.call(this, v); },
    });
  }

  // Delegation: a listener on an ancestor covers this element. Walk up, and
  // also check the two app-level delegation roots.
  const hasCoveringListener = (el) => {
    let n = el;
    while (n && n !== document) {
      const set = attached.get(n);
      if (set && set.size) {
        // Click/change/input are the types the app delegates.
        if ([...set].some(t => ['click', 'change', 'input', 'submit'].includes(t))) {
          return true;
        }
      }
      n = n.parentElement;
    }
    return false;
  };

  // Inline onclick="fn(...)" resolves against window; a control wired this way
  // has a handler even though nothing was attached via addEventListener.
  const inlineHandler = (el) => {
    const attr = el.getAttribute && el.getAttribute('onclick');
    return attr && attr.trim().length > 0 ? attr.trim().slice(0, 60) : null;
  };

  window.__audit = {
    keyOf,
    label,
    /** Direct listeners recorded on this exact element. */
    direct: (el) => [...(attached.get(el) || [])],
    /** True if this element or an ancestor has a click-ish listener. */
    covered: hasCoveringListener,
    inline: inlineHandler,
    /** Summary of everything currently attached, for debugging. */
    dump: () => {
      const out = [];
      attached.forEach((types, el) => {
        if (el.isConnected) out.push({ el: label(el), types: [...types] });
      });
      return out;
    },
  };

  // Success/failure vocabulary. Used to detect a control that CLAIMS success.
  // Deliberately broad; a match alone is not a verdict, it is a candidate that
  // the caller must confirm against the __calls delta.
  window.__successWords = [
    'success', 'successful', 'complete', 'completed', 'done', 'ok', '✓', '✔',
    'saved', 'applied', 'finished', 'exported', 'started', 'acknowledged',
    'connected', 'verified', 'passed', 'online', 'enabled', 'activated',
  ];
})();
window.__calls = {};
window.__TAURI__ = { invoke: async (cmd, args) => {
  window.__calls[cmd] = (window.__calls[cmd] || 0) + 1;
  const findings = window.__findings = window.__findings || [
    { id:'f1', title:'SQL Injection in login form', severity:'CRITICAL', status:'new', category:'web',
      cwe_id:'CWE-89', cve_ids:['CVE-2024-0001'], description:'Unparameterised query.',
      remediation:'Use prepared statements.', evidence:[{kind:'x',description:'payload: id=1 OR 1=1',data:null,captured_at:'now'}],
      mitre_techniques:['T1190'], created_at:'2026-01-20T10:00:00Z', scan_id:'scan_1', updated_at:'2026-01-20T10:00:00Z' },
    { id:'f2', title:'Reflected XSS in search', severity:'HIGH', status:'confirmed', category:'web',
      cwe_id:'CWE-79', cve_ids:[], description:'Unescaped input.', remediation:'Encode output.', evidence:[],
      mitre_techniques:['T1059.007'], created_at:'2025-11-02T10:00:00Z', scan_id:'scan_1', updated_at:'2026-01-05T10:00:00Z' },
    { id:'f3', title:'Missing frame options', severity:'MEDIUM', status:'new', category:'web',
      cwe_id:null, cve_ids:[], description:'Clickjacking possible.', remediation:'Add CSP frame-ancestors.',
      evidence:[], mitre_techniques:[], created_at:'2026-01-30T10:00:00Z', scan_id:'scan_1', updated_at:'2026-01-30T10:00:00Z' },
  ];
  switch (cmd) {
    case 'get_database_status':
      return { available:true, schema_version:2, path:'/home/u/.local/share/siterecorder/siterecorder.db', operator_id:'op-1' };
    case 'list_findings': return findings;
    case 'get_finding': return findings.find(f => f.id === args.id) || null;
    case 'update_finding_status': {
      const f = findings.find(x => x.id === args.id);
      if (f) f.status = args.status;
      return null;
    }
    case 'create_finding':
      findings.push({ id:'f-new', title:args.title, severity:args.severity, status:'new', category:args.category,
        cwe_id:args.cweId||null, cve_ids:[], description:args.description, remediation:args.remediation,
        evidence:[], mitre_techniques:[], created_at:new Date().toISOString(), scan_id:null,
        updated_at:new Date().toISOString() });
      return findings[findings.length-1];
    case 'findings_severity_breakdown': return { critical:1, high:1, medium:1, low:0, info:0, total:3 };
    case 'findings_by_category': return [['web', 3]];
    case 'findings_attack_coverage':
      return { techniques:['T1059.007','T1190'], unmapped:['one or more findings'], score:null, complete:false };
    case 'compliance_assessment':
      return { assessments:[{ framework_id:'owasp-top-10-2021', open_findings:3,
          severity_breakdown:{'CRITICAL':1,'HIGH':1,'MEDIUM':1}, unmapped_findings:1,
          controls_with_findings:['A01:2021-Broken Access Control','A03:2021-Injection'],
          controls_without_findings:['A02:2021-Cryptographic Failures','A04:2021-Insecure Design'],
          readiness_score:null, complete:false,
          notes:['Controls without findings are NOT evidence of compliance: the scanner exercises only the checks it implements.',
                 'CWE-to-category mappings are derived from operator knowledge, not a normative crosswalk. Verify before reporting externally.'] }],
        frameworks_pending:['NIST 800-53','SOC 2 Trust Services Criteria','PCI-DSS v4.0','ISO 27001 Annex A'],
        mapping_confidence:'medium' };
    case 'metrics_report':
      return { generated_at:new Date().toISOString(),
        vulnerability:{ total:3, open:2, by_severity:{CRITICAL:1,HIGH:1,MEDIUM:1},
          aging:{d0_30:1,d31_60:0,d61_90:1,d90_plus:0,oldest_open_days:90}, false_positive_rate:0,
          remediation_rate:0.5, findings_per_asset:1, assets_total:1, assets_with_findings:1 },
        findings_by_category:[['web',3]],
        discovery_trend:[['2026-01-28',0],['2026-01-29',1],['2026-01-30',1]],
        unavailable:[{ name:'MTTD (mean time to detect)', reason:'Requires a detection event correlated with a finding.' },
                     { name:'MTTR (mean time to respond)', reason:'Requires recorded incidents with response timestamps.' },
                     { name:'Patch compliance', reason:'Requires a software inventory per asset.' }] };
    case 'risk_register':
      return { generated_at:new Date().toISOString(),
        entries:[
          { id:'risk_f1', finding_id:'f1', title:'SQL Injection in login form', category:'web', asset_id:'a1',
            likelihood:'almostCertain', impact:'severe', score:25, level:'critical', treatment:'undecided', owner:null,
            impact_basis:'asset criticality: critical' },
          { id:'risk_f2', finding_id:'f2', title:'Reflected XSS in search', category:'web', asset_id:'a1',
            likelihood:'likely', impact:'major', score:16, level:'high', treatment:'mitigate', owner:null,
            impact_basis:'asset criticality: high' },
          { id:'risk_f3', finding_id:'f3', title:'Missing frame options', category:'web', asset_id:null,
            likelihood:'possible', impact:'moderate', score:9, level:'medium', treatment:'undecided', owner:null,
            impact_basis:'no asset criticality recorded; defaulted to Moderate' } ],
        by_level:{critical:1, high:1, medium:1}, by_treatment:{mitigate:1, undecided:2}, residual_score:50,
        unavailable_models:[
          { name:'FAIR (Factor Analysis of Information Risk)', reason:'Needs asset values and business impact factors.' },
          { name:'Monte Carlo simulation', reason:'Needs a distribution of loss magnitudes.' } ],
        notes:['Scores come from a published severity-to-likelihood and criticality-to-impact mapping, not from breach data. They rank work; they are not actuarial values.',
                 'Residual score assumes no treatment has been applied, since none is modelled in this build.'] };
    case 'policy_library':
      return { policies:[
          { id:'pol_sec_001', code:'SEC-001', title:'Access Control Policy', summary:'Starter outline.', status:'draft', version:1, cadence:'annual', owner:null, created_at:'2026-01-01T00:00:00Z', updated_at:'2026-01-01T00:00:00Z', next_review:'2026-06-01T00:00:00Z' },
          { id:'pol_sec_002', code:'SEC-002', title:'Secure Development Lifecycle', summary:'Starter outline.', status:'draft', version:1, cadence:'annual', owner:null, created_at:'2026-01-01T00:00:00Z', updated_at:'2026-01-01T00:00:00Z', next_review:'2026-06-01T00:00:00Z' },
          { id:'pol_sec_003', code:'SEC-003', title:'Incident Response Plan', summary:'Starter outline.', status:'draft', version:1, cadence:'annual', owner:null, created_at:'2026-01-01T00:00:00Z', updated_at:'2026-01-01T00:00:00Z', next_review:'2025-06-01T00:00:00Z' } ],
        drafts:3, active:0, retired:0, overdue_for_review:['SEC-003'],
        target_library_size:50, library_complete:false,
        notes:['The library holds 3 starter policies against the 50-policy target in 5.3.',
               'Every policy is a draft until a named owner reviews and approves it.',
               'Library is INCOMPLETE. It is reported as such rather than padded with unreviewed documents.'] };
    case 'acknowledge_policy': return null;
    case 'list_chained_audit_entries':
      return [ { id:'a1', timestamp:'2026-01-31T09:00:00Z', actor:'op-1', action:'app_start', target:null, details:'database opened', ip_address:null, prev_hash:'GENESIS', hash:'abc123' },
               { id:'a2', timestamp:'2026-01-31T09:05:00Z', actor:'op-1', action:'finding_created', target:'f1', details:'SQL Injection (CRITICAL)', ip_address:null, prev_hash:'abc123', hash:'def456' } ];
    case 'verify_audit_integrity': return { valid:true, entries_checked:2, first_invalid_seq:null, reason:null };
    case 'bounty_status':
      // Mirror the real backend: ChainScope is absent, so the UI must render
      // the disabled reason and hide its controls. Returning available:true
      // here would let the audit pass against a state the app can never reach.
      return { available: false, binary: null,
        reason: 'ChainScope is unavailable, so bounty triage is disabled. none of ["cs", "chain-scope"] responded to `--version` on PATH. No program or hotspot data is shown, because none was retrieved.' };
    case 'get_status': return { is_running:false, session_id:'', current_url:'', pages_visited:0, pages_discovered:0 };
    default: return null;
  }
}};
