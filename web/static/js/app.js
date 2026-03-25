/* =========================================================================
   OT Nation - SCADA Exposure Discovery Platform
   Single Page Application — Vanilla JS, hash-based routing
   ========================================================================= */

'use strict';

/* -------------------------------------------------------------------------
   Utilities
   ------------------------------------------------------------------------- */
const Utils = {
  formatNumber(n) {
    if (n == null || n === undefined) return '0';
    return Number(n).toLocaleString('en-US');
  },

  formatRelativeTime(dateStr) {
    if (!dateStr) return '—';
    const date = new Date(dateStr);
    if (isNaN(date)) return '—';
    const now = Date.now();
    const diff = Math.floor((now - date.getTime()) / 1000);
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  },

  formatDuration(startStr, endStr) {
    if (!startStr) return '—';
    const start = new Date(startStr);
    const end = endStr ? new Date(endStr) : new Date();
    if (isNaN(start)) return '—';
    const secs = Math.floor((end - start) / 1000);
    if (secs < 60) return `${secs}s`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
    return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
  },

  formatISODate(dateStr) {
    if (!dateStr) return '—';
    const d = new Date(dateStr);
    if (isNaN(d)) return '—';
    return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
  },

  escapeHtml(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  },

  debounce(fn, ms) {
    let timer;
    return function (...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), ms);
    };
  },

  animateNumber(el, target, duration = 800) {
    const start = parseInt(el.textContent.replace(/,/g, ''), 10) || 0;
    const end = parseInt(String(target).replace(/,/g, ''), 10) || 0;
    if (start === end) return;
    const startTime = performance.now();
    const step = (now) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = Math.round(start + (end - start) * eased);
      el.textContent = Utils.formatNumber(current);
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  },

  parseTags(tagsRaw) {
    if (!tagsRaw) return [];
    if (Array.isArray(tagsRaw)) return tagsRaw;
    try {
      const parsed = JSON.parse(tagsRaw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }
};

/* -------------------------------------------------------------------------
   API Client
   ------------------------------------------------------------------------- */
class API {
  constructor(baseURL = '/api/v1') {
    this.base = baseURL;
    this._inflight = new Set();
  }

  async _fetch(method, path, body, opts = {}) {
    const url = `${this.base}${path}`;
    const config = {
      method,
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    };
    if (body != null) config.body = JSON.stringify(body);

    try {
      const res = await fetch(url, config);
      if (res.status === 204) return null;
      const ct = res.headers.get('content-type') || '';
      if (!ct.includes('application/json')) {
        const text = await res.text();
        const e = new Error(`Server returned non-JSON response (HTTP ${res.status}). Check the server is running the latest build.`);
        e.status = res.status;
        e.body = text.slice(0, 200);
        throw e;
      }
      const data = await res.json();
      if (!res.ok) {
        const err = new Error(data.error || `HTTP ${res.status}`);
        err.status = res.status;
        err.data = data;
        throw err;
      }
      return data;
    } catch (err) {
      if (err.name === 'TypeError') {
        const e = new Error('Network error: unable to reach the server');
        e.status = 0;
        throw e;
      }
      throw err;
    }
  }

  get(path)            { return this._fetch('GET',    path); }
  post(path, body)     { return this._fetch('POST',   path, body); }
  put(path, body)      { return this._fetch('PUT',    path, body); }
  patch(path, body)    { return this._fetch('PATCH',  path, body); }
  delete(path)         { return this._fetch('DELETE', path); }

  // ---- Identities ----
  listIdentities()                    { return this.get('/identities'); }
  createIdentity(data)                { return this.post('/identities', data); }
  getIdentity(id)                     { return this.get(`/identities/${id}`); }
  updateIdentity(id, data)            { return this.put(`/identities/${id}`, data); }
  deleteIdentity(id)                  { return this.delete(`/identities/${id}`); }

  // ---- Seeds ----
  listSeeds(identityId)               { return this.get(`/identities/${identityId}/seeds`); }
  createSeed(identityId, data)        { return this.post(`/identities/${identityId}/seeds`, data); }

  // ---- Runs ----
  listRuns(identityId)                { return this.get(`/identities/${identityId}/runs`); }
  createRun(identityId, data)         { return this.post(`/identities/${identityId}/runs`, data); }
  getRun(runId)                       { return this.get(`/runs/${runId}`); }

  // ---- Assets ----
  listAssets(identityId, params = {}) {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => { if (v != null && v !== '') qs.set(k, v); });
    const query = qs.toString() ? `?${qs}` : '';
    return this.get(`/identities/${identityId}/assets${query}`);
  }
  getAsset(assetId)                   { return this.get(`/assets/${assetId}`); }
  getAssetScanResults(assetId)        { return this.get(`/assets/${assetId}/scan-results`); }
  getAssetFindings(assetId)           { return this.get(`/assets/${assetId}/findings`); }
  getAssetEnrichment(assetId)         { return this.get(`/assets/${assetId}/enrichment`); }
  getAssetDNSRecords(assetId)         { return this.get(`/assets/${assetId}/dns-records`); }
  getAssetSubdomains(assetId)         { return this.get(`/assets/${assetId}/subdomains`); }
  enumerateAsset(assetId)             { return this.post(`/assets/${assetId}/enumerate`, {}); }
  lookupAssetByValue(identityId, value) { return this.get(`/identities/${identityId}/assets/lookup?value=${encodeURIComponent(value)}`); }
  deepScanAsset(assetId)              { return this.post(`/assets/${assetId}/deep-scan`, {}); }
  portScanAsset(assetId, profile)     { return this.post(`/assets/${assetId}/port-scan?profile=${profile}`, {}); }
  getTLSScan(assetId)                 { return this.get(`/assets/${assetId}/tls-scan`); }
  tlsScanAsset(assetId)               { return this.post(`/assets/${assetId}/tls-scan`, {}); }
  getSecurityTrails(assetId)          { return this.get(`/assets/${assetId}/securitytrails`); }
  securityTrailsEnrich(assetId)       { return this.post(`/assets/${assetId}/securitytrails`, {}); }
  getCrtSh(assetId)                   { return this.get(`/assets/${assetId}/crtsh`); }
  crtShLookup(assetId)                { return this.post(`/assets/${assetId}/crtsh`, {}); }
  getHTTPProbe(assetId)               { return this.get(`/assets/${assetId}/http-probe`); }
  httpProbeAsset(assetId)             { return this.post(`/assets/${assetId}/http-probe`, {}); }
  getSNMP(assetId)                    { return this.get(`/assets/${assetId}/snmp`); }
  snmpEnum(assetId)                   { return this.post(`/assets/${assetId}/snmp`, {}); }
  getOTProbe(assetId)                 { return this.get(`/assets/${assetId}/ot-probe`); }
  otProbe(assetId)                    { return this.post(`/assets/${assetId}/ot-probe`, {}); }
  getBGP(assetId)                     { return this.get(`/assets/${assetId}/bgp`); }
  bgpLookup(assetId)                  { return this.post(`/assets/${assetId}/bgp`, {}); }
  getIPWhois(assetId)                 { return this.get(`/assets/${assetId}/ip-whois`); }
  ipWhoisLookup(assetId)              { return this.post(`/assets/${assetId}/ip-whois`, {}); }
  getCVECorrelate(assetId)            { return this.get(`/assets/${assetId}/cve-correlate`); }
  cveCorrelate(assetId)               { return this.post(`/assets/${assetId}/cve-correlate`, {}); }
  getVulnNotes(assetId)               { return this.get(`/assets/${assetId}/vuln-notes`); }
  searchExploits(cveId)               { return this.get(`/cves/${encodeURIComponent(cveId)}/exploits`); }

  // ---- OT Intel ----
  getIEC61850(id)                     { return this.get(`/assets/${id}/iec61850`); }
  iec61850Scan(id)                    { return this.post(`/assets/${id}/iec61850`, {}); }
  getHistorian(id)                    { return this.get(`/assets/${id}/historian`); }
  historianDetect(id)                 { return this.post(`/assets/${id}/historian`, {}); }
  getHMI(id)                          { return this.get(`/assets/${id}/hmi`); }
  hmiFingerprint(id)                  { return this.post(`/assets/${id}/hmi`, {}); }
  getICSCert(id)                      { return this.get(`/assets/${id}/icscert`); }
  icsCertSearch(id)                   { return this.post(`/assets/${id}/icscert`, {}); }
  getNERCCIP(id)                      { return this.get(`/assets/${id}/nerc-cip`); }
  setNERCCIP(id, data)                { return this.put(`/assets/${id}/nerc-cip`, data); }
  getZones(identId)                   { return this.get(`/identities/${identId}/zones`); }

  // ---- New Protocol Scanners ----
  getIEC104(id)             { return this.get(`/assets/${id}/iec104`); }
  iec104Scan(id)            { return this.post(`/assets/${id}/iec104`, {}); }
  getModbusDeep(id)         { return this.get(`/assets/${id}/modbus-deep`); }
  modbusDeepScan(id)        { return this.post(`/assets/${id}/modbus-deep`, {}); }
  getDNP3Deep(id)           { return this.get(`/assets/${id}/dnp3-deep`); }
  dnp3DeepScan(id)          { return this.post(`/assets/${id}/dnp3-deep`, {}); }
  getICCP(id)               { return this.get(`/assets/${id}/iccp`); }
  iccpScan(id)              { return this.post(`/assets/${id}/iccp`, {}); }
  getEtherNetIPDeep(id)     { return this.get(`/assets/${id}/enip-deep`); }
  etherNetIPDeepScan(id)    { return this.post(`/assets/${id}/enip-deep`, {}); }
  getProfinet(id)           { return this.get(`/assets/${id}/profinet`); }
  profinetScan(id)          { return this.post(`/assets/${id}/profinet`, {}); }
  getOPCUA(id)              { return this.get(`/assets/${id}/opcua`); }
  opcuaScan(id)             { return this.post(`/assets/${id}/opcua`, {}); }
  getDefaultCreds(id)       { return this.get(`/assets/${id}/default-creds`); }
  testDefaultCreds(id)      { return this.post(`/assets/${id}/default-creds`, {}); }
  getCensys(id)             { return this.get(`/assets/${id}/censys`); }
  fetchCensys(id)           { return this.post(`/assets/${id}/censys`, {}); }
  getAssetHistory(id)       { return this.get(`/assets/${id}/history`); }
  autoScan(id)              { return this.post(`/assets/${id}/auto-scan`, {}); }
  reportPDFUrl(id)          { return `${this.base}/identities/${id}/report.pdf`; }

  // ---- Findings ----
  listFindings(identityId, params = {}) {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => { if (v != null && v !== '') qs.set(k, v); });
    const query = qs.toString() ? `?${qs}` : '';
    return this.get(`/identities/${identityId}/findings${query}`);
  }
  getFinding(findingId)               { return this.get(`/findings/${findingId}`); }
  patchFinding(findingId, data)       { return this.patch(`/findings/${findingId}`, data); }
}

/* -------------------------------------------------------------------------
   Router
   ------------------------------------------------------------------------- */
class Router {
  constructor() {
    this._routes = [];
    this._current = null;
    window.addEventListener('hashchange', () => this._dispatch());
  }

  on(pattern, handler) {
    this._routes.push({ pattern, handler, regex: this._compile(pattern) });
    return this;
  }

  _compile(pattern) {
    const src = pattern
      .replace(/[-[\]{}()*+?.,\\^$|#\s]/g, (m) => (m === ':' ? m : `\\${m}`))
      .replace(/:([^/]+)/g, '(?<$1>[^/]+)');
    return new RegExp(`^${src}$`);
  }

  navigate(path) {
    window.location.hash = path;
  }

  _dispatch() {
    const hash = window.location.hash.slice(1) || '/';
    for (const route of this._routes) {
      const m = route.regex.exec(hash);
      if (m) {
        this._current = { path: hash, params: m.groups || {} };
        route.handler(this._current.params, hash);
        return;
      }
    }
    // fallback: 404-like
    const fallback = this._routes.find(r => r.pattern === '*');
    if (fallback) fallback.handler({}, hash);
  }

  start() {
    this._dispatch();
  }
}

/* -------------------------------------------------------------------------
   Component: renderSeverityBadge
   ------------------------------------------------------------------------- */
function renderSeverityBadge(severity) {
  const s = (severity || 'informational').toLowerCase();
  const labels = {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    informational: 'Info',
  };
  return `<span class="badge badge-${s}">${Utils.escapeHtml(labels[s] || s)}</span>`;
}

/* -------------------------------------------------------------------------
   Component: renderStatCard
   ------------------------------------------------------------------------- */
function renderStatCard(label, value, sublabel, variant) {
  const cls = variant ? ` ${variant}` : '';
  return `
    <div class="stat-card${cls}">
      <div class="stat-label">${Utils.escapeHtml(label)}</div>
      <div class="stat-value" data-stat-value="${Utils.escapeHtml(String(value))}">${Utils.formatNumber(value)}</div>
      ${sublabel ? `<div class="stat-sublabel">${Utils.escapeHtml(sublabel)}</div>` : ''}
    </div>
  `;
}

/* -------------------------------------------------------------------------
   Component: renderEmptyState
   ------------------------------------------------------------------------- */
function renderEmptyState(message, desc, actionHtml) {
  return `
    <div class="empty-state">
      <div class="empty-state-icon">&#9711;</div>
      <div class="empty-state-title">${Utils.escapeHtml(message)}</div>
      ${desc ? `<div class="empty-state-desc">${Utils.escapeHtml(desc)}</div>` : ''}
      ${actionHtml || ''}
    </div>
  `;
}

/* -------------------------------------------------------------------------
   Component: renderNav
   ------------------------------------------------------------------------- */
function renderNav(activePage) {
  const links = [
    { id: 'identities', label: 'Identities', hash: '#/identities' },
    { id: 'assets',     label: 'Assets',     hash: '#/assets' },
    { id: 'findings',   label: 'Findings',   hash: '#/findings' },
  ];

  const linksHtml = links.map(l => `
    <a class="nav-link${activePage === l.id ? ' active' : ''}" href="${l.hash}">${l.label}</a>
  `).join('');

  return `
    <nav class="nav">
      <div style="display:flex;align-items:center;gap:8px">
        <button class="nav-sidebar-toggle" title="Toggle sidebar" id="btn-sidebar-toggle">&#9776;</button>
        <a class="nav-logo" href="#/identities">
          <div class="nav-logo-text">OT <span>NATION</span></div>
        </a>
      </div>
      <div class="nav-links">${linksHtml}</div>
      <div class="nav-actions">
        <span class="nav-badge">SCADA Exposure Platform</span>
      </div>
    </nav>
  `;
}

/* -------------------------------------------------------------------------
   Component: renderSidebar
   ------------------------------------------------------------------------- */
function renderSidebar(activePage, ctx) {
  const identityId = ctx && ctx.identityId;

  const mainItems = [
    { id: 'identities', icon: '&#9699;', label: 'Identities', hash: '#/identities' },
    { id: 'assets',     icon: '&#11041;', label: 'All Assets',  hash: '#/assets' },
    { id: 'findings',   icon: '&#9651;', label: 'All Findings', hash: '#/findings' },
  ];

  const mainHtml = mainItems.map(item => `
    <a class="sidebar-item${activePage === item.id ? ' active' : ''}" href="${item.hash}">
      <span class="sidebar-icon">${item.icon}</span>
      ${Utils.escapeHtml(item.label)}
    </a>
  `).join('');

  let contextHtml = '';
  if (identityId && ctx.identity) {
    const id = ctx.identity;
    contextHtml = `
      <div class="sidebar-divider"></div>
      <div class="sidebar-section">
        <div class="sidebar-section-label">Current Identity</div>
        <a class="sidebar-item${activePage === 'identity-detail' ? ' active' : ''}"
           href="#/identities/${identityId}">
          <span class="sidebar-icon">&#9698;</span>
          <span class="truncate">${Utils.escapeHtml(id.name || 'Identity')}</span>
        </a>
        <a class="sidebar-item${activePage === 'identity-assets' ? ' active' : ''}"
           href="#/identities/${identityId}/assets">
          <span class="sidebar-icon">&#11041;</span>
          Assets
        </a>
        <a class="sidebar-item${activePage === 'identity-findings' ? ' active' : ''}"
           href="#/identities/${identityId}/findings">
          <span class="sidebar-icon">&#9651;</span>
          Findings
        </a>
      </div>
    `;
  }

  return `
    <aside class="sidebar">
      <div class="sidebar-section">
        <div class="sidebar-section-label">Navigation</div>
        ${mainHtml}
      </div>
      ${contextHtml}
    </aside>
  `;
}

/* -------------------------------------------------------------------------
   Component: renderIdentitiesList
   ------------------------------------------------------------------------- */
function renderIdentitiesList(identities) {
  if (!identities || identities.length === 0) {
    return renderEmptyState(
      'No identities configured',
      'Create an identity to start discovering SCADA assets and exposures.',
      `<button class="btn btn-primary" onclick="App.showCreateIdentityModal()">New Identity</button>`
    );
  }

  const rows = identities.map(id => {
    const tags = Utils.parseTags(id.tags);
    const tagsHtml = tags.slice(0, 3).map(t =>
      `<span class="tag">${Utils.escapeHtml(String(t))}</span>`
    ).join('');

    return `
      <tr>
        <td class="primary">
          <a class="inline-link" href="#/identities/${Utils.escapeHtml(id.id)}">${Utils.escapeHtml(id.name)}</a>
        </td>
        <td>${Utils.escapeHtml(id.org_name || '—')}</td>
        <td>
          ${id.sector ? `<span class="badge badge-type">${Utils.escapeHtml(id.sector)}</span>` : '—'}
        </td>
        <td>
          <div class="tag-list">${tagsHtml}${tags.length > 3 ? `<span class="tag">+${tags.length - 3}</span>` : ''}</div>
        </td>
        <td><span class="text-muted">—</span></td>
        <td title="${Utils.escapeHtml(Utils.formatISODate(id.created_at))}">${Utils.formatRelativeTime(id.created_at)}</td>
        <td>
          <div class="data-table-actions">
            <a href="#/identities/${Utils.escapeHtml(id.id)}" class="btn btn-ghost btn-sm">View</a>
            <button class="btn btn-danger btn-sm" onclick="App.confirmDeleteIdentity('${Utils.escapeHtml(id.id)}', '${Utils.escapeHtml(id.name)}')">Delete</button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  return `
    <div class="table-wrapper">
      <table class="data-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Organization</th>
            <th>Sector</th>
            <th>Tags</th>
            <th>Last Run</th>
            <th>Created</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

/* -------------------------------------------------------------------------
   Component: renderIdentityDetail
   ------------------------------------------------------------------------- */
function renderIdentityDetail(identity, runs, seeds) {
  const tags = Utils.parseTags(identity.tags);
  const tagsHtml = tags.length
    ? tags.map(t => `<span class="tag">${Utils.escapeHtml(String(t))}</span>`).join('')
    : '<span class="text-muted">No tags</span>';

  const latestRun = runs && runs.length > 0 ? runs[0] : null;
  const latestRunHtml = latestRun ? `
    <a class="inline-link" href="#/identities/${Utils.escapeHtml(identity.id)}/runs/${Utils.escapeHtml(latestRun.id)}">
      View latest run
    </a>
  ` : '<span class="text-muted">No runs yet</span>';

  const seedsHtml = seeds && seeds.length > 0
    ? seeds.map(s => `
        <div class="scan-result-card">
          <span class="badge badge-type">${Utils.escapeHtml(s.type)}</span>
          <span class="mono text-primary">${Utils.escapeHtml(s.value)}</span>
          <span class="text-muted" style="margin-left:auto;font-size:11px"
            title="${Utils.escapeHtml(Utils.formatISODate(s.created_at))}">${Utils.formatRelativeTime(s.created_at)}</span>
        </div>
      `).join('')
    : '<div class="text-muted" style="padding:12px">No seeds configured</div>';

  const runsHtml = runs && runs.length > 0
    ? `
      <div class="table-wrapper">
        <table class="data-table">
          <thead>
            <tr>
              <th>Run ID</th>
              <th>Status</th>
              <th>Triggered By</th>
              <th>Started</th>
              <th>Duration</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${runs.map(r => `
              <tr>
                <td class="mono text-muted" style="font-size:11px">${Utils.escapeHtml(r.id.slice(0, 8))}...</td>
                <td>${renderRunStatusBadge(r.status)}</td>
                <td>${Utils.escapeHtml(r.triggered_by || '—')}</td>
                <td title="${Utils.escapeHtml(Utils.formatISODate(r.started_at))}">${Utils.formatRelativeTime(r.started_at)}</td>
                <td>${Utils.formatDuration(r.started_at, r.ended_at)}</td>
                <td>
                  <a href="#/identities/${Utils.escapeHtml(identity.id)}/runs/${Utils.escapeHtml(r.id)}" class="btn btn-ghost btn-sm">View</a>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `
    : renderEmptyState('No runs yet', 'Start a discovery run to scan for SCADA assets.');

  return `
    <div class="identity-header">
      <div class="identity-header-info">
        <div class="identity-name">${Utils.escapeHtml(identity.name)}</div>
        <div class="identity-org">${Utils.escapeHtml(identity.org_name)}</div>
        <div class="identity-meta">
          ${identity.sector ? `<span class="badge badge-type">${Utils.escapeHtml(identity.sector)}</span>` : ''}
          <div class="identity-meta-item">
            <span class="text-muted">Created</span>
            <span title="${Utils.escapeHtml(Utils.formatISODate(identity.created_at))}">${Utils.formatRelativeTime(identity.created_at)}</span>
          </div>
          ${latestRunHtml}
        </div>
        <div class="tag-list" style="margin-top:10px">${tagsHtml}</div>
      </div>
      <div class="page-header-actions">
        <a href="/api/v1/identities/${Utils.escapeHtml(identity.id)}/report.pdf" target="_blank" class="btn btn-secondary btn-sm">Download PDF</a>
        <button class="btn btn-secondary btn-sm" onclick="App.showCreateSeedModal('${Utils.escapeHtml(identity.id)}')">Add Seed</button>
        <button class="btn btn-primary" onclick="App.startDiscovery('${Utils.escapeHtml(identity.id)}')">
          &#9654; Start Discovery
        </button>
      </div>
    </div>

    <div class="tabs" id="identity-tabs">
      <button class="tab-btn active" data-tab="overview">Overview</button>
      <button class="tab-btn" data-tab="seeds">Seeds (${seeds ? seeds.length : 0})</button>
      <button class="tab-btn" data-tab="runs">Runs (${runs ? runs.length : 0})</button>
    </div>

    <div class="tab-content active" id="tab-overview">
      <div class="card-grid card-grid-3" style="margin-bottom:20px">
        ${renderStatCard('Seeds', seeds ? seeds.length : 0, 'Discovery inputs')}
        ${renderStatCard('Total Runs', runs ? runs.length : 0, 'Discovery executions')}
        ${renderStatCard('Last Run', latestRun ? latestRun.status : 'Never', latestRun ? Utils.formatRelativeTime(latestRun.created_at) : '')}
      </div>
      ${identity.risk_score != null ? `
      <div style="display:flex;flex-wrap:wrap;gap:12px;margin-bottom:20px">
        <div style="padding:16px 20px;background:var(--surface);border:1px solid var(--border);border-radius:8px;min-width:120px">
          <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">Risk Score</div>
          <div style="font-size:28px;font-weight:700;color:${
            (identity.risk_score || 0) >= 75 ? 'var(--severity-critical)' :
            (identity.risk_score || 0) >= 50 ? 'var(--severity-high)' :
            (identity.risk_score || 0) >= 25 ? 'var(--severity-medium)' : 'var(--severity-low)'
          }">${Math.round(identity.risk_score || 0)}</div>
          <div style="font-size:10px;color:var(--text-muted);margin-top:2px">/ 100</div>
        </div>
      </div>` : ''}
      ${identity.notes ? `
        <div class="card mb-16">
          <div class="card-header"><div class="card-title">Notes</div></div>
          <div class="card-body">
            <p class="text-secondary">${Utils.escapeHtml(identity.notes)}</p>
          </div>
        </div>
      ` : ''}
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
        <div class="card">
          <div class="card-header"><div class="card-title">Quick Actions</div></div>
          <div class="card-body" style="display:flex;flex-direction:column;gap:8px">
            <a href="#/identities/${Utils.escapeHtml(identity.id)}/assets" class="btn btn-secondary w-full">View Assets</a>
            <a href="#/identities/${Utils.escapeHtml(identity.id)}/findings" class="btn btn-secondary w-full">View Findings</a>
          </div>
        </div>
        <div class="card">
          <div class="card-header"><div class="card-title">Identity Details</div></div>
          <div class="card-body">
            <div class="detail-grid">
              <div class="detail-item">
                <div class="detail-key">ID</div>
                <div class="detail-value mono" style="font-size:11px">${Utils.escapeHtml(identity.id)}</div>
              </div>
              <div class="detail-item">
                <div class="detail-key">Sector</div>
                <div class="detail-value">${Utils.escapeHtml(identity.sector || '—')}</div>
              </div>
              <div class="detail-item">
                <div class="detail-key">Created</div>
                <div class="detail-value">${Utils.escapeHtml(Utils.formatISODate(identity.created_at))}</div>
              </div>
              <div class="detail-item">
                <div class="detail-key">Updated</div>
                <div class="detail-value">${Utils.escapeHtml(Utils.formatISODate(identity.updated_at))}</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="tab-content" id="tab-seeds">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
        <div class="section-title">Configured Seeds</div>
        <button class="btn btn-secondary btn-sm" onclick="App.showCreateSeedModal('${Utils.escapeHtml(identity.id)}')">Add Seed</button>
      </div>
      ${seedsHtml}
    </div>

    <div class="tab-content" id="tab-runs">
      ${runsHtml}
    </div>
  `;
}

/* -------------------------------------------------------------------------
   Component: renderRunStatusBadge
   ------------------------------------------------------------------------- */
function renderRunStatusBadge(status) {
  const s = (status || 'pending').toLowerCase();
  const labels = { pending: 'Pending', running: 'Running', completed: 'Completed', failed: 'Failed' };
  return `<span class="badge badge-status-${s}">${labels[s] || s}</span>`;
}

/* -------------------------------------------------------------------------
   Component: renderJobStatusBadge
   ------------------------------------------------------------------------- */
function renderJobStatusBadge(status) {
  const s = (status || 'pending').toLowerCase();
  const labels = { pending: 'Pending', running: 'Running', completed: 'Completed', failed: 'Failed', retrying: 'Retrying' };
  return `<span class="badge badge-status-${s}">${labels[s] || s}</span>`;
}

/* -------------------------------------------------------------------------
   Component: renderRunPage
   ------------------------------------------------------------------------- */
function renderRunPage(run, jobs, identityId) {
  const jobsList = jobs || [];
  const total    = jobsList.length;
  const done     = jobsList.filter(j => j.status === 'completed').length;
  const failed   = jobsList.filter(j => j.status === 'failed').length;
  const running  = jobsList.filter(j => j.status === 'running').length;
  const pending  = jobsList.filter(j => j.status === 'pending').length;
  const progress = total > 0 ? Math.round((done / total) * 100) : 0;

  const isActive = run.status === 'running' || run.status === 'pending';

  const jobRows = jobsList.length > 0
    ? jobsList.map(j => `
        <tr>
          <td class="mono text-muted" style="font-size:11px">${Utils.escapeHtml(j.id.slice(0, 8))}...</td>
          <td><span class="badge badge-type">${Utils.escapeHtml(j.type)}</span></td>
          <td>${renderJobStatusBadge(j.status)}</td>
          <td title="${Utils.escapeHtml(Utils.formatISODate(j.started_at))}">${Utils.formatRelativeTime(j.started_at)}</td>
          <td>${Utils.formatDuration(j.started_at, j.ended_at)}</td>
          <td>${j.attempts}/${j.max_attempts}</td>
          <td class="text-muted">${j.error ? `<span class="text-critical">${Utils.escapeHtml(j.error.slice(0, 60))}</span>` : '—'}</td>
        </tr>
      `).join('')
    : `<tr><td colspan="7" style="text-align:center;padding:32px;color:var(--text-muted)">No jobs found</td></tr>`;

  return `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px">
      <div>
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:4px">
          ${renderRunStatusBadge(run.status)}
          ${isActive ? '<span class="text-blue" style="font-size:12px">Auto-refreshing every 5s</span>' : ''}
        </div>
        <div class="text-muted" style="font-size:12px">
          Run ID: <span class="mono">${Utils.escapeHtml(run.id)}</span>
          &nbsp;|&nbsp; Triggered by: ${Utils.escapeHtml(run.triggered_by || 'api')}
          &nbsp;|&nbsp; Started: <span title="${Utils.escapeHtml(Utils.formatISODate(run.started_at))}">${Utils.formatRelativeTime(run.started_at)}</span>
          ${run.ended_at ? `&nbsp;|&nbsp; Duration: ${Utils.formatDuration(run.started_at, run.ended_at)}` : ''}
        </div>
      </div>
      <a href="#/identities/${Utils.escapeHtml(identityId)}" class="btn btn-secondary btn-sm">Back to Identity</a>
    </div>

    <div class="stats-row mb-20">
      ${renderStatCard('Total Jobs', total, 'All job types')}
      ${renderStatCard('Completed', done, `${progress}% done`)}
      ${renderStatCard('Running', running, 'In progress')}
      ${renderStatCard('Failed', failed, pending + ' pending', failed > 0 ? 'critical' : '')}
    </div>

    <div class="card mb-20">
      <div class="card-header">
        <div class="card-title">Progress</div>
        <div class="text-muted" style="font-size:12px">${progress}%</div>
      </div>
      <div class="card-body">
        <div class="progress-bar-wrap">
          <div class="progress-bar${isActive ? ' running' : ''}" style="width:${progress}%"></div>
        </div>
        <div style="display:flex;gap:16px;margin-top:12px;font-size:12px">
          <span><span class="text-blue">&#11044;</span> Pending: ${Utils.formatNumber(pending)}</span>
          <span><span class="text-blue">&#11044;</span> Running: ${Utils.formatNumber(running)}</span>
          <span style="color:#22c55e">&#11044; Completed: ${Utils.formatNumber(done)}</span>
          ${failed > 0 ? `<span class="text-critical">&#11044; Failed: ${Utils.formatNumber(failed)}</span>` : ''}
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-title">Jobs</div>
        <div class="text-muted" style="font-size:12px">${Utils.formatNumber(total)} jobs</div>
      </div>
      <div class="table-wrapper" style="border:none;border-radius:0">
        <table class="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Type</th>
              <th>Status</th>
              <th>Started</th>
              <th>Duration</th>
              <th>Attempts</th>
              <th>Error</th>
            </tr>
          </thead>
          <tbody>${jobRows}</tbody>
        </table>
      </div>
    </div>
  `;
}

/* -------------------------------------------------------------------------
   Component: renderAssetsPage
   ------------------------------------------------------------------------- */
function renderAssetsPage(response, identityId, filters, view) {
  const assets = (response && response.assets) || [];
  const total  = (response && response.total) || 0;
  const page   = (response && response.page) || 1;
  const limit  = (response && response.limit) || 50;
  const isGraph = view === 'graph';

  // SVG icons for toggle buttons
  const iconTable = `<svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="1" y="1" width="12" height="3" rx="1"/><rect x="1" y="6" width="12" height="3" rx="1"/><rect x="1" y="11" width="12" height="2" rx="1"/></svg>`;
  const iconGraph = `<svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="7" cy="7" r="2"/><circle cx="2" cy="2" r="1.5"/><circle cx="12" cy="2" r="1.5"/><circle cx="2" cy="12" r="1.5"/><circle cx="12" cy="12" r="1.5"/><line x1="3.1" y1="3.1" x2="5.6" y2="5.6"/><line x1="10.9" y1="3.1" x2="8.4" y2="5.6"/><line x1="3.1" y1="10.9" x2="5.6" y2="8.4"/><line x1="10.9" y1="10.9" x2="8.4" y2="8.4"/></svg>`;

  const filterBar = `
    <div class="filter-bar">
      <div class="filter-group">
        <label class="filter-label">Type</label>
        <select class="filter-select" id="filter-type" onchange="App.filterAssets()">
          <option value="">All types</option>
          <option value="ip"        ${filters && filters.type === 'ip'        ? 'selected' : ''}>IP</option>
          <option value="domain"    ${filters && filters.type === 'domain'    ? 'selected' : ''}>Domain</option>
          <option value="subdomain" ${filters && filters.type === 'subdomain' ? 'selected' : ''}>Subdomain</option>
          <option value="endpoint"  ${filters && filters.type === 'endpoint'  ? 'selected' : ''}>Endpoint</option>
        </select>
      </div>
      <div class="filter-group">
        <label class="filter-label">Country</label>
        <input class="filter-input" type="text" id="filter-country" placeholder="US, DE, GB..."
          value="${Utils.escapeHtml((filters && filters.country) || '')}"
          oninput="App.debouncedFilterAssets()" />
      </div>
      <div class="filter-group">
        <label class="filter-label">ASN</label>
        <input class="filter-input" type="text" id="filter-asn" placeholder="AS number"
          value="${Utils.escapeHtml((filters && filters.asn) || '')}"
          oninput="App.debouncedFilterAssets()" />
      </div>
      <div class="filter-spacer"></div>
      <div class="filter-results">${Utils.formatNumber(total)} assets</div>
      <button class="btn btn-ghost btn-sm" onclick="App.clearAssetFilters()">Clear</button>
      <div class="view-toggle">
        <button class="view-btn ${!isGraph ? 'active' : ''}" title="Table view"  onclick="App.switchAssetView('table')">${iconTable}</button>
        <button class="view-btn ${isGraph  ? 'active' : ''}" title="Network graph" onclick="App.switchAssetView('graph')">${iconGraph}</button>
      </div>
    </div>`;

  if (isGraph) {
    return filterBar + `
      <div class="asset-graph-wrap" id="asset-graph-wrap">
        <canvas id="asset-graph-canvas"></canvas>
        <div class="graph-legend">
          <div class="graph-legend-item"><svg width="10" height="10"><circle cx="5" cy="5" r="5" fill="#3b82f6"/></svg> IP Address</div>
          <div class="graph-legend-item"><svg width="10" height="10"><circle cx="5" cy="5" r="5" fill="#f59e0b"/></svg> Domain</div>
          <div class="graph-legend-item"><svg width="10" height="10"><circle cx="5" cy="5" r="4" fill="#8b5cf6"/></svg> Subdomain</div>
          <div class="graph-legend-item"><svg width="10" height="10"><circle cx="5" cy="5" r="4" fill="#10b981"/></svg> Endpoint</div>
          <div class="graph-legend-item"><svg width="22" height="10"><line x1="0" y1="5" x2="22" y2="5" stroke="rgba(59,130,246,0.7)" stroke-width="2"/></svg> DNS link</div>
          <div class="graph-legend-item"><svg width="8" height="8"><circle cx="4" cy="4" r="4" fill="#ef4444"/></svg> Has findings</div>
          <div class="graph-legend-item"><span style="font-size:10px;color:rgba(148,213,252,0.95)">☁</span> Cloud / CDN</div>
        </div>
        <div class="asset-graph-hint">Click a node to inspect &nbsp;·&nbsp; Drag to pan &nbsp;·&nbsp; Scroll to zoom</div>
      </div>`;
  }

  const rows = assets.length > 0
    ? assets.map(a => `
        <tr>
          <td class="primary mono">${Utils.escapeHtml(a.value)}</td>
          <td><span class="badge badge-type">${Utils.escapeHtml(a.type)}</span></td>
          <td>${Utils.escapeHtml(a.country_code || '—')}</td>
          <td>
            ${a.asn ? `<span class="mono text-muted" style="font-size:12px">AS${a.asn}</span><br>` : ''}
            <span class="text-secondary">${Utils.escapeHtml(a.asn_org || '—')}</span>
          </td>
          <td>
            ${a.is_public !== undefined
              ? `<span class="badge ${a.is_public ? 'badge-public' : 'badge-private'}">${a.is_public ? 'Public' : 'Private'}</span>`
              : '—'}
            ${a.is_cloud ? `<span class="badge badge-cloud" style="margin-left:4px">Cloud</span>` : ''}
          </td>
          <td>${Utils.escapeHtml(a.provenance || '—')}</td>
          <td title="${Utils.escapeHtml(Utils.formatISODate(a.created_at))}">${Utils.formatRelativeTime(a.created_at)}</td>
          <td><a href="#/assets/${Utils.escapeHtml(a.id)}" class="btn btn-ghost btn-sm">View</a></td>
        </tr>`).join('')
    : `<tr><td colspan="8" style="padding:0">${renderEmptyState('No assets found', 'Adjust your filters or run a discovery.')}</td></tr>`;

  return filterBar + `
    <div class="table-wrapper">
      <table class="data-table">
        <thead>
          <tr>
            <th>Value</th><th>Type</th><th>Country</th><th>ASN / Org</th>
            <th>Visibility</th><th>Provenance</th><th>Discovered</th><th>Actions</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    ${total > limit ? renderPagination(page, Math.ceil(total / limit), limit, total) : ''}`;
}

/* -------------------------------------------------------------------------
   Component: renderFindingsPage
   ------------------------------------------------------------------------- */
function renderFindingsPage(findings, filters, identityId) {
  const list = Array.isArray(findings) ? findings : [];

  const rows = list.length > 0
    ? list.map(f => `
        <tr>
          <td>
            <div class="severity-indicator ${Utils.escapeHtml((f.severity || 'informational').toLowerCase())}">
              <div class="text-primary" style="font-weight:600;font-size:13px">${Utils.escapeHtml(f.title)}</div>
              ${f.category ? `<div class="text-muted" style="font-size:11px">${Utils.escapeHtml(f.category)}</div>` : ''}
            </div>
          </td>
          <td class="mono text-muted" style="font-size:12px">${Utils.escapeHtml(f.asset_id ? f.asset_id.slice(0, 8) + '...' : '—')}</td>
          <td>${f.protocol ? `<span class="badge badge-protocol">${Utils.escapeHtml(f.protocol)}</span>` : '—'}</td>
          <td>${f.vendor ? `<span class="text-secondary">${Utils.escapeHtml(f.vendor)}</span>` : '—'}</td>
          <td>${renderSeverityBadge(f.severity)}</td>
          <td title="${Utils.escapeHtml(Utils.formatISODate(f.created_at))}">${Utils.formatRelativeTime(f.created_at)}</td>
          <td>
            <a href="#/findings/${Utils.escapeHtml(f.id)}" class="btn btn-ghost btn-sm">View</a>
          </td>
        </tr>
      `).join('')
    : `<tr><td colspan="7" style="padding:0">${renderEmptyState('No findings', 'Run a discovery scan to detect SCADA exposures.')}</td></tr>`;

  return `
    <div class="filter-bar">
      <div class="filter-group">
        <label class="filter-label">Severity</label>
        <select class="filter-select" id="filter-severity" onchange="App.filterFindings()">
          <option value="">All severities</option>
          <option value="critical" ${filters && filters.severity === 'critical' ? 'selected' : ''}>Critical</option>
          <option value="high" ${filters && filters.severity === 'high' ? 'selected' : ''}>High</option>
          <option value="medium" ${filters && filters.severity === 'medium' ? 'selected' : ''}>Medium</option>
          <option value="low" ${filters && filters.severity === 'low' ? 'selected' : ''}>Low</option>
          <option value="informational" ${filters && filters.severity === 'informational' ? 'selected' : ''}>Informational</option>
        </select>
      </div>
      <div class="filter-group">
        <label class="filter-label">Protocol</label>
        <input class="filter-input" type="text" id="filter-protocol" placeholder="Modbus, DNP3..."
          value="${Utils.escapeHtml((filters && filters.protocol) || '')}"
          oninput="App.debouncedFilterFindings()" />
      </div>
      <div class="filter-group">
        <label class="filter-label">Vendor</label>
        <input class="filter-input" type="text" id="filter-vendor" placeholder="Vendor name"
          value="${Utils.escapeHtml((filters && filters.vendor) || '')}"
          oninput="App.debouncedFilterFindings()" />
      </div>
      <div class="filter-spacer"></div>
      <div class="filter-results">${Utils.formatNumber(list.length)} findings</div>
      <button class="btn btn-ghost btn-sm" onclick="App.clearFindingFilters()">Clear</button>
    </div>

    <div class="table-wrapper">
      <table class="data-table">
        <thead>
          <tr>
            <th>Finding</th>
            <th>Asset</th>
            <th>Protocol</th>
            <th>Vendor</th>
            <th>Severity</th>
            <th>Detected</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

/* -------------------------------------------------------------------------
   Helper: reconSection — collapsible section block used inside Recon tab
   ------------------------------------------------------------------------- */
function reconSection(id, title, hasData, badgeHtml, bodyHtml) {
  return `
    <details id="recon-${id}" ${hasData ? 'open' : ''} style="border:1px solid var(--border);border-radius:6px;margin-bottom:10px;overflow:hidden">
      <summary style="padding:10px 14px;background:var(--surface);cursor:pointer;list-style:none;display:flex;align-items:center;gap:8px;user-select:none;border-bottom:1px solid ${hasData ? 'var(--border)' : 'transparent'}">
        <span style="font-size:10px;color:var(--text-muted)">&#9654;</span>
        <span style="font-weight:600;font-size:13px;color:var(--text-primary)">${title}</span>
        ${badgeHtml || ''}
        ${hasData ? '<span style="margin-left:auto;font-size:10px;padding:2px 7px;border-radius:3px;background:var(--accent-blue)22;color:var(--accent-blue);font-weight:600">DATA</span>' : '<span style="margin-left:auto;font-size:10px;color:var(--text-muted)">no data</span>'}
      </summary>
      <div style="padding:14px">${bodyHtml}</div>
    </details>`;
}

/* -------------------------------------------------------------------------
   Component: renderReconTab  (SNMP + BGP/WHOIS + HTTP Probe combined)
   ------------------------------------------------------------------------- */
function renderReconTab(snmpRecord, bgpRecord, ipWhoisRecord, httpProbeHtml) {
  // --- SNMP section ---
  const snmpBody = (() => {
    if (!snmpRecord) return renderEmptyState('No SNMP data', 'Use Actions \u2192 SNMP Enumerate to probe community strings.');
    let p = {};
    try { p = typeof snmpRecord.data === 'object' ? snmpRecord.data : JSON.parse(atob(snmpRecord.data) || snmpRecord.data || '{}'); } catch(_) {}
    if (!p.community) return renderEmptyState('No SNMP response', 'No community string responded on this host.');
    const rows = [
      p.sys_descr    && ['sysDescr',    p.sys_descr],
      p.sys_name     && ['sysName',     p.sys_name],
      p.sys_location && ['sysLocation', p.sys_location],
      p.sys_contact  && ['sysContact',  p.sys_contact],
      p.sys_uptime   && ['sysUpTime',   p.sys_uptime],
    ].filter(Boolean);
    return `
      <div style="margin-bottom:10px;font-size:12px">Community string: <span class="mono" style="color:var(--severity-high);font-weight:600">${Utils.escapeHtml(p.community)}</span></div>
      <div class="table-wrapper" style="margin:0">
        <table class="data-table">
          <thead><tr><th>OID</th><th>Value</th></tr></thead>
          <tbody>${rows.map(([k,v]) => `<tr><td class="mono text-muted" style="font-size:11px">${k}</td><td class="mono" style="font-size:12px">${Utils.escapeHtml(v)}</td></tr>`).join('')}</tbody>
        </table>
      </div>`;
  })();
  const snmpHasData = !!(snmpRecord && (() => { try { const p = typeof snmpRecord.data === 'object' ? snmpRecord.data : JSON.parse(atob(snmpRecord.data) || snmpRecord.data || '{}'); return !!p.community; } catch(_) { return false; } })());

  // --- Network Intelligence (BGP + IP WHOIS) section ---
  const netBody = (() => {
    let bgp = {}, whois = {};
    try { bgp = bgpRecord ? (typeof bgpRecord.data === 'object' ? bgpRecord.data : JSON.parse(atob(bgpRecord.data) || bgpRecord.data || '{}')) : {}; } catch(_) {}
    try { whois = ipWhoisRecord ? (typeof ipWhoisRecord.data === 'object' ? ipWhoisRecord.data : JSON.parse(atob(ipWhoisRecord.data) || ipWhoisRecord.data || '{}')) : {}; } catch(_) {}
    const hasData = (bgp.asn || bgp.org) || (whois.ip);
    if (!hasData) return renderEmptyState('No network data', 'Use Actions \u2192 BGP Lookup and IP WHOIS to fetch network intelligence.');
    const items = [
      whois.org        && ['Organization', whois.org],
      whois.isp        && ['ISP',          whois.isp],
      bgp.asn          && ['ASN',          bgp.asn],
      bgp.asn_name     && ['ASN Name',     bgp.asn_name],
      bgp.prefix       && ['Prefix',       bgp.prefix],
      whois.country    && ['Country',      whois.country + (whois.country_code ? ` (${whois.country_code})` : '')],
      whois.city       && ['City',         whois.city],
      whois.region     && ['Region',       whois.region],
      whois.timezone   && ['Timezone',     whois.timezone],
    ].filter(Boolean);
    const prefixesHtml = Array.isArray(bgp.prefixes) && bgp.prefixes.length > 0
      ? `<div style="margin-top:12px"><div style="font-size:11px;color:var(--text-muted);margin-bottom:4px">ANNOUNCED PREFIXES</div><div style="display:flex;flex-wrap:wrap;gap:4px">${bgp.prefixes.map(p=>`<span class="badge badge-type mono">${Utils.escapeHtml(p)}</span>`).join('')}</div></div>` : '';
    return `
      <div class="detail-grid" style="margin-bottom:4px">
        ${items.map(([k,v]) => `<div class="detail-item"><div class="detail-key">${k}</div><div class="detail-value">${Utils.escapeHtml(v)}</div></div>`).join('')}
      </div>${prefixesHtml}`;
  })();
  const netHasData = !!(bgpRecord || ipWhoisRecord);
  const netBadge = (() => {
    try {
      const b = bgpRecord ? (typeof bgpRecord.data === 'object' ? bgpRecord.data : JSON.parse(atob(bgpRecord.data) || bgpRecord.data || '{}')) : {};
      if (b.asn) return `<span class="badge badge-type mono">${Utils.escapeHtml(b.asn)}</span>`;
    } catch(_) {}
    return '';
  })();

  // --- HTTP Probe section ---
  const httpHasData = httpProbeHtml && !httpProbeHtml.includes('empty-state');

  return `
    ${reconSection('snmp',    'SNMP Enumeration',       snmpHasData, snmpHasData ? `<span class="badge badge-type">community found</span>` : '', snmpBody)}
    ${reconSection('net',     'Network Intelligence',   netHasData,  netBadge,    netBody)}
    ${reconSection('http',    'HTTP Probe',             httpHasData, '',          httpProbeHtml || renderEmptyState('No HTTP probe data', 'Use Actions \u2192 HTTP Probe to fingerprint web services.'))}
  `;
}

/* -------------------------------------------------------------------------
   Component: renderOTProbeTab
   ------------------------------------------------------------------------- */
function renderOTProbeTab(rec) {
  if (!rec) return renderEmptyState('No OT probe data', 'Use Actions \u2192 OT Protocol Probe to scan for ICS/SCADA protocols.');
  let parsed = {};
  try { parsed = typeof rec.data === 'object' ? rec.data : JSON.parse(atob(rec.data) || rec.data || '{}'); } catch(_) {}
  const probes = Array.isArray(parsed.probes) ? parsed.probes : [];
  if (probes.length === 0) return renderEmptyState('No OT probe results', 'No protocols were detected.');
  const rows = probes.map(p => {
    const respondedHtml = p.responded
      ? `<span style="color:var(--severity-low);font-size:13px">&#10003; Yes</span>`
      : `<span style="color:var(--text-muted);font-size:13px">&#10007; No</span>`;
    const fieldsHtml = p.fields && Object.keys(p.fields).length > 0
      ? Object.entries(p.fields).map(([k,v]) => `<div style="font-size:11px;color:var(--text-muted)">${Utils.escapeHtml(k)}: <span class="mono">${Utils.escapeHtml(v)}</span></div>`).join('')
      : '';
    return `
      <tr>
        <td><span class="badge badge-protocol">${Utils.escapeHtml(p.protocol)}</span></td>
        <td class="mono">${p.port}</td>
        <td>${respondedHtml}</td>
        <td style="font-size:11px;font-family:var(--font-mono);word-break:break-all;max-width:200px">${p.banner ? Utils.escapeHtml(p.banner.substring(0,60)) + (p.banner.length > 60 ? '...' : '') : '—'}</td>
        <td>${fieldsHtml || '—'}</td>
      </tr>
    `;
  }).join('');
  return `
    <div class="table-wrapper">
      <table class="data-table">
        <thead><tr><th>Protocol</th><th>Port</th><th>Responded</th><th>Banner</th><th>Parsed Fields</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

/* -------------------------------------------------------------------------
   Component: renderBGPTab
   ------------------------------------------------------------------------- */
function renderBGPTab(rec) {
  if (!rec) return renderEmptyState('No BGP data', 'Use Actions \u2192 BGP Lookup to fetch netblock information.');
  let parsed = {};
  try { parsed = typeof rec.data === 'object' ? rec.data : JSON.parse(atob(rec.data) || rec.data || '{}'); } catch(_) {}
  if (!parsed.ip && !parsed.asn) return renderEmptyState('No BGP data', 'BGPView had no data for this IP.');
  const prefixesHtml = Array.isArray(parsed.prefixes) && parsed.prefixes.length > 0
    ? `<div style="margin-top:12px"><div style="font-size:11px;color:var(--text-muted);margin-bottom:4px">ALL PREFIXES</div><div style="display:flex;flex-wrap:wrap;gap:4px">${parsed.prefixes.map(p=>`<span class="badge badge-type mono">${Utils.escapeHtml(p)}</span>`).join('')}</div></div>` : '';
  return `
    <div class="detail-grid" style="margin-bottom:12px">
      ${parsed.asn ? `<div class="detail-item"><div class="detail-key">ASN</div><div class="detail-value mono">AS${parsed.asn}</div></div>` : ''}
      ${parsed.asn_name ? `<div class="detail-item"><div class="detail-key">ASN Name</div><div class="detail-value">${Utils.escapeHtml(parsed.asn_name)}</div></div>` : ''}
      ${parsed.description ? `<div class="detail-item"><div class="detail-key">Description</div><div class="detail-value">${Utils.escapeHtml(parsed.description)}</div></div>` : ''}
      ${parsed.prefix ? `<div class="detail-item"><div class="detail-key">RIR Prefix</div><div class="detail-value mono">${Utils.escapeHtml(parsed.prefix)}</div></div>` : ''}
      ${parsed.country_code ? `<div class="detail-item"><div class="detail-key">Country</div><div class="detail-value">${Utils.escapeHtml(parsed.country_code)}</div></div>` : ''}
    </div>
    ${prefixesHtml}
  `;
}

/* -------------------------------------------------------------------------
   Component: renderIPWhoisTab
   ------------------------------------------------------------------------- */
function renderIPWhoisTab(rec) {
  if (!rec) return renderEmptyState('No IP WHOIS data', 'Use Actions \u2192 IP WHOIS to fetch geolocation and org data.');
  let parsed = {};
  try { parsed = typeof rec.data === 'object' ? rec.data : JSON.parse(atob(rec.data) || rec.data || '{}'); } catch(_) {}
  if (!parsed.ip) return renderEmptyState('No IP WHOIS data', 'No data returned.');
  return `
    <div class="detail-grid">
      ${parsed.org ? `<div class="detail-item"><div class="detail-key">Organization</div><div class="detail-value">${Utils.escapeHtml(parsed.org)}</div></div>` : ''}
      ${parsed.isp ? `<div class="detail-item"><div class="detail-key">ISP</div><div class="detail-value">${Utils.escapeHtml(parsed.isp)}</div></div>` : ''}
      ${parsed.asn ? `<div class="detail-item"><div class="detail-key">ASN</div><div class="detail-value mono">${Utils.escapeHtml(parsed.asn)}</div></div>` : ''}
      ${parsed.country ? `<div class="detail-item"><div class="detail-key">Country</div><div class="detail-value">${Utils.escapeHtml(parsed.country)} (${Utils.escapeHtml(parsed.country_code || '')})</div></div>` : ''}
      ${parsed.city ? `<div class="detail-item"><div class="detail-key">City</div><div class="detail-value">${Utils.escapeHtml(parsed.city)}</div></div>` : ''}
      ${parsed.region ? `<div class="detail-item"><div class="detail-key">Region</div><div class="detail-value">${Utils.escapeHtml(parsed.region)}</div></div>` : ''}
      ${parsed.timezone ? `<div class="detail-item"><div class="detail-key">Timezone</div><div class="detail-value">${Utils.escapeHtml(parsed.timezone)}</div></div>` : ''}
    </div>
  `;
}

/* -------------------------------------------------------------------------
   Component: renderThreatsTab  (CVE + Vuln Notes + Exploits combined)
   ------------------------------------------------------------------------- */
function renderThreatsTab(cveRecord, vulnNotesData) {
  // Parse CVE services keyed by port.
  const cveByPort = {};
  if (cveRecord) {
    let parsed = {};
    try { parsed = typeof cveRecord.data === 'object' ? cveRecord.data : JSON.parse(atob(cveRecord.data) || cveRecord.data || '{}'); } catch(_) {}
    (parsed.services || []).forEach(svc => { cveByPort[svc.port] = svc; });
  }

  // Parse vuln notes keyed by port.
  const noteByPort = {};
  if (vulnNotesData && Array.isArray(vulnNotesData.notes)) {
    vulnNotesData.notes.forEach(n => { noteByPort[n.port] = n; });
  }

  // Union of all ports.
  const allPorts = [...new Set([...Object.keys(cveByPort).map(Number), ...Object.keys(noteByPort).map(Number)])].sort((a,b) => a-b);

  if (allPorts.length === 0) {
    return renderEmptyState('No threat data', 'Run a port scan first, then use Actions \u2192 CVE Correlate to populate this tab.');
  }

  const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  const riskColors = { critical: 'var(--severity-critical)', high: 'var(--severity-high)', medium: 'var(--severity-medium)', low: 'var(--severity-low)' };
  return allPorts.map(port => {
    const svc  = cveByPort[port] || {};
    const note = noteByPort[port] || {};
    const cves = Array.isArray(svc.cves) ? svc.cves : [];
    const service = note.service || svc.service || 'Unknown';
    const risk  = (note.risk || (cves.length > 0 ? 'medium' : 'low')).toLowerCase();
    const riskColor = riskColors[risk] || 'var(--text-muted)';
    const uid = `threats-${port}`;

    const hasNotes = !!(note.notes || (note.red_team_tips && note.red_team_tips.length) || (note.references && note.references.length));

    // Sub-section helper — lighter style for use inside a port card.
    const subSection = (label, badge, open, body) => `
      <details ${open ? 'open' : ''} style="border:1px solid var(--border-subtle);border-radius:5px;margin-bottom:8px;overflow:hidden">
        <summary style="padding:7px 12px;background:var(--bg-secondary);cursor:pointer;list-style:none;display:flex;align-items:center;gap:7px;user-select:none">
          <span style="font-size:9px;color:var(--text-muted)">&#9654;</span>
          <span style="font-size:12px;font-weight:600;color:var(--text-primary)">${label}</span>
          ${badge}
        </summary>
        <div style="padding:12px">${body}</div>
      </details>`;

    // --- Notes & Tips sub-section ---
    const tipsHtml = Array.isArray(note.red_team_tips) && note.red_team_tips.length > 0
      ? `<div style="margin-top:10px"><div style="font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">Red Team Tips</div><ul style="margin:0;padding-left:18px">${note.red_team_tips.map(t=>`<li style="font-size:12px;color:var(--text-secondary);margin-bottom:4px">${Utils.escapeHtml(t)}</li>`).join('')}</ul></div>` : '';
    const refsHtml = Array.isArray(note.references) && note.references.length > 0
      ? `<div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:6px">${note.references.map(r=>`<a href="${Utils.escapeHtml(r)}" target="_blank" rel="noopener" style="font-size:11px;color:var(--accent-blue)">${Utils.escapeHtml(r.replace(/^https?:\/\//, '').split('/')[0])}</a>`).join('<span style="color:var(--border)">&bull;</span>')}</div>` : '';
    const notesBody = hasNotes
      ? `${note.notes ? `<div style="font-size:13px;color:var(--text-secondary);line-height:1.5;margin-bottom:4px">${Utils.escapeHtml(note.notes)}</div>` : ''}${tipsHtml}${refsHtml}`
      : `<div style="font-size:12px;color:var(--text-muted)">No notes available for this service.</div>`;
    const notesSubSection = subSection('Notes &amp; Red Team Tips', `<span class="badge badge-type" style="font-size:10px">${(note.risk||risk).toUpperCase()}</span>`, hasNotes, notesBody);

    // --- CVEs sub-section ---
    const cvesBody = cves.length > 0
      ? cves.map((c, ci) => {
          const sev = (c.severity || 'unknown').toLowerCase();
          const score = typeof c.cvss_score === 'number' ? c.cvss_score.toFixed(1) : '?';
          const sevColor = ['critical','high','medium','low'].includes(sev) ? sev : 'low';
          return `
            <details style="border-left:3px solid var(--severity-${sevColor});margin-bottom:6px;background:var(--surface);border-radius:0 4px 4px 0">
              <summary style="padding:7px 11px;cursor:pointer;list-style:none;display:flex;align-items:center;gap:7px;user-select:none">
                <span style="font-size:9px;color:var(--text-muted)">&#9654;</span>
                <a href="${Utils.escapeHtml(c.url)}" target="_blank" rel="noopener" class="mono" style="color:var(--accent-blue);font-size:12px;font-weight:600" onclick="event.stopPropagation()">${Utils.escapeHtml(c.id)}</a>
                ${renderSeverityBadge(sev)}
                <span class="badge badge-type">CVSS ${score}</span>
              </summary>
              <div style="padding:8px 12px 10px;font-size:12px;color:var(--text-secondary);line-height:1.5">
                ${Utils.escapeHtml(c.description ? c.description.substring(0, 400) + (c.description.length > 400 ? '...' : '') : '')}
              </div>
            </details>`;
        }).join('')
      : `<div style="font-size:12px;color:var(--text-muted)">No CVEs found. Use Actions \u2192 CVE Correlate to search.</div>`;
    const cvesSubSection = subSection(
      'CVEs',
      cves.length > 0 ? `<span class="badge badge-type">${cves.length} found</span>` : '',
      cves.length > 0,
      cvesBody
    );

    // --- Exploits sub-section ---
    // Collect exploits already stored in the CVE record (populated by the backend on correlate).
    const storedExploits = []; // { cveId, exploits[] }
    cves.forEach(c => {
      const exs = Array.isArray(c.exploits) ? c.exploits : [];
      if (exs.length > 0) storedExploits.push({ cveId: c.id, exploits: exs });
    });
    const totalStoredExploits = storedExploits.reduce((n, e) => n + e.exploits.length, 0);
    const exploitsContainerId = `exploits-section-${port}`;
    const cveIds = cves.map(c => c.id);

    const typeColors = { webapps: '#e67e22', remote: '#e74c3c', local: '#c0392b', dos: '#8e44ad', shellcode: '#2980b9', papers: '#27ae60' };

    const renderStoredExploits = (list) => list.map(group => {
      const rows = group.exploits.map(ex => {
        const src = (ex.source || 'exploit-db').toLowerCase();
        const typeKey = (ex.type || src).toLowerCase();
        const typeColor = typeColors[typeKey] || (src === 'exploit-db' ? '#e45c3a' : '#7f8c8d');
        return `
          <div style="display:flex;align-items:flex-start;gap:10px;padding:7px 10px;margin-bottom:5px;background:var(--surface);border:1px solid var(--border);border-radius:4px">
            <div style="flex:1;min-width:0">
              <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:3px">
                <a href="${Utils.escapeHtml(ex.url)}" target="_blank" rel="noopener" style="font-size:12px;font-weight:600;color:var(--accent-blue)">${Utils.escapeHtml(ex.url.split('/').pop() || ex.url)}</a>
                <span style="padding:1px 6px;border-radius:3px;background:${typeColor}22;border:1px solid ${typeColor}55;color:${typeColor};font-size:10px;font-weight:600">${Utils.escapeHtml(src.toUpperCase())}</span>
                ${ex.verified ? `<span style="font-size:10px;color:#27ae60;font-weight:600">&#x2713; Verified</span>` : ''}
              </div>
              ${ex.title ? `<div style="font-size:12px;color:var(--text-secondary)">${Utils.escapeHtml(ex.title)}</div>` : ''}
            </div>
            <a href="${Utils.escapeHtml(ex.url)}" target="_blank" rel="noopener" class="btn btn-sm" style="font-size:11px;padding:3px 8px;flex-shrink:0">View</a>
          </div>`;
      }).join('');
      return `
        <div style="margin-bottom:12px">
          <div style="font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">
            ${Utils.escapeHtml(group.cveId)} &mdash; ${group.exploits.length} exploit${group.exploits.length !== 1 ? 's' : ''}
          </div>
          ${rows}
        </div>`;
    }).join('');

    let exploitsBody;
    if (cveIds.length === 0) {
      exploitsBody = `<div style="font-size:12px;color:var(--text-muted)">No CVEs to search exploits for.</div>`;
    } else if (totalStoredExploits > 0) {
      // Already have exploits from the last correlate run — show them plus a refresh button.
      exploitsBody = `
        <div style="margin-bottom:10px;font-size:12px;font-weight:600;color:var(--severity-critical)">
          &#x1F4A5; ${totalStoredExploits} exploit${totalStoredExploits !== 1 ? 's' : ''} found across ${storedExploits.length} CVE${storedExploits.length !== 1 ? 's' : ''}
        </div>
        ${renderStoredExploits(storedExploits)}
        <div id="${exploitsContainerId}" style="margin-top:8px">
          <button class="btn btn-ghost btn-sm" onclick="App.searchAllExploitsForPort(${JSON.stringify(cveIds)}, '${exploitsContainerId}')" style="font-size:11px;padding:4px 10px">
            &#x1F504; Refresh from Exploit-DB
          </button>
        </div>`;
    } else {
      exploitsBody = `
        <div id="${exploitsContainerId}">
          <button class="btn btn-sm" onclick="App.searchAllExploitsForPort(${JSON.stringify(cveIds)}, '${exploitsContainerId}')" style="font-size:11px;padding:4px 12px">
            &#x1F50D; Search Exploit-DB for all ${cveIds.length} CVE${cveIds.length !== 1 ? 's' : ''}
          </button>
        </div>`;
    }

    const exploitsBadge = totalStoredExploits > 0
      ? `<span style="font-size:10px;font-weight:600;color:var(--severity-critical)">&#x1F4A5; ${totalStoredExploits} found</span>`
      : '';
    const exploitsSubSection = subSection('Exploits', exploitsBadge, totalStoredExploits > 0, exploitsBody);

    return `
      <details id="${uid}" style="border:1px solid var(--border);border-radius:6px;margin-bottom:10px;overflow:hidden">
        <summary style="padding:10px 14px;background:var(--surface);cursor:pointer;list-style:none;display:flex;align-items:center;gap:8px;user-select:none">
          <span style="font-size:10px;color:var(--text-muted)">&#9654;</span>
          <span class="badge badge-protocol">${port}</span>
          <span style="font-weight:600;color:var(--text-primary)">${Utils.escapeHtml(service)}</span>
          ${svc.banner ? `<span style="font-size:11px;color:var(--text-muted);font-family:var(--font-mono)">${Utils.escapeHtml(svc.banner.substring(0, 40))}</span>` : ''}
          <span style="display:inline-block;padding:2px 8px;border-radius:3px;background:${riskColor};color:#fff;font-size:11px;font-weight:600">${risk.toUpperCase()}</span>
          ${cves.length > 0 ? `<span class="badge badge-type">${cves.length} CVE${cves.length !== 1 ? 's' : ''}</span>` : ''}
          <span style="margin-left:auto;font-size:10px;color:var(--text-muted)">click to expand</span>
        </summary>
        <div style="padding:12px">
          ${notesSubSection}
          ${cvesSubSection}
          ${exploitsSubSection}
        </div>
      </details>`;
  }).join('');
}

/* -------------------------------------------------------------------------
   Component: renderAssetDetail
   ------------------------------------------------------------------------- */
function renderAssetDetail(asset, scanResults, dnsRecords, findings, enrichment, subdomains, tlsResult, snmpRecord, otProbeRecord, bgpRecord, ipWhoisRecord, cveRecord, vulnNotesData, iec61850Record, historianRecord, hmiRecord, icscertRecord, nercCipData, iec104Record, modbusDeepRecord, dnp3DeepRecord, iccpRecord, enipDeepRecord, profinetRecord, opcuaRecord, defaultCredsRecord, censysRecord) {
  const sr = scanResults || [];
  const dns = dnsRecords || [];
  const fi = findings || [];
  const en = Array.isArray(enrichment) ? enrichment : (enrichment ? [enrichment] : []);
  const subs = subdomains || [];
  const isDomain = asset.type === 'domain' || asset.type === 'subdomain';

  const infoHtml = `
    <div class="detail-grid">
      <div class="detail-item">
        <div class="detail-key">Type</div>
        <div class="detail-value"><span class="badge badge-type">${Utils.escapeHtml(asset.type)}</span></div>
      </div>
      <div class="detail-item">
        <div class="detail-key">Visibility</div>
        <div class="detail-value">
          <span class="badge ${asset.is_public ? 'badge-public' : 'badge-private'}">${asset.is_public ? 'Public' : 'Private'}</span>
          ${asset.is_cloud ? '<span class="badge badge-cloud" style="margin-left:4px">Cloud</span>' : ''}
        </div>
      </div>
      <div class="detail-item">
        <div class="detail-key">Value</div>
        <div class="detail-value mono">${Utils.escapeHtml(asset.value)}</div>
      </div>
      <div class="detail-item">
        <div class="detail-key">Country</div>
        <div class="detail-value">${Utils.escapeHtml(asset.country_code || '—')}</div>
      </div>
      <div class="detail-item">
        <div class="detail-key">ASN</div>
        <div class="detail-value mono">${asset.asn ? 'AS' + asset.asn : '—'}</div>
      </div>
      <div class="detail-item">
        <div class="detail-key">Organization</div>
        <div class="detail-value">${Utils.escapeHtml(asset.asn_org || '—')}</div>
      </div>
      <div class="detail-item">
        <div class="detail-key">Provenance</div>
        <div class="detail-value">${Utils.escapeHtml(asset.provenance || '—')}</div>
      </div>
      <div class="detail-item">
        <div class="detail-key">Reverse DNS</div>
        <div class="detail-value mono">${Utils.escapeHtml(asset.reverse_dns || '—')}</div>
      </div>
      <div class="detail-item">
        <div class="detail-key">Discovered</div>
        <div class="detail-value" title="${Utils.escapeHtml(Utils.formatISODate(asset.created_at))}">${Utils.formatRelativeTime(asset.created_at)}</div>
      </div>
      <div class="detail-item">
        <div class="detail-key">Last Updated</div>
        <div class="detail-value" title="${Utils.escapeHtml(Utils.formatISODate(asset.updated_at))}">${Utils.formatRelativeTime(asset.updated_at)}</div>
      </div>
    </div>
  `;

  function renderScanCard(s) {
    const bannerId = 'banner-' + s.port;
    const evidenceId = 'evidence-' + s.port;
    let evidence = null;
    if (s.raw_response) {
      try {
        const raw = typeof s.raw_response === 'string' ? s.raw_response : atob(s.raw_response);
        evidence = JSON.parse(raw);
      } catch(_) {}
    }
    const hasDetails = s.banner || evidence;
    const catColor = {
      industrial_protocol: 'var(--severity-critical)',
      remote_access: 'var(--severity-high)',
      web_interface: 'var(--accent-blue)',
      database: 'var(--severity-medium)',
    }[s.service_category] || 'var(--text-muted)';

    return `
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;margin-bottom:8px;overflow:hidden">
        <div style="display:flex;align-items:center;gap:12px;padding:12px 14px;cursor:${hasDetails?'pointer':'default'}"
             onclick="${hasDetails ? `document.getElementById('${bannerId}').style.display=document.getElementById('${bannerId}').style.display==='none'?'block':'none'` : ''}">
          <div style="min-width:90px;font-family:var(--font-mono);font-size:14px;font-weight:700;color:${catColor}">
            ${Utils.escapeHtml(String(s.port))}
            <span style="font-weight:400;font-size:11px;color:var(--text-muted)">/${Utils.escapeHtml(s.protocol||'tcp')}</span>
          </div>
          <div style="flex:1">
            <div style="font-weight:600;color:var(--text-primary);font-size:13px">${Utils.escapeHtml(s.service_name || 'Unknown Service')}</div>
            ${s.service_category ? `<div style="font-size:11px;color:var(--text-muted);margin-top:2px">${Utils.escapeHtml(s.service_category.replace('_',' '))}</div>` : ''}
          </div>
          <div style="display:flex;align-items:center;gap:8px">
            <div style="font-size:11px;color:var(--text-muted);font-family:var(--font-mono)">${Math.round((s.confidence||0)*100)}%</div>
            ${s.service_category ? `<span class="badge badge-${s.service_category==='industrial_protocol'?'critical':s.service_category==='remote_access'?'high':'service'}">${Utils.escapeHtml(s.service_category.replace(/_/g,' '))}</span>` : ''}
            ${hasDetails ? `<span style="color:var(--text-muted);font-size:12px">&#9660;</span>` : ''}
          </div>
        </div>
        ${hasDetails ? `
          <div id="${bannerId}" style="display:none;border-top:1px solid var(--border-subtle)">
            ${s.banner ? `
              <div style="padding:10px 14px">
                <div style="font-size:10px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px">Grabbed Banner</div>
                <pre style="margin:0;font-family:var(--font-mono);font-size:11px;color:var(--text-secondary);white-space:pre-wrap;word-break:break-all;background:var(--surface-elevated);padding:10px;border-radius:4px;max-height:200px;overflow:auto">${Utils.escapeHtml(s.banner)}</pre>
              </div>
            ` : ''}
            ${evidence ? `
              <div style="padding:10px 14px;border-top:1px solid var(--border-subtle)">
                <div style="font-size:10px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px">Service Details</div>
                <div class="detail-grid" style="gap:6px">
                  ${evidence.product ? `<div class="detail-item"><div class="detail-key">Product</div><div class="detail-value mono">${Utils.escapeHtml(evidence.product)}</div></div>` : ''}
                  ${evidence.version ? `<div class="detail-item"><div class="detail-key">Version</div><div class="detail-value mono">${Utils.escapeHtml(evidence.version)}</div></div>` : ''}
                  ${evidence.extra_info ? `<div class="detail-item"><div class="detail-key">Info</div><div class="detail-value">${Utils.escapeHtml(evidence.extra_info)}</div></div>` : ''}
                  ${evidence.device_type ? `<div class="detail-item"><div class="detail-key">Device Type</div><div class="detail-value">${Utils.escapeHtml(evidence.device_type)}</div></div>` : ''}
                  ${evidence.os_type ? `<div class="detail-item"><div class="detail-key">OS Type</div><div class="detail-value">${Utils.escapeHtml(evidence.os_type)}</div></div>` : ''}
                  ${evidence.hostname ? `<div class="detail-item"><div class="detail-key">Hostname</div><div class="detail-value mono">${Utils.escapeHtml(evidence.hostname)}</div></div>` : ''}
                  ${evidence.method ? `<div class="detail-item"><div class="detail-key">Method</div><div class="detail-value">${Utils.escapeHtml(evidence.method)}</div></div>` : ''}
                </div>
                ${evidence.cpe && evidence.cpe.length > 0 ? `
                  <div style="margin-top:8px">
                    <div style="font-size:10px;color:var(--text-muted);margin-bottom:4px">CPE</div>
                    <div style="display:flex;flex-wrap:wrap;gap:4px">
                      ${(evidence.cpe||[]).map(c=>`<span class="badge badge-type" style="font-family:var(--font-mono);font-size:10px">${Utils.escapeHtml(String(c))}</span>`).join('')}
                    </div>
                  </div>
                ` : ''}
                ${evidence['banner'] ? `
                  <div style="margin-top:8px">
                    <div style="font-size:10px;color:var(--text-muted);margin-bottom:4px">NSE Banner</div>
                    <pre style="margin:0;font-family:var(--font-mono);font-size:10px;color:var(--text-secondary);white-space:pre-wrap;word-break:break-all;background:var(--surface-elevated);padding:8px;border-radius:4px;max-height:120px;overflow:auto">${Utils.escapeHtml(evidence['banner'])}</pre>
                  </div>
                ` : ''}
                ${evidence['http-title'] ? `
                  <div style="margin-top:8px">
                    <div style="font-size:10px;color:var(--text-muted);margin-bottom:4px">HTTP Title</div>
                    <div style="font-family:var(--font-mono);font-size:11px;color:var(--text-secondary)">${Utils.escapeHtml(evidence['http-title'])}</div>
                  </div>
                ` : ''}
                ${evidence['ssl-cert'] ? `
                  <div style="margin-top:8px">
                    <div style="font-size:10px;color:var(--text-muted);margin-bottom:4px">SSL Certificate</div>
                    <pre style="margin:0;font-family:var(--font-mono);font-size:10px;color:var(--text-secondary);white-space:pre-wrap;background:var(--surface-elevated);padding:8px;border-radius:4px;max-height:120px;overflow:auto">${Utils.escapeHtml(evidence['ssl-cert'])}</pre>
                  </div>
                ` : ''}
              </div>
            ` : ''}
          </div>
        ` : ''}
      </div>
    `;
  }

  const scanHtml = sr.length > 0
    ? `<div style="margin-bottom:8px;font-size:11px;color:var(--text-muted)">${sr.length} open port${sr.length!==1?'s':''} — click a row to expand banner details</div>` +
      sr.map(renderScanCard).join('')
    : renderEmptyState('No scan results', 'Use Port Scan to discover open services.');

  const dnsHtml = dns.length > 0
    ? `
      <div class="table-wrapper">
        <table class="data-table">
          <thead>
            <tr><th>Type</th><th>Name</th><th>Value</th><th>Resolved IP</th></tr>
          </thead>
          <tbody>
            ${dns.map(d => {
              const isARecord = d.record_type === 'A' || d.record_type === 'AAAA';
              const ipValue = isARecord ? d.value : (d.resolved_ip || '');
              const ipCell = isARecord
                ? `<a href="#" class="mono text-primary link-navigate" style="color:var(--accent-blue);text-decoration:none"
                      onclick="App.navigateToAssetByValue('${Utils.escapeHtml(asset.identity_id)}','${Utils.escapeHtml(ipValue)}');return false;"
                      title="Open IP asset">${Utils.escapeHtml(d.value)}</a>`
                : `<span class="mono text-primary">${Utils.escapeHtml(d.value)}</span>`;
              return `
              <tr>
                <td><span class="badge badge-protocol">${Utils.escapeHtml(d.record_type)}</span></td>
                <td class="mono text-secondary">${Utils.escapeHtml(d.name)}</td>
                <td>${ipCell}</td>
                <td class="mono text-muted">${Utils.escapeHtml(d.resolved_ip || '—')}</td>
              </tr>
            `}).join('')}
          </tbody>
        </table>
      </div>
    `
    : renderEmptyState('No DNS records', 'No DNS records found for this asset.');

  const findingsHtml = fi.length > 0
    ? fi.map(f => `
        <div class="severity-indicator ${Utils.escapeHtml((f.severity || 'informational').toLowerCase())}" style="padding:12px;background:var(--surface);border:1px solid var(--border);border-radius:var(--border-radius-sm);margin-bottom:8px">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px">
            <div class="text-primary" style="font-weight:600">${Utils.escapeHtml(f.title)}</div>
            ${renderSeverityBadge(f.severity)}
          </div>
          ${f.description ? `<div class="text-secondary" style="font-size:12px">${Utils.escapeHtml(f.description)}</div>` : ''}
          <div style="display:flex;gap:8px;margin-top:6px">
            ${f.protocol ? `<span class="badge badge-protocol">${Utils.escapeHtml(f.protocol)}</span>` : ''}
            ${f.vendor ? `<span class="badge badge-type">${Utils.escapeHtml(f.vendor)}</span>` : ''}
          </div>
          ${(() => {
            let ttps = [];
            try {
              ttps = typeof f.attack_ttps === 'string' ? JSON.parse(atob(f.attack_ttps)) : (f.attack_ttps || []);
              if (!Array.isArray(ttps)) ttps = [];
            } catch(_) { ttps = []; }
            if (ttps.length === 0) return '';
            return `<div style="margin-top:8px">
              <div style="font-size:10px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">ATT&amp;CK for ICS</div>
              ${ttps.map(t => `<span title="${Utils.escapeHtml(t.tactic)}" style="display:inline-block;margin:2px 4px 2px 0;padding:2px 8px;background:rgba(139,92,246,.1);border:1px solid rgba(139,92,246,.3);border-radius:3px;font-size:10px;font-family:monospace;color:#7c3aed">${Utils.escapeHtml(t.technique_id)} — ${Utils.escapeHtml(t.technique_name)}</span>`).join('')}
            </div>`;
          })()}
        </div>
      `).join('')
    : renderEmptyState('No findings', 'No security findings detected for this asset.');

  function renderEnrichmentRecord(e) {
    let parsed = {};
    try { parsed = typeof e.data === 'object' ? e.data : JSON.parse(atob(e.data) || e.data || '{}'); } catch(_) {}
    const isShodan = e.source === 'shodan';
    if (isShodan && parsed.ip_str) {
      return `
        <div class="card mb-8">
          <div class="card-header">
            <div class="card-title">Shodan Intelligence</div>
            <span class="text-muted" style="font-size:11px">${Utils.formatRelativeTime(e.updated_at || e.created_at)}</span>
          </div>
          <div class="card-body">
            <div class="detail-grid">
              ${parsed.country_name ? `<div class="detail-item"><div class="detail-key">Country</div><div class="detail-value">${Utils.escapeHtml(parsed.country_name)} (${Utils.escapeHtml(parsed.country_code||'')})</div></div>` : ''}
              ${parsed.city ? `<div class="detail-item"><div class="detail-key">City</div><div class="detail-value">${Utils.escapeHtml(parsed.city)}${parsed.region_code ? ', ' + Utils.escapeHtml(parsed.region_code) : ''}</div></div>` : ''}
              ${parsed.org ? `<div class="detail-item"><div class="detail-key">Organization</div><div class="detail-value">${Utils.escapeHtml(parsed.org)}</div></div>` : ''}
              ${parsed.isp ? `<div class="detail-item"><div class="detail-key">ISP</div><div class="detail-value">${Utils.escapeHtml(parsed.isp)}</div></div>` : ''}
              ${parsed.asn ? `<div class="detail-item"><div class="detail-key">ASN</div><div class="detail-value mono">${Utils.escapeHtml(parsed.asn)}</div></div>` : ''}
              ${parsed.os ? `<div class="detail-item"><div class="detail-key">OS</div><div class="detail-value">${Utils.escapeHtml(parsed.os)}</div></div>` : ''}
              ${parsed.latitude ? `<div class="detail-item"><div class="detail-key">Coordinates</div><div class="detail-value mono">${parsed.latitude}, ${parsed.longitude}</div></div>` : ''}
              ${parsed.last_update ? `<div class="detail-item"><div class="detail-key">Last Seen</div><div class="detail-value">${Utils.escapeHtml(parsed.last_update)}</div></div>` : ''}
            </div>
            ${(parsed.hostnames||[]).length > 0 ? `<div style="margin-top:12px"><div class="text-muted" style="font-size:11px;margin-bottom:4px">HOSTNAMES</div><div style="display:flex;flex-wrap:wrap;gap:4px">${parsed.hostnames.map(h=>`<span class="badge badge-type">${Utils.escapeHtml(h)}</span>`).join('')}</div></div>` : ''}
            ${(parsed.domains||[]).length > 0 ? `<div style="margin-top:8px"><div class="text-muted" style="font-size:11px;margin-bottom:4px">DOMAINS</div><div style="display:flex;flex-wrap:wrap;gap:4px">${parsed.domains.map(d=>`<span class="badge badge-type">${Utils.escapeHtml(d)}</span>`).join('')}</div></div>` : ''}
            ${(parsed.tags||[]).length > 0 ? `<div style="margin-top:8px"><div class="text-muted" style="font-size:11px;margin-bottom:4px">TAGS</div><div style="display:flex;flex-wrap:wrap;gap:4px">${parsed.tags.map(t=>`<span class="badge badge-service">${Utils.escapeHtml(t)}</span>`).join('')}</div></div>` : ''}
            ${(parsed.vulns||[]).length > 0 ? `<div style="margin-top:12px"><div class="text-muted" style="font-size:11px;margin-bottom:4px">REPORTED CVEs</div><div style="display:flex;flex-wrap:wrap;gap:4px">${parsed.vulns.map(v=>`<span class="badge badge-critical">${Utils.escapeHtml(v)}</span>`).join('')}</div></div>` : ''}
            ${(parsed.ports||[]).length > 0 ? `<div style="margin-top:8px"><div class="text-muted" style="font-size:11px;margin-bottom:4px">OPEN PORTS</div><div style="display:flex;flex-wrap:wrap;gap:4px">${parsed.ports.map(p=>`<span class="badge badge-protocol">${p}</span>`).join('')}</div></div>` : ''}
            ${(parsed.data||[]).length > 0 ? `
              <div style="margin-top:16px"><div class="text-muted" style="font-size:11px;margin-bottom:8px">SERVICES DETAIL</div>
                ${parsed.data.map(svc => `
                  <div style="background:var(--surface-elevated);border:1px solid var(--border-subtle);border-radius:4px;padding:10px;margin-bottom:6px">
                    <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
                      <span class="badge badge-protocol" style="font-size:12px">${svc.port}/${Utils.escapeHtml(svc.transport||'tcp')}</span>
                      ${svc.product ? `<span class="text-primary" style="font-weight:500">${Utils.escapeHtml(svc.product)}</span>` : ''}
                      ${svc.version ? `<span class="text-secondary" style="font-size:11px">${Utils.escapeHtml(svc.version)}</span>` : ''}
                      ${svc.info ? `<span class="text-muted" style="font-size:11px">${Utils.escapeHtml(svc.info)}</span>` : ''}
                    </div>
                    ${svc.data ? `<pre class="mono text-muted" style="font-size:10px;overflow:auto;max-height:80px;margin:0">${Utils.escapeHtml(svc.data.substring(0,400))}</pre>` : ''}
                    ${svc.http && svc.http.title ? `<div style="margin-top:4px;font-size:11px;color:var(--text-secondary)">HTTP: ${Utils.escapeHtml(svc.http.title)}</div>` : ''}
                    ${svc.ssl && svc.ssl.subject ? `<div style="margin-top:4px;font-size:11px;color:var(--accent-blue)">SSL: ${Utils.escapeHtml(JSON.stringify(svc.ssl.subject))}</div>` : ''}
                    ${Object.keys(svc.vulns||{}).length > 0 ? `<div style="margin-top:4px;display:flex;flex-wrap:wrap;gap:3px">${Object.keys(svc.vulns).map(c=>`<span class="badge badge-critical" style="font-size:10px">${Utils.escapeHtml(c)}</span>`).join('')}</div>` : ''}
                  </div>
                `).join('')}
              </div>
            ` : ''}
            <div style="margin-top:16px;border-top:1px solid var(--border-subtle);padding-top:12px">
              <div style="display:flex;align-items:center;justify-content:space-between;cursor:pointer;user-select:none"
                   onclick="const el=document.getElementById('shodan-raw');el.style.display=el.style.display==='none'?'block':'none';this.querySelector('.raw-toggle').textContent=el.style.display==='none'?'\u25b6 Show Raw JSON':'\u25bc Hide Raw JSON'">
                <span class="text-muted" style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em">Raw JSON</span>
                <span class="raw-toggle text-muted" style="font-size:11px">\u25b6 Show Raw JSON</span>
              </div>
              <pre id="shodan-raw" style="display:none;margin:8px 0 0;font-family:var(--font-mono);font-size:10px;color:var(--text-secondary);background:var(--surface-elevated);padding:12px;border-radius:4px;overflow:auto;max-height:400px;white-space:pre-wrap;word-break:break-all">${Utils.escapeHtml(JSON.stringify(parsed, null, 2))}</pre>
            </div>
          </div>
        </div>
      `;
    }
    // Generic enrichment record.
    let displayData = '';
    try { displayData = JSON.stringify(parsed, null, 2); } catch(_) { displayData = String(e.data || ''); }
    return `
      <div class="card mb-8">
        <div class="card-header">
          <div class="card-title">${Utils.escapeHtml(e.source || 'Internal')}</div>
          <span class="text-muted" style="font-size:11px">${Utils.formatRelativeTime(e.updated_at || e.created_at)}</span>
        </div>
        <div class="card-body">
          <pre class="mono text-secondary" style="font-size:11px;overflow:auto;max-height:300px;margin:0">${Utils.escapeHtml(displayData)}</pre>
        </div>
      </div>
    `;
  }

  const subsHtml = isDomain
    ? (subs.length > 0
        ? `
          <div class="table-wrapper">
            <table class="data-table">
              <thead>
                <tr><th>Subdomain</th><th>TLD</th><th>ASN</th><th>Organization</th><th>Discovered</th></tr>
              </thead>
              <tbody>
                ${subs.map(s => {
                  const parts = (s.value || '').split('.');
                  const tld = parts.length >= 2 ? '.' + parts.slice(-2).join('.') : (s.value || '—');
                  return `
                  <tr style="cursor:pointer" onclick="App.navigate('/assets/${Utils.escapeHtml(s.id)}')">
                    <td class="mono text-primary" style="color:var(--accent-blue)">${Utils.escapeHtml(s.value)}</td>
                    <td class="mono text-muted">${Utils.escapeHtml(tld)}</td>
                    <td class="mono text-muted">${s.asn ? 'AS' + s.asn : '—'}</td>
                    <td class="text-secondary">${Utils.escapeHtml(s.asn_org || '—')}</td>
                    <td class="text-muted" title="${Utils.escapeHtml(Utils.formatISODate(s.created_at))}">${Utils.formatRelativeTime(s.created_at)}</td>
                  </tr>
                `;
                }).join('')}
              </tbody>
            </table>
          </div>
        `
        : renderEmptyState('No subdomains found', 'Run a discovery scan to enumerate subdomains of this domain.'))
    : '';

  const isIP = asset.type === 'ip';

  const httpProbeRecord = en.find(e => e.source === 'http_probe') || null;

  const aid = Utils.escapeHtml(asset.id);

  // ── Actions dropdown (IP assets) ──────────────────────────────
  const AI = `display:block;width:100%;padding:7px 14px;border:none;background:none;cursor:pointer;text-align:left;font-size:13px;font-family:var(--font-sans);color:var(--text-secondary);transition:background .15s,color .15s`;
  const AD = `height:1px;background:var(--border);margin:4px 0`;
  const AH = `padding:6px 14px 3px;font-size:10px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--text-muted)`;

  const actionsMenu = isIP ? `
    <div id="actions-menu" style="display:none;position:fixed;z-index:1000;min-width:220px;background:var(--surface-elevated);border:1px solid var(--border);border-radius:var(--border-radius);box-shadow:var(--shadow-md);padding:4px 0;overflow-y:auto;max-height:80vh">
      <div style="${AH}">Port Scan</div>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerPortScan('${aid}','light')">Light Scan</button>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerPortScan('${aid}','standard')">Standard Scan</button>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerPortScan('${aid}','deep')">Deep Scan</button>
      <div style="${AD}"></div>
      <div style="${AH}">Reconnaissance</div>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerHTTPProbe('${aid}')">HTTP Probe</button>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerSNMPEnum('${aid}')">SNMP Enum</button>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerBGPLookup('${aid}')">BGP Lookup</button>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerIPWhois('${aid}')">IP WHOIS</button>
      <div style="${AD}"></div>
      <div style="${AH}">OT Protocols</div>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerOTProbe('${aid}')">OT Probe</button>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerIEC61850Scan('${aid}')">IEC 61850 MMS</button>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerIEC104Scan('${aid}')">IEC 104 RTU</button>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerICCPScan('${aid}')">ICCP / TASE.2</button>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerModbusDeepScan('${aid}')">Modbus FC1-FC4</button>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerDNP3DeepScan('${aid}')">DNP3 Class 0</button>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerEtherNetIPDeepScan('${aid}')">EtherNet/IP CIP</button>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerProfinetScan('${aid}')">Profinet DCP</button>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerOPCUAScan('${aid}')">OPC-UA</button>
      <div style="${AD}"></div>
      <div style="${AH}">Threats</div>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerCVECorrelate('${aid}')">CVE Correlate</button>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerHistorianDetect('${aid}')">Historian Detect</button>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerHMIFingerprint('${aid}')">HMI Fingerprint</button>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerICSCertSearch('${aid}')">ICS-CERT Advise</button>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerTestDefaultCreds('${aid}')">Default Creds Test</button>
      <div style="${AD}"></div>
      <div style="${AH}">Intelligence</div>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerDeepScan('${aid}')">Shodan Lookup</button>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerFetchCensys('${aid}')">Censys Fetch</button>
      <div style="${AD}"></div>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerAutoScan('${aid}')">&#9889; Auto Scan Chain</button>
    </div>
  ` : isDomain ? `
    <div id="actions-menu" style="display:none;position:fixed;z-index:1000;min-width:200px;background:var(--surface-elevated);border:1px solid var(--border);border-radius:var(--border-radius);box-shadow:var(--shadow-md);padding:4px 0">
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerEnumerate('${aid}')">Enumerate Subdomains</button>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerTLSScan('${aid}')">TLS Scan</button>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerCrtSh('${aid}')">crt.sh Lookup</button>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerSecurityTrails('${aid}')">SecurityTrails</button>
      <button style="${AI}" onmouseover="this.style.background='var(--surface-hover)';this.style.color='var(--text-primary)'" onmouseout="this.style.background='none';this.style.color='var(--text-secondary)'" onclick="App.triggerHTTPProbe('${aid}')">HTTP Probe</button>
    </div>
  ` : '';

  const deepScanBtn = `<button id="btn-actions" class="btn btn-secondary btn-sm" onclick="App.showActionsMenu('${aid}')">Actions &#9660;</button>${actionsMenu}`;

  const shodanRecord = isIP ? en.find(e => e.source === 'shodan') : null;
  const shodanHtml = isIP
    ? (shodanRecord
        ? renderEnrichmentRecord(shodanRecord)
        : renderEmptyState('No Shodan data', 'Use Actions \u2192 Shodan Lookup to fetch intelligence for this IP.'))
    : '';

  const stRecord = isDomain ? en.find(e => e.source === 'securitytrails') : null;
  const crtshRecord = isDomain ? (en.find(e => e.source === 'crtsh') || null) : null;

  const nonShodanEnrich = isIP ? en.filter(e => e.source !== 'shodan') : en;
  const enrichHtml = nonShodanEnrich.length > 0
    ? nonShodanEnrich.map(renderEnrichmentRecord).join('')
    : renderEmptyState('No enrichment data', 'No additional enrichment data available.');

  // TLS tab content (domain assets only).
  const tlsHtml = (() => {
    if (!isDomain) return '';
    if (!tlsResult) {
      return renderEmptyState('No TLS scan data', 'Use Actions \u2192 TLS Scan to inspect the certificate and protocol.');
    }
    const gradeColors = { A: '#22c55e', B: '#84cc16', C: '#f59e0b', F: '#ef4444' };
    const gradeColor = gradeColors[tlsResult.grade] || 'var(--text-muted)';
    const gradeBadge = `<span style="display:inline-flex;align-items:center;justify-content:center;width:36px;height:36px;border-radius:50%;background:${gradeColor};color:#fff;font-weight:700;font-size:16px">${Utils.escapeHtml(tlsResult.grade || '?')}</span>`;

    if (tlsResult.error_msg && !tlsResult.common_name) {
      return `
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
          ${gradeBadge}
          <div>
            <div style="font-weight:600;color:var(--severity-critical)">Connection Failed</div>
            <div style="font-size:12px;color:var(--text-muted)">${Utils.escapeHtml(tlsResult.error_msg)}</div>
          </div>
        </div>
      `;
    }

    let tlsIssues = [];
    try {
      const raw = typeof tlsResult.issues === 'string' ? tlsResult.issues : JSON.stringify(tlsResult.issues || '[]');
      tlsIssues = JSON.parse(raw);
    } catch(_) {}

    const issuesHtml = tlsIssues.length > 0
      ? `<div style="font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">${tlsIssues.length} Issue${tlsIssues.length !== 1 ? 's' : ''} Found</div>` +
        tlsIssues.map(issue => {
          const sev = (issue.severity || 'info').toLowerCase();
          const sevLabel = { critical: 'Critical', high: 'High', medium: 'Medium', info: 'Info' }[sev] || sev;
          const sevColors = { critical: 'var(--severity-critical)', high: 'var(--severity-high)', medium: 'var(--severity-medium)', info: 'var(--text-muted)' };
          return `
            <div style="border-left:3px solid ${sevColors[sev] || 'var(--text-muted)'};padding:10px 14px;background:var(--surface);border-radius:0 4px 4px 0;margin-bottom:8px">
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
                <span class="badge badge-${sev}">${Utils.escapeHtml(sevLabel)}</span>
                <span style="font-weight:600;color:var(--text-primary);font-size:13px">${Utils.escapeHtml(issue.title || '')}</span>
              </div>
              ${issue.description ? `<div style="font-size:12px;color:var(--text-secondary)">${Utils.escapeHtml(issue.description)}</div>` : ''}
            </div>
          `;
        }).join('')
      : `<div style="color:var(--text-muted);font-size:13px;padding:12px 0">No issues found — certificate and protocol look healthy.</div>`;

    const expiryStyle = tlsResult.days_until_expiry != null && tlsResult.days_until_expiry < 30 ? 'color:var(--severity-high)' : '';

    return `
      <div style="display:flex;align-items:center;gap:16px;padding:16px;background:var(--surface);border:1px solid var(--border);border-radius:6px;margin-bottom:16px">
        ${gradeBadge}
        <div style="flex:1">
          <div style="font-size:18px;font-weight:700;color:var(--text-primary);font-family:var(--font-mono)">${Utils.escapeHtml(tlsResult.common_name || '—')}</div>
          <div style="font-size:12px;color:var(--text-muted)">Issued by ${Utils.escapeHtml(tlsResult.issuer || '—')}</div>
        </div>
        <div style="text-align:right">
          <div style="font-size:11px;color:var(--text-muted)">Scanned ${Utils.formatRelativeTime(tlsResult.scanned_at)}</div>
          ${tlsResult.error_msg ? `<div style="font-size:11px;color:var(--severity-high);margin-top:2px">${Utils.escapeHtml(tlsResult.error_msg)}</div>` : ''}
        </div>
      </div>
      <div class="detail-grid" style="margin-bottom:16px">
        <div class="detail-item"><div class="detail-key">TLS Version</div><div class="detail-value mono">${Utils.escapeHtml(tlsResult.tls_version || '—')}</div></div>
        <div class="detail-item"><div class="detail-key">Cipher Suite</div><div class="detail-value mono" style="font-size:11px">${Utils.escapeHtml(tlsResult.cipher_suite || '—')}</div></div>
        <div class="detail-item"><div class="detail-key">Key Algorithm</div><div class="detail-value mono">${Utils.escapeHtml(tlsResult.key_algorithm || '—')}</div></div>
        <div class="detail-item"><div class="detail-key">Key Size</div><div class="detail-value mono">${tlsResult.key_size ? tlsResult.key_size + ' bits' : '—'}</div></div>
        <div class="detail-item"><div class="detail-key">Signature Algorithm</div><div class="detail-value mono">${Utils.escapeHtml(tlsResult.signature_algo || '—')}</div></div>
        <div class="detail-item"><div class="detail-key">Not Before</div><div class="detail-value">${tlsResult.not_before ? Utils.formatISODate(tlsResult.not_before) : '—'}</div></div>
        <div class="detail-item"><div class="detail-key">Not After</div><div class="detail-value">${tlsResult.not_after ? Utils.formatISODate(tlsResult.not_after) : '—'}</div></div>
        <div class="detail-item"><div class="detail-key">Days Until Expiry</div><div class="detail-value" style="${expiryStyle}">${tlsResult.days_until_expiry != null ? tlsResult.days_until_expiry + ' days' : '—'}</div></div>
      </div>
      ${issuesHtml}
    `;
  })();

  // SecurityTrails tab content (domain assets only).
  const stHtml = (() => {
    if (!isDomain) return '';
    if (!stRecord) {
      return renderEmptyState('No SecurityTrails data', 'Use Actions \u2192 SecurityTrails to fetch historical DNS and WHOIS data.');
    }
    let parsed = {};
    try {
      parsed = typeof stRecord.data === 'object' ? stRecord.data : JSON.parse(atob(stRecord.data) || stRecord.data || '{}');
    } catch(_) {}

    const domainInfo = parsed.domain || {};

    const domainInfoHtml = `
      <div style="margin-bottom:16px">
        <div style="font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Domain Info</div>
        <div class="detail-grid">
          ${domainInfo.apex_domain ? `<div class="detail-item"><div class="detail-key">Apex Domain</div><div class="detail-value mono">${Utils.escapeHtml(domainInfo.apex_domain)}</div></div>` : ''}
          ${domainInfo.alexa_rank != null ? `<div class="detail-item"><div class="detail-key">Alexa Rank</div><div class="detail-value mono">${Utils.escapeHtml(String(domainInfo.alexa_rank))}</div></div>` : ''}
          ${domainInfo.subdomain_count != null ? `<div class="detail-item"><div class="detail-key">Subdomain Count</div><div class="detail-value mono">${Utils.escapeHtml(String(domainInfo.subdomain_count))}</div></div>` : ''}
          ${(domainInfo.tags||[]).length > 0 ? `<div class="detail-item"><div class="detail-key">Tags</div><div class="detail-value">${domainInfo.tags.map(t=>`<span class="badge badge-type">${Utils.escapeHtml(String(t))}</span>`).join(' ')}</div></div>` : ''}
        </div>
      </div>
    `;

    const currentDns = domainInfo.current_dns || {};
    const dnsTypes = ['a', 'aaaa', 'mx', 'ns', 'txt'];
    const currentDnsRows = dnsTypes.flatMap(type => {
      const rec = currentDns[type];
      if (!rec) return [];
      const values = (rec.values || []).map(v => {
        const ip = v.ip || v.value || v.hostname || JSON.stringify(v);
        return `<span class="badge badge-type mono" style="font-size:11px">${Utils.escapeHtml(String(ip))}</span>`;
      }).join(' ');
      return values ? [`<div class="detail-item"><div class="detail-key">${type.toUpperCase()}</div><div class="detail-value">${values}</div></div>`] : [];
    }).join('');

    const currentDnsHtml = currentDnsRows ? `
      <div style="margin-bottom:16px">
        <div style="font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Current DNS</div>
        <div class="detail-grid">${currentDnsRows}</div>
      </div>
    ` : '';

    function renderHistorySection(title, id, histData) {
      const records = (histData && histData.records) ? histData.records : [];
      if (!records.length) return '';
      const rows = records.slice(0, 50).map(r => {
        const vals = (r.values || []).map(v => Utils.escapeHtml(String(v.ip || v.value || v.hostname || JSON.stringify(v)))).join(', ');
        return `<tr><td class="mono" style="font-size:11px;word-break:break-all">${vals || '—'}</td><td class="text-muted" style="font-size:11px;white-space:nowrap">${Utils.escapeHtml(r.first_seen || '—')}</td><td class="text-muted" style="font-size:11px;white-space:nowrap">${Utils.escapeHtml(r.last_seen || '—')}</td></tr>`;
      }).join('');
      return `
        <div style="margin-bottom:12px;border:1px solid var(--border-subtle);border-radius:6px;overflow:hidden">
          <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px;cursor:pointer;user-select:none;background:var(--surface)"
               onclick="const b=document.getElementById('${id}');b.style.display=b.style.display==='none'?'block':'none';this.querySelector('.st-toggle').textContent=b.style.display==='none'?'\u25b6':'\u25bc'">
            <span style="font-size:12px;font-weight:600;color:var(--text-primary)">${Utils.escapeHtml(title)} <span class="text-muted" style="font-weight:400">(${records.length})</span></span>
            <span class="st-toggle text-muted" style="font-size:11px">\u25b6</span>
          </div>
          <div id="${id}" style="display:none">
            <div class="table-wrapper" style="margin:0">
              <table class="data-table" style="font-size:12px">
                <thead><tr><th>Value</th><th>First Seen</th><th>Last Seen</th></tr></thead>
                <tbody>${rows}</tbody>
              </table>
            </div>
          </div>
        </div>
      `;
    }

    const histAHtml    = renderHistorySection('A Record History',    'st-hist-a',    parsed.history_a);
    const histNsHtml   = renderHistorySection('NS Record History',   'st-hist-ns',   parsed.history_ns);
    const histMxHtml   = renderHistorySection('MX Record History',   'st-hist-mx',   parsed.history_mx);
    const histTxtHtml  = renderHistorySection('TXT Record History',  'st-hist-txt',  parsed.history_txt);

    const whoisRecords = (parsed.history_whois && parsed.history_whois.result) ? parsed.history_whois.result : [];
    const whoisHtml = whoisRecords.length > 0 ? `
      <div style="margin-bottom:12px;border:1px solid var(--border-subtle);border-radius:6px;overflow:hidden">
        <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px;cursor:pointer;user-select:none;background:var(--surface)"
             onclick="const b=document.getElementById('st-hist-whois');b.style.display=b.style.display==='none'?'block':'none';this.querySelector('.st-toggle').textContent=b.style.display==='none'?'\u25b6':'\u25bc'">
          <span style="font-size:12px;font-weight:600;color:var(--text-primary)">WHOIS History <span class="text-muted" style="font-weight:400">(${whoisRecords.length})</span></span>
          <span class="st-toggle text-muted" style="font-size:11px">\u25b6</span>
        </div>
        <div id="st-hist-whois" style="display:none;padding:12px 14px">
          ${whoisRecords.map(w => `
            <div style="border:1px solid var(--border-subtle);border-radius:4px;padding:10px;margin-bottom:8px;background:var(--surface-elevated)">
              <div class="detail-grid">
                ${w.registrar ? `<div class="detail-item"><div class="detail-key">Registrar</div><div class="detail-value">${Utils.escapeHtml(String(w.registrar))}</div></div>` : ''}
                ${w.created_date ? `<div class="detail-item"><div class="detail-key">Created</div><div class="detail-value">${Utils.escapeHtml(String(w.created_date))}</div></div>` : ''}
                ${w.expires_date ? `<div class="detail-item"><div class="detail-key">Expires</div><div class="detail-value">${Utils.escapeHtml(String(w.expires_date))}</div></div>` : ''}
                ${w.updated_date ? `<div class="detail-item"><div class="detail-key">Updated</div><div class="detail-value">${Utils.escapeHtml(String(w.updated_date))}</div></div>` : ''}
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    ` : '';

    return `
      ${domainInfoHtml}
      ${currentDnsHtml}
      ${histAHtml}
      ${histNsHtml}
      ${histMxHtml}
      ${histTxtHtml}
      ${whoisHtml}
      <div style="margin-top:16px;border-top:1px solid var(--border-subtle);padding-top:12px">
        <div style="display:flex;align-items:center;justify-content:space-between;cursor:pointer;user-select:none"
             onclick="const el=document.getElementById('st-raw');el.style.display=el.style.display==='none'?'block':'none';this.querySelector('.raw-toggle').textContent=el.style.display==='none'?'\u25b6 Show Raw JSON':'\u25bc Hide Raw JSON'">
          <span class="text-muted" style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em">Raw JSON</span>
          <span class="raw-toggle text-muted" style="font-size:11px">\u25b6 Show Raw JSON</span>
        </div>
        <pre id="st-raw" style="display:none;margin:8px 0 0;font-family:var(--font-mono);font-size:10px;color:var(--text-secondary);background:var(--surface-elevated);padding:12px;border-radius:4px;overflow:auto;max-height:400px;white-space:pre-wrap;word-break:break-all">${Utils.escapeHtml(JSON.stringify(parsed, null, 2))}</pre>
      </div>
    `;
  })();

  // crt.sh Certificate Transparency tab content (domain assets only).
  const crtshHtml = (() => {
    if (!isDomain) return '';
    if (!crtshRecord) {
      return renderEmptyState('No crt.sh data', 'Use Actions \u2192 crt.sh Lookup to search Certificate Transparency logs for this domain.');
    }
    let parsed = {};
    try {
      parsed = typeof crtshRecord.data === 'object' ? crtshRecord.data : JSON.parse(atob(crtshRecord.data) || crtshRecord.data || '{}');
    } catch(_) {}

    const names = Array.isArray(parsed.names) ? parsed.names : [];
    const entries = Array.isArray(parsed.entries) ? parsed.entries : [];

    const namesHtml = names.length > 0 ? `
      <div style="margin-bottom:16px">
        <div style="font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">${names.length} Unique Name${names.length !== 1 ? 's' : ''} Found</div>
        <div class="table-wrapper" style="margin:0">
          <table class="data-table">
            <thead><tr><th>Hostname</th></tr></thead>
            <tbody>
              ${names.map(n => `<tr><td class="mono" style="font-size:12px">${Utils.escapeHtml(n)}</td></tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>
    ` : '<div style="color:var(--text-muted);font-size:13px;padding:12px 0">No hostnames found in certificate data.</div>';

    const fetchedAt = parsed.fetched_at ? Utils.formatRelativeTime(parsed.fetched_at) : '';

    return `
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
        <div style="font-size:13px;color:var(--text-secondary)">Certificate Transparency data for <span class="mono">${Utils.escapeHtml(parsed.domain || '')}</span>${fetchedAt ? ` &mdash; fetched ${fetchedAt}` : ''}</div>
        <span class="badge badge-type">${entries.length} cert${entries.length !== 1 ? 's' : ''}</span>
      </div>
      ${namesHtml}
      <div style="margin-top:16px;border-top:1px solid var(--border-subtle);padding-top:12px">
        <div style="display:flex;align-items:center;justify-content:space-between;cursor:pointer;user-select:none"
             onclick="const el=document.getElementById('crtsh-raw');el.style.display=el.style.display==='none'?'block':'none';this.querySelector('.raw-toggle').textContent=el.style.display==='none'?'\u25b6 Show Raw JSON':'\u25bc Hide Raw JSON'">
          <span class="text-muted" style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em">Raw JSON</span>
          <span class="raw-toggle text-muted" style="font-size:11px">\u25b6 Show Raw JSON</span>
        </div>
        <pre id="crtsh-raw" style="display:none;margin:8px 0 0;font-family:var(--font-mono);font-size:10px;color:var(--text-secondary);background:var(--surface-elevated);padding:12px;border-radius:4px;overflow:auto;max-height:400px;white-space:pre-wrap;word-break:break-all">${Utils.escapeHtml(JSON.stringify(parsed, null, 2))}</pre>
      </div>
    `;
  })();

  // HTTP Probe tab content (all asset types).
  const httpProbeHtml = (() => {
    if (!httpProbeRecord) {
      return renderEmptyState('No HTTP probe data', 'Use Actions \u2192 HTTP Probe to fingerprint web services on this asset.');
    }
    let parsed = {};
    try {
      parsed = typeof httpProbeRecord.data === 'object' ? httpProbeRecord.data : JSON.parse(atob(httpProbeRecord.data) || httpProbeRecord.data || '{}');
    } catch(_) {}

    const probes = Array.isArray(parsed.probes) ? parsed.probes : [];
    const activeProbes = probes.filter(p => p.status_code > 0);

    if (activeProbes.length === 0) {
      return renderEmptyState('No web services found', 'No HTTP/HTTPS services responded on common web ports for this asset.');
    }

    const statusBadge = (code) => {
      if (!code) return '';
      let color = 'var(--text-muted)';
      if (code >= 200 && code < 300) color = 'var(--severity-low)';
      else if (code >= 300 && code < 400) color = 'var(--severity-medium)';
      else if (code >= 400) color = 'var(--severity-high)';
      return `<span style="display:inline-block;padding:2px 8px;border-radius:3px;background:${color};color:#fff;font-size:11px;font-weight:600;font-family:var(--font-mono)">${code}</span>`;
    };

    const secHeaderBadge = (ok, label) =>
      `<span style="display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:3px;background:var(--surface);border:1px solid ${ok ? 'var(--severity-low)' : 'var(--border)'};font-size:11px;color:${ok ? 'var(--severity-low)' : 'var(--text-muted)'}">${ok ? '\u2713' : '\u2717'} ${Utils.escapeHtml(label)}</span>`;

    const probesHtml = activeProbes.map(p => `
      <div style="border:1px solid var(--border);border-radius:6px;padding:14px;margin-bottom:12px;background:var(--surface)">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap">
          ${statusBadge(p.status_code)}
          <span class="mono" style="font-size:13px;font-weight:600;color:var(--accent-blue)">${Utils.escapeHtml(p.url)}</span>
          ${p.final_url ? `<span style="font-size:11px;color:var(--text-muted)">&rarr; ${Utils.escapeHtml(p.final_url)}</span>` : ''}
        </div>
        ${p.title ? `<div style="font-size:12px;color:var(--text-secondary);margin-bottom:8px"><strong>Title:</strong> ${Utils.escapeHtml(p.title)}</div>` : ''}
        <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px">
          ${p.server ? `<span class="badge badge-type">Server: ${Utils.escapeHtml(p.server)}</span>` : ''}
          ${p.powered_by ? `<span class="badge badge-type">Powered By: ${Utils.escapeHtml(p.powered_by)}</span>` : ''}
          ${(p.technologies || []).map(t => `<span class="badge badge-cloud">${Utils.escapeHtml(t)}</span>`).join('')}
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:8px">
          ${secHeaderBadge(p.hsts, 'HSTS')}
          ${secHeaderBadge(p.csp, 'CSP')}
          ${secHeaderBadge(p.x_frame_options, 'X-Frame-Options')}
          ${secHeaderBadge(p.x_content_type_options, 'X-Content-Type-Options')}
        </div>
        ${(p.interesting_paths || []).length > 0 ? `
          <div style="margin-top:8px">
            <div style="font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Interesting Paths</div>
            <div style="display:flex;flex-wrap:wrap;gap:4px">
              ${p.interesting_paths.map(ip => `<span style="display:inline-block;padding:2px 8px;border-radius:3px;background:var(--severity-high);color:#fff;font-size:11px;font-family:var(--font-mono)">${Utils.escapeHtml(ip.path)} (${ip.status_code})</span>`).join('')}
            </div>
          </div>
        ` : ''}
        ${p.error ? `<div style="font-size:12px;color:var(--severity-high);margin-top:6px">Error: ${Utils.escapeHtml(p.error)}</div>` : ''}
      </div>
    `).join('');

    return `
      ${probesHtml}
      <div style="margin-top:16px;border-top:1px solid var(--border-subtle);padding-top:12px">
        <div style="display:flex;align-items:center;justify-content:space-between;cursor:pointer;user-select:none"
             onclick="const el=document.getElementById('httpprobe-raw');el.style.display=el.style.display==='none'?'block':'none';this.querySelector('.raw-toggle').textContent=el.style.display==='none'?'\u25b6 Show Raw JSON':'\u25bc Hide Raw JSON'">
          <span class="text-muted" style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em">Raw JSON</span>
          <span class="raw-toggle text-muted" style="font-size:11px">\u25b6 Show Raw JSON</span>
        </div>
        <pre id="httpprobe-raw" style="display:none;margin:8px 0 0;font-family:var(--font-mono);font-size:10px;color:var(--text-secondary);background:var(--surface-elevated);padding:12px;border-radius:4px;overflow:auto;max-height:400px;white-space:pre-wrap;word-break:break-all">${Utils.escapeHtml(JSON.stringify(parsed, null, 2))}</pre>
      </div>
    `;
  })();

  return `
    <div class="asset-detail-layout" id="asset-detail-layout">
      <div class="asset-detail-panel">
        <div class="card mb-16">
          <div class="card-header">
            <div>
              <div class="card-title">${Utils.escapeHtml(asset.value)}</div>
              <div class="card-subtitle">Asset Information</div>
            </div>
            ${deepScanBtn}
          </div>
          <div class="card-body" style="padding:0">
            ${infoHtml}
          </div>
        </div>
        <div class="card-grid card-grid-2">
          ${renderStatCard('Open Ports', sr.length, 'Scan results')}
          ${renderStatCard('Findings', fi.length, 'Security issues', fi.some(f => f.severity === 'critical') ? 'critical' : '')}
          ${isDomain ? renderStatCard('Subdomains', subs.length, 'Discovered subdomains') : ''}
        </div>
      </div>

      <div class="asset-detail-right">
        <div class="tabs" id="asset-tabs">
          <button class="tab-btn active" data-tab="scan">Scan Results (${sr.length})</button>
          <button class="tab-btn" data-tab="dns">DNS Records (${dns.length})</button>
          ${isIP ? `<button class="tab-btn" data-tab="shodan">Shodan${shodanRecord ? ' \u2713' : ''}</button>` : ''}
          ${isDomain ? `<button class="tab-btn" data-tab="subdomains">Subdomains (${subs.length})</button>` : ''}
          ${isDomain ? `<button class="tab-btn" data-tab="tls">TLS${tlsResult ? ' (' + (tlsResult.grade || '?') + ')' : ''}</button>` : ''}
          ${isDomain ? `<button class="tab-btn" data-tab="st">SecurityTrails${stRecord ? ' \u2713' : ''}</button>` : ''}
          ${isDomain ? `<button class="tab-btn" data-tab="crtsh">crt.sh${crtshRecord ? ' \u2713' : ''}</button>` : ''}
          ${isDomain ? `<button class="tab-btn" data-tab="http-probe">HTTP Probe${httpProbeRecord ? ' \u2713' : ''}</button>` : ''}
          ${isIP ? `<button class="tab-btn" data-tab="recon">Recon${(snmpRecord || bgpRecord || ipWhoisRecord || httpProbeRecord) ? ' \u2713' : ''}</button>` : ''}
          ${isIP ? `<button class="tab-btn" data-tab="ot-probe">OT Probe${otProbeRecord ? ' \u2713' : ''}</button>` : ''}
          ${isIP ? `<button class="tab-btn" data-tab="threats">Threats${(cveRecord || vulnNotesData) ? ' \u2713' : ''}</button>` : ''}
          ${isIP ? `<button class="tab-btn" data-tab="ot-intel">OT Intel${(iec61850Record || historianRecord || hmiRecord || icscertRecord || iec104Record || modbusDeepRecord || dnp3DeepRecord || iccpRecord || enipDeepRecord || profinetRecord || opcuaRecord || defaultCredsRecord || censysRecord) ? ' \u2713' : ''}</button>` : ''}
          ${isIP ? `<button class="tab-btn" data-tab="nerc-cip">NERC CIP${(nercCipData && (nercCipData.bcs_asset || nercCipData.impact_rating)) ? ' \u2713' : ''}</button>` : ''}
          ${isIP ? `<button class="tab-btn" data-tab="history">History</button>` : ''}
          <button class="tab-btn" data-tab="findings">Findings (${fi.length})</button>
          <button class="tab-btn" data-tab="enrichment">Enrichment (${nonShodanEnrich.length})</button>
        </div>

        <div class="tab-content active" id="tab-scan">
          ${scanHtml}
        </div>
        <div class="tab-content" id="tab-dns">
          ${dnsHtml}
        </div>
        ${isIP ? `<div class="tab-content" id="tab-shodan">${shodanHtml}</div>` : ''}
        ${isDomain ? `<div class="tab-content" id="tab-subdomains">${subsHtml}</div>` : ''}
        ${isDomain ? `<div class="tab-content" id="tab-tls">${tlsHtml}</div>` : ''}
        ${isDomain ? `<div class="tab-content" id="tab-st">${stHtml}</div>` : ''}
        ${isDomain ? `<div class="tab-content" id="tab-crtsh">${crtshHtml}</div>` : ''}
        ${isDomain ? `<div class="tab-content" id="tab-http-probe">${httpProbeHtml}</div>` : ''}
        ${isIP ? `<div class="tab-content" id="tab-recon">${renderReconTab(snmpRecord, bgpRecord, ipWhoisRecord, httpProbeHtml)}</div>` : ''}
        ${isIP ? `<div class="tab-content" id="tab-ot-probe">${renderOTProbeTab(otProbeRecord)}</div>` : ''}
        ${isIP ? `<div class="tab-content" id="tab-threats">${renderThreatsTab(cveRecord, vulnNotesData)}</div>` : ''}
        ${isIP ? `<div class="tab-content" id="tab-ot-intel">${renderOTIntelTab(iec61850Record, historianRecord, hmiRecord, icscertRecord, iec104Record, modbusDeepRecord, dnp3DeepRecord, iccpRecord, enipDeepRecord, profinetRecord, opcuaRecord, defaultCredsRecord, censysRecord)}</div>` : ''}
        ${isIP ? `<div class="tab-content" id="tab-nerc-cip">${renderNERCCIPTab(asset.id, nercCipData)}</div>` : ''}
        ${isIP ? `<div class="tab-content" id="tab-history">${renderScanHistoryTab(asset.id)}</div>` : ''}
        <div class="tab-content" id="tab-findings">
          ${findingsHtml}
        </div>
        <div class="tab-content" id="tab-enrichment">
          ${enrichHtml}
        </div>
      </div>
    </div>
  `;
}

/* -------------------------------------------------------------------------
   Component: renderOTIntelTab  (IEC 61850 + Historian + HMI + ICS-CERT combined)
   ------------------------------------------------------------------------- */
function renderScanHistoryTab(assetId) {
  return `<div id="scan-history-content" style="padding:8px 0">
    <div style="color:var(--text-muted);font-size:13px">Loading scan history\u2026</div>
  </div>`;
  // History is loaded lazily when the tab is clicked — see _bindTabListeners extension below.
}

/* -------------------------------------------------------------------------
   Component: renderOTIntelTab  (IEC 61850 + Historian + HMI + ICS-CERT + new protocols combined)
   ------------------------------------------------------------------------- */
function renderOTIntelTab(iec61850Rec, historianRec, hmiRec, icscertRec, iec104Rec, modbusDeepRec, dnp3DeepRec, iccpRec, enipDeepRec, profinetRec, opcuaRec, defaultCredsRec, censysRec) {
  function parseData(rec) {
    if (!rec || !rec.data) return null;
    try {
      if (typeof rec.data === 'object') return rec.data;
      try { return JSON.parse(rec.data); } catch(_) {}
      return JSON.parse(atob(rec.data));
    } catch(_) { return null; }
  }

  const iec = parseData(iec61850Rec);
  const hist = parseData(historianRec);
  const hmi = parseData(hmiRec);
  const ics = parseData(icscertRec);
  const iec104 = parseData(iec104Rec);
  const modbusDeep = parseData(modbusDeepRec);
  const dnp3Deep = parseData(dnp3DeepRec);
  const iccp = parseData(iccpRec);
  const enipDeep = parseData(enipDeepRec);
  const profinet = parseData(profinetRec);
  const opcua = parseData(opcuaRec);
  const defCreds = parseData(defaultCredsRec);
  const censys = parseData(censysRec);

  // IEC 61850 section
  let iecBody = '';
  if (iec) {
    const ied = iec;
    iecBody = `
      <div style="margin-bottom:8px">
        <span style="font-size:12px;color:var(--text-muted)">Device Type:</span>
        <span style="font-size:12px;font-weight:600;margin-left:6px">${Utils.escapeHtml(ied.device_type || 'Unknown')}</span>
      </div>
      <div style="margin-bottom:8px">
        <span style="font-size:12px;color:var(--text-muted)">Responded:</span>
        <span style="font-size:12px;font-weight:600;margin-left:6px;color:${ied.responded ? 'var(--severity-high)' : 'var(--text-muted)'}">${ied.responded ? 'Yes' : 'No'}</span>
      </div>
      ${ied.logical_devices && ied.logical_devices.length > 0 ? `
        <div style="margin-bottom:8px">
          <div style="font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Logical Devices</div>
          ${ied.logical_devices.map(d => `<span style="display:inline-block;margin:2px 4px 2px 0;padding:2px 8px;background:var(--surface);border:1px solid var(--border);border-radius:3px;font-size:12px">${Utils.escapeHtml(d)}</span>`).join('')}
        </div>` : ''}
      ${ied.raw_banner ? `<div style="font-size:11px;color:var(--text-muted);font-family:monospace;word-break:break-all">Banner: ${Utils.escapeHtml(ied.raw_banner)}</div>` : ''}`;
  }

  // Historian section
  let histBody = '';
  if (hist && hist.services && hist.services.length > 0) {
    histBody = hist.services.map(svc => `
      <div style="padding:10px 12px;border:1px solid var(--border);border-radius:6px;margin-bottom:8px;border-left:3px solid var(--severity-critical)">
        <div style="font-weight:600;color:var(--text-primary);margin-bottom:4px">${Utils.escapeHtml(svc.product)} <span style="font-size:11px;color:var(--text-muted)">port ${svc.port}</span></div>
        ${svc.version ? `<div style="font-size:12px;color:var(--text-secondary)">Version: ${Utils.escapeHtml(svc.version)}</div>` : ''}
        ${svc.banner ? `<div style="font-size:11px;color:var(--text-muted);font-family:monospace;margin-top:4px;word-break:break-all">${Utils.escapeHtml(svc.banner)}</div>` : ''}
      </div>`).join('');
  }

  // HMI section
  let hmiBody = '';
  if (hmi && hmi.hmis && hmi.hmis.length > 0) {
    hmiBody = hmi.hmis.map(h => `
      <div style="padding:10px 12px;border:1px solid var(--border);border-radius:6px;margin-bottom:8px;border-left:3px solid var(--severity-high)">
        <div style="font-weight:600;color:var(--text-primary);margin-bottom:4px">${Utils.escapeHtml(h.vendor)} ${Utils.escapeHtml(h.product)} <span style="font-size:11px;color:var(--text-muted)">port ${h.port}</span></div>
        ${h.version ? `<div style="font-size:12px;color:var(--text-secondary)">Version: ${Utils.escapeHtml(h.version)}</div>` : ''}
        <div style="font-size:12px;color:var(--severity-high);margin-top:4px">${Utils.escapeHtml(h.risk_note || '')}</div>
        ${h.evidence ? `<div style="font-size:11px;color:var(--text-muted);margin-top:4px">${Utils.escapeHtml(h.evidence)}</div>` : ''}
      </div>`).join('');
  }

  // ICS-CERT section
  let icsBody = '';
  if (ics && ics.advisories && ics.advisories.length > 0) {
    icsBody = `<div style="font-size:12px;color:var(--text-muted);margin-bottom:8px">${ics.total} advisories found</div>` +
      ics.advisories.slice(0, 20).map(a => `
        <div style="padding:8px 12px;border:1px solid var(--border);border-radius:4px;margin-bottom:6px">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px">
            <span style="font-size:11px;font-weight:700;color:var(--severity-critical)">${Utils.escapeHtml(a.id)}</span>
            <span style="font-size:12px;font-weight:600">${Utils.escapeHtml(a.title)}</span>
          </div>
          <div style="font-size:11px;color:var(--text-secondary)">Vendor: ${Utils.escapeHtml(a.vendor)} &mdash; Product: ${Utils.escapeHtml(a.product)}</div>
          ${a.description ? `<div style="font-size:11px;color:var(--text-muted);margin-top:3px">${Utils.escapeHtml(a.description.substring(0,200))}${a.description.length > 200 ? '...' : ''}</div>` : ''}
          <div style="font-size:10px;color:var(--text-muted);margin-top:3px">Added: ${Utils.escapeHtml(a.date_added || '')}</div>
        </div>`).join('');
  }

  // IEC 104 section
  let iec104Body = '';
  if (iec104 && iec104.responded) {
    iec104Body = `
      <div style="padding:10px 12px;border:1px solid var(--border);border-radius:6px;margin-bottom:8px;border-left:3px solid var(--severity-critical)">
        <div style="font-weight:600;color:var(--text-primary);margin-bottom:4px">Device Type: <span style="color:var(--severity-critical)">${Utils.escapeHtml(iec104.device_type || 'IEC 104 RTU')}</span></div>
        ${iec104.data_objects && iec104.data_objects.length > 0 ? `
          <div style="font-size:12px;color:var(--text-secondary);margin-top:4px">Data Objects: ${iec104.data_objects.length} streaming</div>
          <table style="width:100%;border-collapse:collapse;margin-top:6px;font-size:11px">
            <tr style="border-bottom:1px solid var(--border)"><th style="text-align:left;padding:3px 6px;color:var(--text-muted)">Type</th><th style="text-align:left;padding:3px 6px;color:var(--text-muted)">Address</th><th style="text-align:left;padding:3px 6px;color:var(--text-muted)">Raw Value</th></tr>
            ${iec104.data_objects.slice(0,10).map(d => `<tr style="border-bottom:1px solid var(--border)"><td style="padding:3px 6px">${d.type_id}</td><td style="padding:3px 6px">${d.address}</td><td style="padding:3px 6px;font-family:monospace">${Utils.escapeHtml(d.raw_value || '')}</td></tr>`).join('')}
          </table>` : ''}
        ${iec104.raw_banner ? `<div style="font-size:11px;color:var(--text-muted);font-family:monospace;margin-top:6px;word-break:break-all">Banner: ${Utils.escapeHtml(iec104.raw_banner)}</div>` : ''}
      </div>`;
  }

  // Modbus Deep section
  let modbusDeepBody = '';
  if (modbusDeep && modbusDeep.registers && modbusDeep.registers.length > 0) {
    modbusDeepBody = modbusDeep.registers.map(rs => `
      <div style="padding:8px 12px;border:1px solid var(--border);border-radius:4px;margin-bottom:6px">
        <div style="font-size:12px;font-weight:600;margin-bottom:4px">FC${rs.fc} \u2014 ${Utils.escapeHtml(rs.name)}</div>
        ${rs.error ? `<div style="font-size:11px;color:var(--text-muted)">${Utils.escapeHtml(rs.error)}</div>` :
          `<div style="font-size:11px;color:var(--text-secondary);font-family:monospace">[${(rs.values || []).join(', ')}]</div>`}
      </div>`).join('');
  }

  // DNP3 Deep section
  let dnp3DeepBody = '';
  if (dnp3Deep && dnp3Deep.responded) {
    dnp3DeepBody = `
      <div style="padding:10px 12px;border:1px solid var(--border);border-radius:6px;margin-bottom:8px;border-left:3px solid var(--severity-critical)">
        <div style="font-weight:600;color:var(--severity-critical);margin-bottom:4px">DNP3 RTU Responded</div>
        ${dnp3Deep.data_points && dnp3Deep.data_points.length > 0 ? `
          <div style="font-size:12px;color:var(--text-secondary)">${dnp3Deep.data_points.length} data point(s) received</div>` : ''}
        ${dnp3Deep.raw_banner ? `<div style="font-size:11px;color:var(--text-muted);font-family:monospace;margin-top:4px;word-break:break-all">Banner: ${Utils.escapeHtml(dnp3Deep.raw_banner)}</div>` : ''}
      </div>`;
  }

  // ICCP section
  let iccpBody = '';
  if (iccp && iccp.responded) {
    iccpBody = `
      <div style="padding:10px 12px;border:1px solid var(--border);border-radius:6px;margin-bottom:8px;border-left:3px solid var(--severity-critical)">
        <div style="font-weight:600;color:var(--text-primary);margin-bottom:4px">Device Type: <span style="color:${iccp.device_type && iccp.device_type.includes('ICCP') ? 'var(--severity-critical)' : 'var(--text-secondary)'}">${Utils.escapeHtml(iccp.device_type || 'COTP')}</span></div>
        ${iccp.raw_banner ? `<div style="font-size:11px;color:var(--text-muted);font-family:monospace;margin-top:4px;word-break:break-all">Banner: ${Utils.escapeHtml(iccp.raw_banner)}</div>` : ''}
      </div>`;
  }

  // EtherNet/IP Deep section
  let enipDeepBody = '';
  if (enipDeep && enipDeep.responded) {
    enipDeepBody = `
      <div style="padding:10px 12px;border:1px solid var(--border);border-radius:6px;margin-bottom:8px;border-left:3px solid var(--severity-high)">
        ${enipDeep.product_name ? `<div style="font-weight:600;color:var(--text-primary);margin-bottom:4px">${Utils.escapeHtml(enipDeep.product_name)}</div>` : ''}
        ${enipDeep.vendor_id ? `<div style="font-size:12px;color:var(--text-secondary)">Vendor ID: 0x${enipDeep.vendor_id.toString(16).toUpperCase().padStart(4,'0')}</div>` : ''}
        ${enipDeep.tags && enipDeep.tags.length > 0 ? `
          <div style="font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin:6px 0 4px">CIP Tags</div>
          ${enipDeep.tags.slice(0,15).map(t => `<span style="display:inline-block;margin:2px 4px 2px 0;padding:2px 8px;background:var(--surface);border:1px solid var(--border);border-radius:3px;font-size:11px;font-family:monospace">${Utils.escapeHtml(t.name)}</span>`).join('')}` : ''}
      </div>`;
  }

  // Profinet section
  let profinetBody = '';
  if (profinet && profinet.responded) {
    profinetBody = `
      <div style="padding:10px 12px;border:1px solid var(--border);border-radius:6px;margin-bottom:8px;border-left:3px solid var(--severity-high)">
        ${profinet.station_name ? `<div style="font-weight:600;color:var(--text-primary);margin-bottom:4px">Station: ${Utils.escapeHtml(profinet.station_name)}</div>` : '<div style="font-weight:600;color:var(--text-primary);margin-bottom:4px">Profinet Device Responded</div>'}
        ${profinet.vendor_id ? `<div style="font-size:12px;color:var(--text-secondary)">Vendor ID: ${Utils.escapeHtml(profinet.vendor_id)}</div>` : ''}
        ${profinet.raw_banner ? `<div style="font-size:11px;color:var(--text-muted);font-family:monospace;margin-top:4px;word-break:break-all">Banner: ${Utils.escapeHtml(profinet.raw_banner)}</div>` : ''}
      </div>`;
  }

  // OPC-UA section
  let opcuaBody = '';
  if (opcua && opcua.responded) {
    opcuaBody = `
      <div style="padding:10px 12px;border:1px solid var(--border);border-radius:6px;margin-bottom:8px;border-left:3px solid var(--severity-medium)">
        <div style="font-weight:600;color:var(--text-primary);margin-bottom:4px">${Utils.escapeHtml(opcua.server_uri || 'OPC-UA Server')}</div>
        ${opcua.endpoints && opcua.endpoints.length > 0 ? `
          <div style="font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin:6px 0 4px">Endpoints</div>
          ${opcua.endpoints.map(ep => `
            <div style="font-size:11px;padding:4px 0;border-bottom:1px solid var(--border)">
              <span style="font-family:monospace;color:var(--text-secondary)">${Utils.escapeHtml(ep.url)}</span>
              <span style="margin-left:8px;padding:1px 6px;border-radius:3px;font-size:10px;background:${ep.security_mode === 'None' ? 'rgba(239,68,68,.1)' : 'rgba(34,197,94,.1)'};color:${ep.security_mode === 'None' ? 'var(--severity-high)' : 'var(--severity-low)'}">
                ${Utils.escapeHtml(ep.security_mode)}
              </span>
            </div>`).join('')}` : ''}
      </div>`;
  }

  // Default Credentials section
  let defCredsBody = '';
  if (defCreds) {
    const found = defCreds.found;
    defCredsBody = `
      <div style="padding:10px 12px;border:1px solid ${found ? 'var(--severity-critical)' : 'var(--border)'};border-radius:6px;margin-bottom:8px;border-left:3px solid ${found ? 'var(--severity-critical)' : 'var(--border)'}">
        <div style="font-weight:600;color:${found ? 'var(--severity-critical)' : 'var(--text-primary)'};margin-bottom:8px">${found ? '\u26a0 DEFAULT CREDENTIALS ACCEPTED' : 'No default credentials accepted'}</div>
        ${(defCreds.results || []).filter(r => r.success).map(r => `
          <div style="padding:6px 10px;background:rgba(239,68,68,.08);border-radius:4px;margin-bottom:4px;font-size:12px">
            <strong>${Utils.escapeHtml(r.username)}</strong> / <strong>${Utils.escapeHtml(r.password || '(empty)')}</strong>
            <span style="margin-left:8px;color:var(--text-muted)">${Utils.escapeHtml(r.url)}</span>
          </div>`).join('')}
      </div>`;
  }

  // Censys section
  let censysBody = '';
  if (censys) {
    const svcCount = (censys.services || []).length;
    censysBody = `
      <div style="padding:10px 12px;border:1px solid var(--border);border-radius:6px;margin-bottom:8px">
        <div style="font-size:12px;color:var(--text-secondary);margin-bottom:6px">IP: ${Utils.escapeHtml(censys.ip || '')} \u2014 ${svcCount} service(s)</div>
        ${(censys.services || []).slice(0,10).map(svc => `
          <div style="font-size:11px;padding:4px 0;border-bottom:1px solid var(--border)">
            <span style="font-family:monospace">${Utils.escapeHtml(String(svc.port || ''))}</span>
            <span style="margin-left:8px;color:var(--text-muted)">${Utils.escapeHtml(svc.service_name || svc.transport_protocol || '')}</span>
          </div>`).join('')}
      </div>`;
  }

  return `
    ${reconSection('iec61850', 'IEC 61850 MMS Scan', !!iec, iec && iec.device_type ? `<span class="badge badge-type">${Utils.escapeHtml(iec.device_type)}</span>` : '', iecBody || renderEmptyState('No IEC 61850 data', 'Use Actions \u2192 OT Intel \u2192 IEC 61850 Scan to probe port 102.'))}
    ${reconSection('historian', 'Historian Detection', !!(hist && hist.services && hist.services.length > 0), hist && hist.services ? `<span class="badge badge-type">${hist.services.length} service(s)</span>` : '', histBody || renderEmptyState('No historian data', 'Use Actions \u2192 OT Intel \u2192 Historian Detect.'))}
    ${reconSection('hmi', 'HMI Fingerprinting', !!(hmi && hmi.hmis && hmi.hmis.length > 0), hmi && hmi.hmis ? `<span class="badge badge-type">${hmi.hmis.length} HMI(s)</span>` : '', hmiBody || renderEmptyState('No HMI data', 'Use Actions \u2192 OT Intel \u2192 HMI Fingerprint.'))}
    ${reconSection('icscert', 'ICS-CERT Advisories', !!(ics && ics.advisories && ics.advisories.length > 0), ics && ics.total ? `<span class="badge badge-type">${ics.total} advisories</span>` : '', icsBody || renderEmptyState('No ICS-CERT data', 'Use Actions \u2192 OT Intel \u2192 ICS-CERT Search.'))}
    ${reconSection('iec104', 'IEC 60870-5-104 (Grid RTU)', !!(iec104 && iec104.responded), iec104 && iec104.responded ? `<span class="badge badge-type" style="background:rgba(239,68,68,.15);color:var(--severity-critical)">${Utils.escapeHtml(iec104.device_type || 'RTU')}</span>` : '', iec104Body || renderEmptyState('No IEC 104 data', 'Use Actions \u2192 Protocols \u2192 IEC 104 Scan to probe port 2404.'))}
    ${reconSection('modbusdeep', 'Modbus Deep Read (FC1-FC4)', !!(modbusDeep && modbusDeep.registers && modbusDeep.registers.some(r => !r.error)), modbusDeep ? `<span class="badge badge-type">${modbusDeep.registers ? modbusDeep.registers.filter(r=>!r.error).length : 0} FC(s) responded</span>` : '', modbusDeepBody || renderEmptyState('No Modbus deep data', 'Use Actions \u2192 Protocols \u2192 Modbus Deep Scan.'))}
    ${reconSection('dnp3deep', 'DNP3 Deep Enumeration', !!(dnp3Deep && dnp3Deep.responded), dnp3Deep && dnp3Deep.responded ? `<span class="badge badge-type" style="background:rgba(239,68,68,.15);color:var(--severity-critical)">RTU Active</span>` : '', dnp3DeepBody || renderEmptyState('No DNP3 deep data', 'Use Actions \u2192 Protocols \u2192 DNP3 Deep Scan.'))}
    ${reconSection('iccp', 'ICCP/TASE.2 Detection', !!(iccp && iccp.responded && iccp.device_type && iccp.device_type.includes('ICCP')), iccp && iccp.responded ? `<span class="badge badge-type">${Utils.escapeHtml(iccp.device_type || '')}</span>` : '', iccpBody || renderEmptyState('No ICCP data', 'Use Actions \u2192 Protocols \u2192 ICCP Scan.'))}
    ${reconSection('enipdeep', 'EtherNet/IP CIP Deep', !!(enipDeep && enipDeep.responded), enipDeep && enipDeep.tags && enipDeep.tags.length > 0 ? `<span class="badge badge-type">${enipDeep.tags.length} tag(s)</span>` : '', enipDeepBody || renderEmptyState('No EtherNet/IP deep data', 'Use Actions \u2192 Protocols \u2192 EtherNet/IP Deep Scan.'))}
    ${reconSection('profinet', 'Profinet DCP Detection', !!(profinet && profinet.responded), profinet && profinet.station_name ? `<span class="badge badge-type">${Utils.escapeHtml(profinet.station_name)}</span>` : '', profinetBody || renderEmptyState('No Profinet data', 'Use Actions \u2192 Protocols \u2192 Profinet Scan.'))}
    ${reconSection('opcua', 'OPC-UA Enumeration', !!(opcua && opcua.responded), opcua && opcua.endpoints ? `<span class="badge badge-type">${opcua.endpoints.length} endpoint(s)</span>` : '', opcuaBody || renderEmptyState('No OPC-UA data', 'Use Actions \u2192 Protocols \u2192 OPC-UA Scan.'))}
    ${reconSection('defcreds', 'Default Credential Test', !!(defCreds && defCreds.found), defCreds && defCreds.found ? `<span class="badge badge-type" style="background:rgba(239,68,68,.15);color:var(--severity-critical)">CREDENTIALS FOUND</span>` : '', defCredsBody || renderEmptyState('No credential test data', 'Use Actions \u2192 Threats \u2192 Test Default Creds.'))}
    ${reconSection('censys', 'Censys Intelligence', !!(censys && censys.ip), censys ? `<span class="badge badge-type">${(censys.services||[]).length} service(s)</span>` : '', censysBody || renderEmptyState('No Censys data', 'Use Actions \u2192 Intelligence \u2192 Fetch Censys Data.'))}
  `;
}

/* -------------------------------------------------------------------------
   Component: renderNERCCIPTab
   ------------------------------------------------------------------------- */
function renderNERCCIPTab(assetId, cipData) {
  const d = cipData || {};
  const standards = Array.isArray(d.cip_standards) ? d.cip_standards : [];
  const allStds = ['CIP-002','CIP-003','CIP-004','CIP-005','CIP-006','CIP-007','CIP-008','CIP-009','CIP-010','CIP-011','CIP-013','CIP-014'];
  return `
    <div style="padding:16px">
      <div style="font-size:13px;font-weight:600;color:var(--text-primary);margin-bottom:16px">NERC CIP Asset Classification</div>
      <form onsubmit="App.saveNERCCIP('${Utils.escapeHtml(assetId)}', event); return false;">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
          <div>
            <label style="font-size:12px;font-weight:600;color:var(--text-muted);display:block;margin-bottom:6px">BCS Asset (Bulk Electric System)</label>
            <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
              <input type="checkbox" name="bcs_asset" ${d.bcs_asset ? 'checked' : ''} style="width:16px;height:16px">
              <span style="font-size:13px">This is a BES cyber asset</span>
            </label>
          </div>
          <div>
            <label style="font-size:12px;font-weight:600;color:var(--text-muted);display:block;margin-bottom:6px">Impact Rating</label>
            <select name="impact_rating" style="width:100%;padding:7px 10px;background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--text-primary);font-size:13px">
              <option value="" ${!d.impact_rating ? 'selected' : ''}>Select...</option>
              ${['High','Medium','Low','Not BES'].map(v => `<option value="${v}" ${d.impact_rating === v ? 'selected' : ''}>${v}</option>`).join('')}
            </select>
          </div>
          <div>
            <label style="font-size:12px;font-weight:600;color:var(--text-muted);display:block;margin-bottom:6px">Asset Type</label>
            <select name="asset_type" style="width:100%;padding:7px 10px;background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--text-primary);font-size:13px">
              <option value="" ${!d.asset_type ? 'selected' : ''}>Select...</option>
              ${['Control Center','Substation','Generation','Transmission'].map(v => `<option value="${v}" ${d.asset_type === v ? 'selected' : ''}>${v}</option>`).join('')}
            </select>
          </div>
          <div>
            <label style="font-size:12px;font-weight:600;color:var(--text-muted);display:block;margin-bottom:6px">Network Zone (IEC 62443)</label>
            <select name="zone" style="width:100%;padding:7px 10px;background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--text-primary);font-size:13px">
              <option value="" ${!d.zone ? 'selected' : ''}>Select...</option>
              ${['Safety','Control','Operations','Enterprise'].map(v => `<option value="${v}" ${d.zone === v ? 'selected' : ''}>${v}</option>`).join('')}
            </select>
          </div>
          <div>
            <label style="font-size:12px;font-weight:600;color:var(--text-muted);display:block;margin-bottom:6px">ESP Name (Electronic Security Perimeter)</label>
            <input type="text" name="esp_name" value="${Utils.escapeHtml(d.esp_name || '')}" placeholder="e.g. ESP-Control-Zone-A" style="width:100%;padding:7px 10px;background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--text-primary);font-size:13px">
          </div>
          <div>
            <label style="font-size:12px;font-weight:600;color:var(--text-muted);display:block;margin-bottom:6px">Notes</label>
            <input type="text" name="notes" value="${Utils.escapeHtml(d.notes || '')}" placeholder="Additional notes" style="width:100%;padding:7px 10px;background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--text-primary);font-size:13px">
          </div>
        </div>
        <div style="margin-bottom:16px">
          <label style="font-size:12px;font-weight:600;color:var(--text-muted);display:block;margin-bottom:8px">Applicable CIP Standards</label>
          <div style="display:flex;flex-wrap:wrap;gap:10px">
            ${allStds.map(std => `
              <label style="display:flex;align-items:center;gap:6px;cursor:pointer">
                <input type="checkbox" name="cip_standards" value="${std}" ${standards.includes(std) ? 'checked' : ''} style="width:14px;height:14px">
                <span style="font-size:12px">${std}</span>
              </label>`).join('')}
          </div>
        </div>
        <button type="submit" class="btn btn-primary" style="padding:8px 24px">Save Classification</button>
      </form>
    </div>
  `;
}

/* -------------------------------------------------------------------------
   Component: renderCreateIdentityModal
   ------------------------------------------------------------------------- */
function renderCreateIdentityModal() {
  return `
    <div class="modal-overlay" id="modal-overlay" onclick="App._onModalOverlayClick(event)">
      <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">
        <div class="modal-header">
          <div class="modal-title" id="modal-title">New Identity</div>
          <button class="modal-close" onclick="App.hideModal()" aria-label="Close">&times;</button>
        </div>
        <div class="modal-body">
          <form id="create-identity-form" onsubmit="App.submitCreateIdentity(event)">
            <div class="form-row">
              <div class="form-group">
                <label class="form-label" for="fi-name">Identity Name <span class="required">*</span></label>
                <input class="form-input" type="text" id="fi-name" name="name" placeholder="e.g. Acme Power Grid" required autocomplete="off" />
              </div>
              <div class="form-group">
                <label class="form-label" for="fi-org">Organization Name <span class="required">*</span></label>
                <input class="form-input" type="text" id="fi-org" name="org_name" placeholder="e.g. Acme Corp" required autocomplete="off" />
              </div>
            </div>
            <div class="form-row">
              <div class="form-group">
                <label class="form-label" for="fi-sector">Sector</label>
                <select class="form-select" id="fi-sector" name="sector">
                  <option value="">Select sector...</option>
                  <option value="Power">Power</option>
                  <option value="Oil &amp; Gas">Oil &amp; Gas</option>
                  <option value="Water">Water</option>
                  <option value="Manufacturing">Manufacturing</option>
                  <option value="Transportation">Transportation</option>
                  <option value="Other">Other</option>
                </select>
              </div>
              <div class="form-group">
                <label class="form-label" for="fi-tags">Tags</label>
                <input class="form-input" type="text" id="fi-tags" name="tags" placeholder="ics, scada, critical (comma-separated)" autocomplete="off" />
                <div class="form-hint">Comma-separated list of tags</div>
              </div>
            </div>
            <div class="form-group">
              <label class="form-label" for="fi-notes">Notes</label>
              <textarea class="form-textarea" id="fi-notes" name="notes" placeholder="Optional description or context..." rows="3"></textarea>
            </div>
            <div class="divider"></div>
            <div class="section-title">Discovery Seeds</div>
            <div class="form-group">
              <label class="form-label" for="fi-domains">Known Domains</label>
              <textarea class="form-textarea" id="fi-domains" name="domains" placeholder="example.com&#10;scada.example.com&#10;(one per line)" rows="4"></textarea>
              <div class="form-hint">One domain per line</div>
            </div>
            <div class="form-group">
              <label class="form-label" for="fi-ips">Known IPs / CIDRs</label>
              <textarea class="form-textarea" id="fi-ips" name="ips" placeholder="192.168.1.0/24&#10;10.0.0.1&#10;(one per line)" rows="4"></textarea>
              <div class="form-hint">One IP or CIDR per line</div>
            </div>
          </form>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" onclick="App.hideModal()">Cancel</button>
          <button class="btn btn-primary" onclick="App.submitCreateIdentity()" id="create-identity-submit">
            Create Identity
          </button>
        </div>
      </div>
    </div>
  `;
}

/* -------------------------------------------------------------------------
   Component: renderCreateSeedModal
   ------------------------------------------------------------------------- */
function renderCreateSeedModal(identityId) {
  return `
    <div class="modal-overlay" id="modal-overlay" onclick="App._onModalOverlayClick(event)">
      <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">
        <div class="modal-header">
          <div class="modal-title" id="modal-title">Add Discovery Seed</div>
          <button class="modal-close" onclick="App.hideModal()" aria-label="Close">&times;</button>
        </div>
        <div class="modal-body">
          <form id="create-seed-form" onsubmit="App.submitCreateSeed(event, '${Utils.escapeHtml(identityId)}')">
            <div class="form-group">
              <label class="form-label" for="fs-type">Seed Type <span class="required">*</span></label>
              <select class="form-select" id="fs-type" name="type" required>
                <option value="">Select type...</option>
                <option value="ip">IP Address</option>
                <option value="cidr">CIDR Range</option>
                <option value="domain">Domain</option>
              </select>
            </div>
            <div class="form-group">
              <label class="form-label" for="fs-value">Value <span class="required">*</span></label>
              <input class="form-input" type="text" id="fs-value" name="value" placeholder="e.g. 192.168.1.1, 10.0.0.0/24, example.com" required autocomplete="off" />
            </div>
          </form>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" onclick="App.hideModal()">Cancel</button>
          <button class="btn btn-primary" onclick="App.submitCreateSeed(null, '${Utils.escapeHtml(identityId)}')">
            Add Seed
          </button>
        </div>
      </div>
    </div>
  `;
}

/* -------------------------------------------------------------------------
   Component: renderConfirmModal
   ------------------------------------------------------------------------- */
function renderConfirmModal(title, message, confirmLabel, confirmClass, onConfirmCall) {
  return `
    <div class="modal-overlay" id="modal-overlay" onclick="App._onModalOverlayClick(event)">
      <div class="modal" style="max-width:420px" role="dialog" aria-modal="true">
        <div class="modal-header">
          <div class="modal-title">${Utils.escapeHtml(title)}</div>
          <button class="modal-close" onclick="App.hideModal()" aria-label="Close">&times;</button>
        </div>
        <div class="modal-body">
          <p class="text-secondary">${Utils.escapeHtml(message)}</p>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" onclick="App.hideModal()">Cancel</button>
          <button class="btn ${Utils.escapeHtml(confirmClass)}" onclick="${Utils.escapeHtml(onConfirmCall)}">${Utils.escapeHtml(confirmLabel)}</button>
        </div>
      </div>
    </div>
  `;
}

/* -------------------------------------------------------------------------
   Component: renderPagination
   ------------------------------------------------------------------------- */
function renderPagination(page, totalPages, limit, total) {
  return `
    <div class="pagination">
      <div class="pagination-info">
        Showing ${Utils.formatNumber((page - 1) * limit + 1)}–${Utils.formatNumber(Math.min(page * limit, total))} of ${Utils.formatNumber(total)}
      </div>
      <div class="pagination-controls">
        <button class="btn btn-ghost btn-sm" ${page <= 1 ? 'disabled' : ''} onclick="App.changePage(${page - 1})">Prev</button>
        <span class="text-muted" style="padding:0 12px">Page ${page} of ${totalPages}</span>
        <button class="btn btn-ghost btn-sm" ${page >= totalPages ? 'disabled' : ''} onclick="App.changePage(${page + 1})">Next</button>
      </div>
    </div>
  `;
}

/* -------------------------------------------------------------------------
   Component: renderSkeletonTable
   ------------------------------------------------------------------------- */
function renderSkeletonTable(cols, rows = 5) {
  const headerCols = Array(cols).fill('<th></th>').join('');
  const bodyCols = Array(cols).fill('<td><div class="skeleton skeleton-text" style="width:80%"></div></td>').join('');
  const bodyRows = Array(rows).fill(`<tr>${bodyCols}</tr>`).join('');
  return `
    <div class="table-wrapper">
      <table class="data-table">
        <thead><tr>${headerCols}</tr></thead>
        <tbody>${bodyRows}</tbody>
      </table>
    </div>
  `;
}

/* -------------------------------------------------------------------------
   Main App Controller
   ------------------------------------------------------------------------- */
const App = {
  api: new API(),
  router: new Router(),
  _runPollTimer: null,
  _currentPage: null,
  _currentParams: {},
  _assetFilters: {},
  _assetView: 'graph',
  _findingFilters: {},
  _currentPage_num: 1,
  _currentIdentityId: null,

  // Debounced filter handlers (set up in init)
  debouncedFilterAssets: null,
  debouncedFilterFindings: null,

  init() {
    this.debouncedFilterAssets = Utils.debounce(() => this.filterAssets(), 300);
    this.debouncedFilterFindings = Utils.debounce(() => this.filterFindings(), 300);

    this.router
      .on('/', (p) => this.navigate('/identities'))
      .on('/identities', () => this.showPage('identities', {}))
      .on('/identities/:id', (p) => this.showPage('identity-detail', p))
      .on('/identities/:id/assets', (p) => this.showPage('identity-assets', p))
      .on('/identities/:id/findings', (p) => this.showPage('identity-findings', p))
      .on('/identities/:id/runs/:runId', (p) => this.showPage('run-detail', p))
      .on('/assets', () => this.showPage('assets-global', {}))
      .on('/assets/:assetId', (p) => this.showPage('asset-detail', p))
      .on('/findings', () => this.showPage('findings-global', {}))
      .on('/findings/:findingId', (p) => this.showPage('finding-detail', p))
      .on('*', () => this.showPage('not-found', {}));

    this.router.start();
  },

  navigate(path) {
    this.router.navigate(path);
  },

  async showPage(name, params) {
    this._stopRunPoll();
    this._currentPage = name;
    this._currentParams = params;

    const appEl = document.getElementById('app');
    if (!appEl) return;

    switch (name) {
      case 'identities':        return this._renderIdentitiesPage(params);
      case 'identity-detail':   return this._renderIdentityDetailPage(params);
      case 'identity-assets':   return this._renderIdentityAssetsPage(params);
      case 'identity-findings': return this._renderIdentityFindingsPage(params);
      case 'run-detail':        return this._renderRunDetailPage(params);
      case 'assets-global':     return this._renderAssetsGlobalPage(params);
      case 'asset-detail':      return this._renderAssetDetailPage(params);
      case 'findings-global':   return this._renderFindingsGlobalPage(params);
      case 'not-found':         return this._renderNotFound();
    }
  },

  _setAppHTML(navActive, sidebarActive, pageTitle, breadcrumbs, actionsHtml, contentHtml, ctx) {
    const appEl = document.getElementById('app');
    if (!appEl) return;

    const bcHtml = breadcrumbs && breadcrumbs.length
      ? `<div class="breadcrumb">
          ${breadcrumbs.map((b, i) =>
            i < breadcrumbs.length - 1
              ? `<a href="${Utils.escapeHtml(b.href)}">${Utils.escapeHtml(b.label)}</a><span class="breadcrumb-sep">/</span>`
              : `<span>${Utils.escapeHtml(b.label)}</span>`
          ).join('')}
        </div>`
      : '';

    appEl.innerHTML = `
      ${renderNav(navActive)}
      <div class="app-body">
        ${renderSidebar(sidebarActive, ctx || {})}
        <main class="main-content" id="main-content">
          <div class="page-header">
            <div class="page-header-left">
              ${bcHtml}
              <h1 class="page-title">${Utils.escapeHtml(pageTitle)}</h1>
            </div>
            <div class="page-header-actions">${actionsHtml || ''}</div>
          </div>
          <div id="page-content">${contentHtml}</div>
        </main>
      </div>
    `;

    // Bind sidebar toggle button.
    const sidebarToggleBtn = appEl.querySelector('#btn-sidebar-toggle');
    if (sidebarToggleBtn) {
      sidebarToggleBtn.addEventListener('click', () => this.toggleSidebar());
    }

    // Restore sidebar state from localStorage.
    try {
      if (localStorage.getItem('sidebar-hidden') === '1') {
        const body = appEl.querySelector('.app-body');
        if (body) body.classList.add('sidebar-hidden');
      }
    } catch(_) {}

    this._bindTabListeners();
    this._animateStatCards();
  },

  _bindTabListeners() {
    document.querySelectorAll('.tabs').forEach(tabContainer => {
      tabContainer.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          const tabId = btn.dataset.tab;
          tabContainer.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          // Find parent scope for tab content
          const parent = tabContainer.parentElement;
          parent.querySelectorAll('.tab-content').forEach(tc => {
            tc.classList.toggle('active', tc.id === `tab-${tabId}`);
          });
          // Lazy-load scan history when the History tab is clicked
          if (tabId === 'history') {
            const histEl = document.getElementById('scan-history-content');
            if (histEl && histEl.textContent.includes('Loading')) {
              const assetId = this._currentParams && this._currentParams.assetId;
              if (assetId) {
                this.api.getAssetHistory(assetId).then(history => {
                  if (!history || history.length === 0) {
                    histEl.innerHTML = '<div style="color:var(--text-muted);font-size:13px;padding:20px 0">No scan history yet. Run a port scan to start tracking changes.</div>';
                    return;
                  }
                  histEl.innerHTML = '<table style="width:100%;border-collapse:collapse;font-size:12px">' +
                    '<tr style="border-bottom:2px solid var(--border)"><th style="text-align:left;padding:6px 8px;color:var(--text-muted)">Date</th><th style="text-align:left;padding:6px 8px;color:var(--text-muted)">Open Ports</th><th style="text-align:right;padding:6px 8px;color:var(--text-muted)">Count</th></tr>' +
                    history.map((h, i) => {
                      let ports = [];
                      try { ports = typeof h.open_ports === 'string' ? JSON.parse(atob(h.open_ports)) : (h.open_ports || []); } catch(_) {}
                      const prev = history[i+1];
                      let prevPorts = [];
                      if (prev) { try { prevPorts = typeof prev.open_ports === 'string' ? JSON.parse(atob(prev.open_ports)) : (prev.open_ports || []); } catch(_) {} }
                      const newPorts = ports.filter(p => !prevPorts.includes(p));
                      return '<tr style="border-bottom:1px solid var(--border)">' +
                        '<td style="padding:6px 8px">' + new Date(h.scan_date).toLocaleString() + '</td>' +
                        '<td style="padding:6px 8px;font-family:monospace">' + ports.slice(0,20).map(p => '<span style="margin-right:4px;' + (newPorts.includes(p) ? 'color:var(--severity-critical);font-weight:700' : '') + '">' + p + '</span>').join('') + (ports.length > 20 ? '\u2026' : '') + '</td>' +
                        '<td style="padding:6px 8px;text-align:right">' + ports.length + '</td>' +
                      '</tr>';
                    }).join('') +
                    '</table>';
                }).catch(() => {
                  if (histEl) histEl.innerHTML = '<div style="color:var(--text-muted);font-size:13px">Failed to load scan history.</div>';
                });
              }
            }
          }
        });
      });
    });
  },

  _animateStatCards() {
    document.querySelectorAll('[data-stat-value]').forEach(el => {
      const raw = el.dataset.statValue;
      const num = parseInt(raw.replace(/,/g, ''), 10);
      if (!isNaN(num) && num > 0) {
        el.textContent = '0';
        Utils.animateNumber(el, num);
      }
    });
  },

  // -----------------------------------------------------------------------
  // Page: Identities List
  // -----------------------------------------------------------------------
  async _renderIdentitiesPage() {
    this._setAppHTML('identities', 'identities', 'Identities', [],
      `<button class="btn btn-primary" onclick="App.showCreateIdentityModal()">+ New Identity</button>`,
      renderSkeletonTable(7)
    );

    try {
      const identities = await this.api.listIdentities();
      const el = document.getElementById('page-content');
      if (el) {
        el.innerHTML = renderIdentitiesList(identities);
        this._animateStatCards();
      }
    } catch (err) {
      this._showError(err);
    }
  },

  // -----------------------------------------------------------------------
  // Page: Identity Detail
  // -----------------------------------------------------------------------
  async _renderIdentityDetailPage(params) {
    const { id } = params;
    this._currentIdentityId = id;

    this._setAppHTML('identities', 'identity-detail', 'Loading...', [
      { label: 'Identities', href: '#/identities' },
      { label: 'Identity Detail', href: '#' }
    ], '', renderSkeletonTable(3, 3), { identityId: id });

    try {
      const [identity, runs, seeds] = await Promise.all([
        this.api.getIdentity(id),
        this.api.listRuns(id),
        this.api.listSeeds(id),
      ]);

      const titleEl = document.querySelector('.page-title');
      if (titleEl) titleEl.textContent = identity.name;

      const bc = document.querySelector('.breadcrumb');
      if (bc) bc.innerHTML = `
        <a href="#/identities">Identities</a>
        <span class="breadcrumb-sep">/</span>
        <span>${Utils.escapeHtml(identity.name)}</span>
      `;

      const el = document.getElementById('page-content');
      if (el) {
        el.innerHTML = renderIdentityDetail(identity, runs, seeds);
        this._bindTabListeners();
        this._animateStatCards();
      }

      // Update sidebar context
      const sidebar = document.querySelector('.sidebar');
      if (sidebar) {
        sidebar.outerHTML = renderSidebar('identity-detail', { identityId: id, identity });
      }
    } catch (err) {
      this._showError(err);
    }
  },

  // -----------------------------------------------------------------------
  // Page: Identity Assets
  // -----------------------------------------------------------------------
  async _renderIdentityAssetsPage(params) {
    const { id } = params;
    this._currentIdentityId = id;
    this._assetFilters = {};
    this._assetView = 'graph';

    let identity = null;
    try {
      identity = await this.api.getIdentity(id);
    } catch (_) {}

    this._setAppHTML('identities', 'identity-assets',
      identity ? `${identity.name} — Assets` : 'Assets',
      [
        { label: 'Identities', href: '#/identities' },
        { label: identity ? identity.name : id, href: `#/identities/${id}` },
        { label: 'Assets', href: '#' }
      ], '', renderSkeletonTable(8),
      { identityId: id, identity }
    );

    await this._loadIdentityAssets(id);
  },

  async _loadIdentityAssets(id) {
    const filters = this._assetFilters;
    const view = this._assetView || 'table';
    const el = document.getElementById('page-content');
    if (!el) return;
    try {
      const params = { ...filters };
      if (view === 'graph') { params.limit = 1000; params.graph = 1; }
      const response = await this.api.listAssets(id, params);
      el.innerHTML = renderAssetsPage(response, id, filters, view);
      if (view === 'graph') {
        const assets        = (response && response.assets)         || [];
        const findingCounts = (response && response.finding_counts) || {};
        const dnsLinks      = (response && response.dns_links)      || [];
        setTimeout(() => this._initAssetGraph(assets, findingCounts, dnsLinks, id), 50);
      }
    } catch (err) {
      el.innerHTML = `<div class="empty-state"><div class="empty-state-title text-critical">Error loading assets</div><div class="empty-state-desc">${Utils.escapeHtml(err.message)}</div></div>`;
    }
  },

  switchAssetView(view) {
    this._assetView = view;
    const id = this._currentIdentityId || this._currentParams.id;
    if (id) this._loadIdentityAssets(id);
  },

  filterAssets() {
    const typeEl = document.getElementById('filter-type');
    const countryEl = document.getElementById('filter-country');
    const asnEl = document.getElementById('filter-asn');
    this._assetFilters = {
      type: typeEl ? typeEl.value : '',
      country: countryEl ? countryEl.value : '',
      asn: asnEl ? asnEl.value : '',
    };
    const id = this._currentIdentityId || this._currentParams.id;
    if (id) this._loadIdentityAssets(id);
  },

  clearAssetFilters() {
    this._assetFilters = {};
    const id = this._currentIdentityId || this._currentParams.id;
    if (id) this._loadIdentityAssets(id);
  },

  // -----------------------------------------------------------------------
  // Page: Identity Findings
  // -----------------------------------------------------------------------
  async _renderIdentityFindingsPage(params) {
    const { id } = params;
    this._currentIdentityId = id;
    this._findingFilters = {};

    let identity = null;
    try { identity = await this.api.getIdentity(id); } catch (_) {}

    this._setAppHTML('identities', 'identity-findings',
      identity ? `${identity.name} — Findings` : 'Findings',
      [
        { label: 'Identities', href: '#/identities' },
        { label: identity ? identity.name : id, href: `#/identities/${id}` },
        { label: 'Findings', href: '#' }
      ], '', renderSkeletonTable(7),
      { identityId: id, identity }
    );

    await this._loadIdentityFindings(id);
  },

  async _loadIdentityFindings(id) {
    const filters = this._findingFilters;
    const el = document.getElementById('page-content');
    if (!el) return;
    try {
      const findings = await this.api.listFindings(id, filters);
      const list = Array.isArray(findings) ? findings : (findings && findings.findings) || [];
      el.innerHTML = renderFindingsPage(list, filters, id);
    } catch (err) {
      el.innerHTML = `<div class="empty-state"><div class="empty-state-title text-critical">Error loading findings</div><div class="empty-state-desc">${Utils.escapeHtml(err.message)}</div></div>`;
    }
  },

  filterFindings() {
    const sevEl = document.getElementById('filter-severity');
    const protoEl = document.getElementById('filter-protocol');
    const vendorEl = document.getElementById('filter-vendor');
    this._findingFilters = {
      severity: sevEl ? sevEl.value : '',
      protocol: protoEl ? protoEl.value : '',
      vendor: vendorEl ? vendorEl.value : '',
    };
    const id = this._currentIdentityId || this._currentParams.id;
    if (id) this._loadIdentityFindings(id);
  },

  clearFindingFilters() {
    this._findingFilters = {};
    const id = this._currentIdentityId || this._currentParams.id;
    if (id) this._loadIdentityFindings(id);
  },

  // -----------------------------------------------------------------------
  // Page: Run Detail
  // -----------------------------------------------------------------------
  async _renderRunDetailPage(params) {
    const { id, runId } = params;

    let identity = null;
    try { identity = await this.api.getIdentity(id); } catch (_) {}

    this._setAppHTML('identities', 'identity-detail',
      'Run Detail',
      [
        { label: 'Identities', href: '#/identities' },
        { label: identity ? identity.name : id, href: `#/identities/${id}` },
        { label: 'Run', href: '#' }
      ], '', `<div class="flex-center" style="height:200px"><div class="loading-spinner"></div></div>`,
      { identityId: id, identity }
    );

    await this._loadRunDetail(id, runId);
  },

  async _loadRunDetail(identityId, runId) {
    const el = document.getElementById('page-content');
    if (!el) return;

    try {
      const data = await this.api.getRun(runId);
      const { run, jobs } = data;

      el.innerHTML = renderRunPage(run, jobs, identityId);
      this._animateStatCards();

      const isActive = run.status === 'running' || run.status === 'pending';
      if (isActive) {
        this._startRunPoll(identityId, runId);
      }
    } catch (err) {
      el.innerHTML = `<div class="empty-state"><div class="empty-state-title text-critical">Error loading run</div><div class="empty-state-desc">${Utils.escapeHtml(err.message)}</div></div>`;
    }
  },

  _startRunPoll(identityId, runId) {
    this._stopRunPoll();
    this._runPollTimer = setInterval(async () => {
      if (this._currentPage !== 'run-detail') {
        this._stopRunPoll();
        return;
      }
      try {
        const data = await this.api.getRun(runId);
        const { run, jobs } = data;
        const el = document.getElementById('page-content');
        if (el) {
          el.innerHTML = renderRunPage(run, jobs, identityId);
          this._animateStatCards();
        }
        if (run.status === 'completed' || run.status === 'failed') {
          this._stopRunPoll();
        }
      } catch (_) {}
    }, 5000);
  },

  _stopRunPoll() {
    if (this._runPollTimer) {
      clearInterval(this._runPollTimer);
      this._runPollTimer = null;
    }
  },

  // -----------------------------------------------------------------------
  // Page: Global Assets
  // -----------------------------------------------------------------------
  async _renderAssetsGlobalPage() {
    this._setAppHTML('assets', 'assets',
      'All Assets', [],
      '',
      renderEmptyState('Select an identity', 'Navigate to an identity to view its assets.'),
    );
  },

  // -----------------------------------------------------------------------
  // Page: Asset Detail
  // -----------------------------------------------------------------------
  async _renderAssetDetailPage(params) {
    const { assetId } = params;

    this._setAppHTML('assets', 'assets',
      'Asset Detail',
      [{ label: 'Asset', href: '#' }],
      '', `<div class="flex-center" style="height:200px"><div class="loading-spinner"></div></div>`
    );

    try {
      const [asset, scanResults, findings, enrichment] = await Promise.all([
        this.api.getAsset(assetId),
        this.api.getAssetScanResults(assetId).catch(() => []),
        this.api.getAssetFindings(assetId).catch(() => []),
        this.api.getAssetEnrichment(assetId).catch(() => []),
      ]);

      const titleEl = document.querySelector('.page-title');
      if (titleEl) titleEl.textContent = asset.value;

      const isDomainType = asset.type === 'domain' || asset.type === 'subdomain';
      const isIPType = asset.type === 'ip';

      const [dnsRecords, subdomains, tlsResult, snmpRec, otProbeRec, bgpRec, ipWhoisRec, cveRec, vulnNotesData, iec61850Rec, historianRec, hmiRec, icscertRec, nercCipData, iec104Rec, modbusDeepRec, dnp3DeepRec, iccpRec, enipDeepRec, profinetRec, opcuaRec, defaultCredsRec, censysRec] = await Promise.all([
        this.api.getAssetDNSRecords(assetId).catch(() => []),
        isDomainType ? this.api.getAssetSubdomains(assetId).catch(() => []) : Promise.resolve([]),
        isDomainType ? this.api.getTLSScan(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getSNMP(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getOTProbe(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getBGP(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getIPWhois(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getCVECorrelate(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getVulnNotes(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getIEC61850(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getHistorian(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getHMI(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getICSCert(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getNERCCIP(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getIEC104(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getModbusDeep(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getDNP3Deep(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getICCP(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getEtherNetIPDeep(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getProfinet(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getOPCUA(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getDefaultCreds(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getCensys(assetId).catch(() => null) : Promise.resolve(null),
      ]);

      const el = document.getElementById('page-content');
      if (el) {
        el.innerHTML = renderAssetDetail(asset, scanResults, dnsRecords, findings, enrichment, subdomains, tlsResult, snmpRec, otProbeRec, bgpRec, ipWhoisRec, cveRec, vulnNotesData, iec61850Rec, historianRec, hmiRec, icscertRec, nercCipData, iec104Rec, modbusDeepRec, dnp3DeepRec, iccpRec, enipDeepRec, profinetRec, opcuaRec, defaultCredsRec, censysRec);
        this._bindTabListeners();
        this._animateStatCards();
      }
    } catch (err) {
      this._showError(err);
    }
  },

  async navigateToAssetByValue(identityId, value) {
    try {
      const asset = await this.api.lookupAssetByValue(identityId, value);
      this.navigate(`/assets/${asset.id}`);
    } catch (err) {
      this.showToast('Asset not found for IP: ' + value, 'error');
    }
  },

  toggleSidebar() {
    const body = document.querySelector('.app-body');
    if (!body) return;
    const hidden = body.classList.toggle('sidebar-hidden');
    try { localStorage.setItem('sidebar-hidden', hidden ? '1' : '0'); } catch(_) {}
  },

  showActionsMenu(assetId) {
    const menu = document.getElementById('actions-menu');
    const btn  = document.getElementById('btn-actions');
    if (!menu || !btn) return;
    const isVisible = menu.style.display !== 'none';
    if (isVisible) { menu.style.display = 'none'; return; }

    // Position using fixed coords so the menu escapes any overflow:hidden parent.
    const rect = btn.getBoundingClientRect();
    menu.style.position = 'fixed';
    menu.style.top  = (rect.bottom + 4) + 'px';
    menu.style.left = 'auto';
    menu.style.right = (window.innerWidth - rect.right) + 'px';
    menu.style.display = 'block';

    const close = (e) => {
      if (!menu.contains(e.target) && e.target.id !== 'btn-actions') {
        menu.style.display = 'none';
        document.removeEventListener('click', close);
      }
    };
    setTimeout(() => document.addEventListener('click', close), 0);
  },

  async triggerPortScan(assetId, profile) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    const btn = document.getElementById('btn-actions');
    if (btn) { btn.disabled = true; btn.textContent = `Scanning (${profile})...`; }

    this.showToast(`Port scan started — ${profile} profile`, 'info');
    try {
      const result = await this.api.portScanAsset(assetId, profile);
      const summary = result.summary || {};
      this.showToast(
        `Scan complete — ${result.scan_results ? result.scan_results.length : 0} open port(s) found`,
        'success'
      );
      const el = document.getElementById('page-content');
      if (el) {
        const asset = result.asset;
        const isDomainType = asset.type === 'domain' || asset.type === 'subdomain';
        const [dnsRecords, enrichment, subdomains] = await Promise.all([
          this.api.getAssetDNSRecords(assetId).catch(() => []),
          this.api.getAssetEnrichment(assetId).catch(() => []),
          isDomainType ? this.api.getAssetSubdomains(assetId).catch(() => []) : Promise.resolve([]),
        ]);
        el.innerHTML = renderAssetDetail(asset, result.scan_results || [], dnsRecords, result.findings || [], enrichment, subdomains);
        this._bindTabListeners();
        this._animateStatCards();
      }
    } catch (err) {
      this.showToast('Port scan failed: ' + (err.message || 'nmap error'), 'error');
      if (btn) { btn.disabled = false; btn.textContent = 'Actions \u25BC'; }
    }
  },

  async triggerDeepScan(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    const btn = document.getElementById('btn-actions');
    if (btn) { btn.disabled = true; btn.textContent = 'Running Shodan...'; }
    try {
      const result = await this.api.deepScanAsset(assetId);
      const hasData = !!result.enrichment;
      this.showToast(hasData ? 'Shodan lookup complete — data updated' : 'Shodan has no data for this IP', hasData ? 'success' : 'info');
      const el = document.getElementById('page-content');
      if (el) {
        const [dnsRecords, subdomains] = await Promise.all([
          this.api.getAssetDNSRecords(assetId).catch(() => []),
          Promise.resolve([]),
        ]);
        el.innerHTML = renderAssetDetail(
          result.asset,
          result.scan_results || [],
          dnsRecords,
          result.findings || [],
          result.enrichment ? [result.enrichment] : [],
          subdomains
        );
        this._bindTabListeners();
        this._animateStatCards();
        if (hasData) {
          const shodanTab = document.querySelector('[data-tab="shodan"]');
          if (shodanTab) shodanTab.click();
        }
      }
    } catch (err) {
      this.showToast('Deep scan failed: ' + (err.message || 'Check Shodan API key in config.yaml'), 'error');
      if (btn) { btn.disabled = false; btn.textContent = 'Actions \u25BC'; }
    }
  },

  async triggerEnumerate(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    const btn = document.getElementById('btn-actions');
    if (btn) { btn.disabled = true; btn.textContent = 'Enumerating...'; }

    this.showToast('Subdomain enumeration started — this may take a minute', 'info');
    try {
      const result = await this.api.enumerateAsset(assetId);
      const count = result.count || 0;
      this.showToast(`Enumeration complete — ${count} subdomain${count !== 1 ? 's' : ''} found`, 'success');

      // Reload subdomains tab with fresh data.
      const el = document.getElementById('page-content');
      if (el) {
        const [asset, scanResults, dnsRecords, findings, enrichment, subdomains] = await Promise.all([
          this.api.getAsset(assetId),
          this.api.getAssetScanResults(assetId).catch(() => []),
          this.api.getAssetDNSRecords(assetId).catch(() => []),
          this.api.getAssetFindings(assetId).catch(() => []),
          this.api.getAssetEnrichment(assetId).catch(() => []),
          this.api.getAssetSubdomains(assetId).catch(() => []),
        ]);
        el.innerHTML = renderAssetDetail(asset, scanResults, dnsRecords, findings, enrichment, subdomains);
        this._bindTabListeners();
        this._animateStatCards();
        // Switch to subdomains tab to show results.
        const subsTab = document.querySelector('[data-tab="subdomains"]');
        if (subsTab) subsTab.click();
      }
    } catch (err) {
      this.showToast('Enumeration failed: ' + (err.message || 'unknown error'), 'error');
      if (btn) { btn.disabled = false; btn.textContent = 'Actions \u25BC'; }
    }
  },

  async triggerTLSScan(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    const btn = document.getElementById('btn-actions');
    if (btn) { btn.disabled = true; btn.textContent = 'Scanning TLS...'; }

    this.showToast('TLS scan started…', 'info');
    try {
      const tlsResult = await this.api.tlsScanAsset(assetId);
      this.showToast(`TLS scan complete — Grade: ${tlsResult.grade || '?'}`, 'success');

      const el = document.getElementById('page-content');
      if (el) {
        const [asset, scanResults, dnsRecords, findings, enrichment, subdomains] = await Promise.all([
          this.api.getAsset(assetId),
          this.api.getAssetScanResults(assetId).catch(() => []),
          this.api.getAssetDNSRecords(assetId).catch(() => []),
          this.api.getAssetFindings(assetId).catch(() => []),
          this.api.getAssetEnrichment(assetId).catch(() => []),
          this.api.getAssetSubdomains(assetId).catch(() => []),
        ]);
        el.innerHTML = renderAssetDetail(asset, scanResults, dnsRecords, findings, enrichment, subdomains, tlsResult);
        this._bindTabListeners();
        this._animateStatCards();
        const tlsTab = document.querySelector('[data-tab="tls"]');
        if (tlsTab) tlsTab.click();
      }
    } catch (err) {
      this.showToast('TLS scan failed: ' + (err.message || 'unknown error'), 'error');
      if (btn) { btn.disabled = false; btn.textContent = 'Actions \u25BC'; }
    }
  },

  async triggerSecurityTrails(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    const btn = document.getElementById('btn-actions');
    if (btn) { btn.disabled = true; btn.textContent = 'Fetching...'; }

    this.showToast('SecurityTrails lookup started\u2026', 'info');
    try {
      const result = await this.api.securityTrailsEnrich(assetId);
      if (result && result.message) {
        this.showToast(result.message, 'info');
        if (btn) { btn.disabled = false; btn.textContent = 'Actions \u25BC'; }
        return;
      }
      this.showToast('SecurityTrails lookup complete', 'success');

      const el = document.getElementById('page-content');
      if (el) {
        const [asset, scanResults, dnsRecords, findings, enrichment, subdomains, tlsResult] = await Promise.all([
          this.api.getAsset(assetId),
          this.api.getAssetScanResults(assetId).catch(() => []),
          this.api.getAssetDNSRecords(assetId).catch(() => []),
          this.api.getAssetFindings(assetId).catch(() => []),
          this.api.getAssetEnrichment(assetId).catch(() => []),
          this.api.getAssetSubdomains(assetId).catch(() => []),
          this.api.getTLSScan(assetId).catch(() => null),
        ]);
        el.innerHTML = renderAssetDetail(asset, scanResults, dnsRecords, findings, enrichment, subdomains, tlsResult);
        this._bindTabListeners();
        this._animateStatCards();
        const stTab = document.querySelector('[data-tab="st"]');
        if (stTab) stTab.click();
      }
    } catch (err) {
      this.showToast('SecurityTrails lookup failed: ' + (err.message || 'unknown error'), 'error');
      if (btn) { btn.disabled = false; btn.textContent = 'Actions \u25BC'; }
    }
  },

  async triggerCrtSh(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    const btn = document.getElementById('btn-actions');
    if (btn) { btn.disabled = true; btn.textContent = 'Fetching crt.sh\u2026'; }

    this.showToast('crt.sh lookup started\u2026', 'info');
    try {
      const result = await this.api.crtShLookup(assetId);
      if (result && result.message) {
        this.showToast(result.message, 'info');
        if (btn) { btn.disabled = false; btn.textContent = 'Actions \u25BC'; }
        return;
      }
      this.showToast(`crt.sh lookup complete \u2014 ${result.count || 0} name(s) found`, 'success');

      const el = document.getElementById('page-content');
      if (el) {
        const [asset, scanResults, dnsRecords, findings, enrichment, subdomains, tlsResult] = await Promise.all([
          this.api.getAsset(assetId),
          this.api.getAssetScanResults(assetId).catch(() => []),
          this.api.getAssetDNSRecords(assetId).catch(() => []),
          this.api.getAssetFindings(assetId).catch(() => []),
          this.api.getAssetEnrichment(assetId).catch(() => []),
          this.api.getAssetSubdomains(assetId).catch(() => []),
          this.api.getTLSScan(assetId).catch(() => null),
        ]);
        el.innerHTML = renderAssetDetail(asset, scanResults, dnsRecords, findings, enrichment, subdomains, tlsResult);
        this._bindTabListeners();
        this._animateStatCards();
        const crtshTab = document.querySelector('[data-tab="crtsh"]');
        if (crtshTab) crtshTab.click();
      }
    } catch (err) {
      this.showToast('crt.sh lookup failed: ' + (err.message || 'unknown error'), 'error');
      if (btn) { btn.disabled = false; btn.textContent = 'Actions \u25BC'; }
    }
  },

  async triggerHTTPProbe(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    const btn = document.getElementById('btn-actions');
    if (btn) { btn.disabled = true; btn.textContent = 'Probing HTTP\u2026'; }

    this.showToast('HTTP probe started\u2026', 'info');
    try {
      const result = await this.api.httpProbeAsset(assetId);
      const probeCount = (result.result && result.result.probes) ? result.result.probes.filter(p => p.status_code > 0).length : 0;
      this.showToast(`HTTP probe complete \u2014 ${probeCount} service(s) found`, 'success');

      const el = document.getElementById('page-content');
      if (el) {
        const [asset, scanResults, dnsRecords, findings, enrichment, subdomains, tlsResult] = await Promise.all([
          this.api.getAsset(assetId),
          this.api.getAssetScanResults(assetId).catch(() => []),
          this.api.getAssetDNSRecords(assetId).catch(() => []),
          this.api.getAssetFindings(assetId).catch(() => []),
          this.api.getAssetEnrichment(assetId).catch(() => []),
          this.api.getAssetSubdomains(assetId).catch(() => []),
          this.api.getTLSScan(assetId).catch(() => null),
        ]);
        el.innerHTML = renderAssetDetail(asset, scanResults, dnsRecords, findings, enrichment, subdomains, tlsResult);
        this._bindTabListeners();
        this._animateStatCards();
        // For IP assets the probe lives inside the Recon tab; for domains it's its own tab.
        const probeTab = document.querySelector('[data-tab="recon"]') || document.querySelector('[data-tab="http-probe"]');
        if (probeTab) probeTab.click();
      }
    } catch (err) {
      this.showToast('HTTP probe failed: ' + (err.message || 'unknown error'), 'error');
      if (btn) { btn.disabled = false; btn.textContent = 'Actions \u25BC'; }
    }
  },

  async triggerSNMPEnum(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    const btn = document.getElementById('btn-actions');
    if (btn) { btn.disabled = true; btn.textContent = 'Running SNMP\u2026'; }
    this.showToast('Running SNMP enumeration\u2026', 'info');
    try {
      const result = await this.api.snmpEnum(assetId);
      if (result && result.message) {
        this.showToast(result.message, 'info');
        if (btn) { btn.disabled = false; btn.textContent = 'Actions \u25BC'; }
        return;
      }
      this.showToast('SNMP enumeration complete', 'success');
      await this.showAsset(assetId);
    } catch(e) {
      this.showToast('SNMP enum failed: ' + (e.message || 'unknown error'), 'error');
      if (btn) { btn.disabled = false; btn.textContent = 'Actions \u25BC'; }
    }
  },

  async triggerOTProbe(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    const btn = document.getElementById('btn-actions');
    if (btn) { btn.disabled = true; btn.textContent = 'Probing OT\u2026'; }
    this.showToast('Running OT protocol probe\u2026', 'info');
    try {
      const result = await this.api.otProbe(assetId);
      const count = (result.findings || []).length;
      this.showToast(`OT probe complete \u2014 ${count} finding(s) generated`, count > 0 ? 'success' : 'info');
      await this.showAsset(assetId);
    } catch(e) {
      this.showToast('OT probe failed: ' + (e.message || 'unknown error'), 'error');
      if (btn) { btn.disabled = false; btn.textContent = 'Actions \u25BC'; }
    }
  },

  async triggerBGPLookup(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    const btn = document.getElementById('btn-actions');
    if (btn) { btn.disabled = true; btn.textContent = 'BGP Lookup\u2026'; }
    this.showToast('Running BGP lookup\u2026', 'info');
    try {
      const result = await this.api.bgpLookup(assetId);
      if (result && result.message) {
        this.showToast(result.message, 'info');
        if (btn) { btn.disabled = false; btn.textContent = 'Actions \u25BC'; }
        return;
      }
      this.showToast('BGP lookup complete', 'success');
      await this.showAsset(assetId);
    } catch(e) {
      this.showToast('BGP lookup failed: ' + (e.message || 'unknown error'), 'error');
      if (btn) { btn.disabled = false; btn.textContent = 'Actions \u25BC'; }
    }
  },

  async triggerIPWhois(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    const btn = document.getElementById('btn-actions');
    if (btn) { btn.disabled = true; btn.textContent = 'WHOIS\u2026'; }
    this.showToast('Running IP WHOIS lookup\u2026', 'info');
    try {
      const result = await this.api.ipWhoisLookup(assetId);
      if (result && result.message) {
        this.showToast(result.message, 'info');
        if (btn) { btn.disabled = false; btn.textContent = 'Actions \u25BC'; }
        return;
      }
      this.showToast('IP WHOIS lookup complete', 'success');
      await this.showAsset(assetId);
    } catch(e) {
      this.showToast('IP WHOIS failed: ' + (e.message || 'unknown error'), 'error');
      if (btn) { btn.disabled = false; btn.textContent = 'Actions \u25BC'; }
    }
  },

  async triggerCVECorrelate(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    const btn = document.getElementById('btn-actions');
    if (btn) { btn.disabled = true; btn.textContent = 'CVE Correlate\u2026'; }
    this.showToast('Running CVE correlation (this may take a minute)\u2026', 'info');
    try {
      const result = await this.api.cveCorrelate(assetId);
      const count = (result.findings || []).length;
      this.showToast(`CVE correlation complete \u2014 ${count} finding(s) generated`, 'success');
      await this.showAsset(assetId);
    } catch(e) {
      this.showToast('CVE correlation failed: ' + (e.message || 'unknown error'), 'error');
      if (btn) { btn.disabled = false; btn.textContent = 'Actions \u25BC'; }
    }
  },

  async triggerIEC61850Scan(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    const btn = document.getElementById('btn-actions');
    if (btn) { btn.disabled = true; btn.textContent = 'IEC 61850 Scan…'; }
    this.showToast('Running IEC 61850 MMS scan…', 'info');
    try {
      const result = await this.api.iec61850Scan(assetId);
      if (result && result.message) {
        this.showToast(result.message, 'info');
        if (btn) { btn.disabled = false; btn.textContent = 'Actions ▼'; }
        return;
      }
      const count = (result.findings || []).length;
      this.showToast(`IEC 61850 scan complete — ${count} finding(s) generated`, count > 0 ? 'success' : 'info');
      await this.showAsset(assetId);
    } catch(e) {
      this.showToast('IEC 61850 scan failed: ' + (e.message || 'unknown error'), 'error');
      if (btn) { btn.disabled = false; btn.textContent = 'Actions ▼'; }
    }
  },

  async triggerHistorianDetect(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    const btn = document.getElementById('btn-actions');
    if (btn) { btn.disabled = true; btn.textContent = 'Historian Detect…'; }
    this.showToast('Detecting OT historian services…', 'info');
    try {
      const result = await this.api.historianDetect(assetId);
      if (result && result.message) {
        this.showToast(result.message, 'info');
        if (btn) { btn.disabled = false; btn.textContent = 'Actions ▼'; }
        return;
      }
      const count = (result.findings || []).length;
      this.showToast(`Historian detection complete — ${count} finding(s) generated`, count > 0 ? 'success' : 'info');
      await this.showAsset(assetId);
    } catch(e) {
      this.showToast('Historian detection failed: ' + (e.message || 'unknown error'), 'error');
      if (btn) { btn.disabled = false; btn.textContent = 'Actions ▼'; }
    }
  },

  async triggerHMIFingerprint(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    const btn = document.getElementById('btn-actions');
    if (btn) { btn.disabled = true; btn.textContent = 'HMI Fingerprint…'; }
    this.showToast('Fingerprinting SCADA HMI software…', 'info');
    try {
      const result = await this.api.hmiFingerprint(assetId);
      if (result && result.message) {
        this.showToast(result.message, 'info');
        if (btn) { btn.disabled = false; btn.textContent = 'Actions ▼'; }
        return;
      }
      const count = (result.findings || []).length;
      this.showToast(`HMI fingerprinting complete — ${count} finding(s) generated`, count > 0 ? 'success' : 'info');
      await this.showAsset(assetId);
    } catch(e) {
      this.showToast('HMI fingerprinting failed: ' + (e.message || 'unknown error'), 'error');
      if (btn) { btn.disabled = false; btn.textContent = 'Actions ▼'; }
    }
  },

  async triggerICSCertSearch(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    const btn = document.getElementById('btn-actions');
    if (btn) { btn.disabled = true; btn.textContent = 'ICS-CERT Search…'; }
    this.showToast('Searching CISA ICS advisories…', 'info');
    try {
      const result = await this.api.icsCertSearch(assetId);
      if (result && result.message) {
        this.showToast(result.message, 'info');
        if (btn) { btn.disabled = false; btn.textContent = 'Actions ▼'; }
        return;
      }
      const total = (result.result && result.result.total) || 0;
      this.showToast(`ICS-CERT search complete — ${total} advisory(ies) found`, total > 0 ? 'success' : 'info');
      await this.showAsset(assetId);
    } catch(e) {
      this.showToast('ICS-CERT search failed: ' + (e.message || 'unknown error'), 'error');
      if (btn) { btn.disabled = false; btn.textContent = 'Actions ▼'; }
    }
  },

  async triggerIEC104Scan(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    this.showToast('Scanning for IEC 60870-5-104 service on port 2404\u2026', 'info');
    try {
      const result = await this.api.iec104Scan(assetId);
      if (result && result.message) { this.showToast(result.message, 'info'); return; }
      const count = (result.findings || []).length;
      this.showToast(`IEC 104 scan complete \u2014 ${count} finding(s)`, count > 0 ? 'success' : 'info');
      await this.showAsset(assetId);
    } catch(e) { this.showToast('IEC 104 scan failed: ' + (e.message || 'unknown error'), 'error'); }
  },

  async triggerModbusDeepScan(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    this.showToast('Reading Modbus registers FC1\u2013FC4\u2026', 'info');
    try {
      const result = await this.api.modbusDeepScan(assetId);
      if (result && result.message) { this.showToast(result.message, 'info'); return; }
      const count = (result.findings || []).length;
      this.showToast(`Modbus deep scan complete \u2014 ${count} finding(s)`, count > 0 ? 'success' : 'info');
      await this.showAsset(assetId);
    } catch(e) { this.showToast('Modbus deep scan failed: ' + (e.message || 'unknown error'), 'error'); }
  },

  async triggerDNP3DeepScan(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    this.showToast('Reading DNP3 Class 0 data points\u2026', 'info');
    try {
      const result = await this.api.dnp3DeepScan(assetId);
      if (result && result.message) { this.showToast(result.message, 'info'); return; }
      const count = (result.findings || []).length;
      this.showToast(`DNP3 deep scan complete \u2014 ${count} finding(s)`, count > 0 ? 'success' : 'info');
      await this.showAsset(assetId);
    } catch(e) { this.showToast('DNP3 deep scan failed: ' + (e.message || 'unknown error'), 'error'); }
  },

  async triggerICCPScan(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    this.showToast('Probing for ICCP/TASE.2 on port 102\u2026', 'info');
    try {
      const result = await this.api.iccpScan(assetId);
      if (result && result.message) { this.showToast(result.message, 'info'); return; }
      const count = (result.findings || []).length;
      this.showToast(`ICCP scan complete \u2014 ${count} finding(s)`, count > 0 ? 'success' : 'info');
      await this.showAsset(assetId);
    } catch(e) { this.showToast('ICCP scan failed: ' + (e.message || 'unknown error'), 'error'); }
  },

  async triggerEtherNetIPDeepScan(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    this.showToast('Enumerating EtherNet/IP CIP tags\u2026', 'info');
    try {
      const result = await this.api.etherNetIPDeepScan(assetId);
      if (result && result.message) { this.showToast(result.message, 'info'); return; }
      const count = (result.findings || []).length;
      this.showToast(`EtherNet/IP deep scan complete \u2014 ${count} finding(s)`, count > 0 ? 'success' : 'info');
      await this.showAsset(assetId);
    } catch(e) { this.showToast('EtherNet/IP deep scan failed: ' + (e.message || 'unknown error'), 'error'); }
  },

  async triggerProfinetScan(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    this.showToast('Sending Profinet DCP Identify request\u2026', 'info');
    try {
      const result = await this.api.profinetScan(assetId);
      if (result && result.message) { this.showToast(result.message, 'info'); return; }
      const count = (result.findings || []).length;
      this.showToast(`Profinet scan complete \u2014 ${count} finding(s)`, count > 0 ? 'success' : 'info');
      await this.showAsset(assetId);
    } catch(e) { this.showToast('Profinet scan failed: ' + (e.message || 'unknown error'), 'error'); }
  },

  async triggerOPCUAScan(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    this.showToast('Enumerating OPC-UA endpoints on port 4840\u2026', 'info');
    try {
      const result = await this.api.opcuaScan(assetId);
      if (result && result.message) { this.showToast(result.message, 'info'); return; }
      const count = (result.findings || []).length;
      this.showToast(`OPC-UA scan complete \u2014 ${count} finding(s)`, count > 0 ? 'success' : 'info');
      await this.showAsset(assetId);
    } catch(e) { this.showToast('OPC-UA scan failed: ' + (e.message || 'unknown error'), 'error'); }
  },

  async triggerTestDefaultCreds(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    this.showToast('Testing default credentials on HMI/SCADA web interfaces\u2026', 'info');
    try {
      const result = await this.api.testDefaultCreds(assetId);
      if (result && result.message) { this.showToast(result.message, 'info'); return; }
      const count = (result.findings || []).length;
      this.showToast(count > 0 ? `\u26a0 Default credentials found! ${count} finding(s) generated` : 'No default credentials accepted', count > 0 ? 'error' : 'info');
      await this.showAsset(assetId);
    } catch(e) { this.showToast('Credential test failed: ' + (e.message || 'unknown error'), 'error'); }
  },

  async triggerFetchCensys(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    this.showToast('Fetching Censys host intelligence\u2026', 'info');
    try {
      const result = await this.api.fetchCensys(assetId);
      if (result && result.message) { this.showToast(result.message, 'info'); return; }
      this.showToast('Censys data fetched', 'success');
      await this.showAsset(assetId);
    } catch(e) { this.showToast('Censys fetch failed: ' + (e.message || 'unknown error'), 'error'); }
  },

  async triggerAutoScan(assetId) {
    const menu = document.getElementById('actions-menu');
    if (menu) menu.style.display = 'none';
    this.showToast('Running auto scan chain \u2014 probing all detected OT protocols\u2026', 'info');
    try {
      const result = await this.api.autoScan(assetId);
      const count = (result.findings || []).length;
      const probed = result.protocols_scanned || 0;
      this.showToast(`Auto scan complete \u2014 ${probed} protocol(s) probed, ${count} finding(s)`, count > 0 ? 'success' : 'info');
      await this.showAsset(assetId);
    } catch(e) { this.showToast('Auto scan failed: ' + (e.message || 'unknown error'), 'error'); }
  },

  setToolboxCat(cat) {
    document.querySelectorAll('.toolbox-cat').forEach(b => b.classList.toggle('active', b.dataset.cat === cat));
    document.querySelectorAll('.toolbox-panel').forEach(p => p.classList.toggle('active', p.id === 'tb-' + cat));
  },

  async saveNERCCIP(assetId, event) {
    event.preventDefault();
    const form = event.target;
    const data = {
      bcs_asset:     form.bcs_asset.checked,
      impact_rating: form.impact_rating.value,
      asset_type:    form.asset_type.value,
      zone:          form.zone.value,
      esp_name:      form.esp_name.value,
      notes:         form.notes.value,
      cip_standards: Array.from(form.querySelectorAll('input[name="cip_standards"]:checked')).map(el => el.value),
    };
    try {
      await this.api.setNERCCIP(assetId, data);
      this.showToast('NERC CIP classification saved', 'success');
      await this.showAsset(assetId);
    } catch(e) {
      this.showToast('Failed to save NERC CIP: ' + (e.message || 'unknown error'), 'error');
    }
  },

  // Called from the "Search Exploits" button in the Exploits sub-section of the threats tab.
  // Fetches exploits for all CVEs associated with a port and renders them grouped by CVE.
  async searchAllExploitsForPort(cveIds, containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML = `<span style="font-size:12px;color:var(--text-muted)">Searching Exploit-DB for ${cveIds.length} CVE${cveIds.length !== 1 ? 's' : ''}\u2026</span>`;

    const typeColors = { webapps: '#e67e22', remote: '#e74c3c', local: '#c0392b', dos: '#8e44ad', shellcode: '#2980b9', papers: '#27ae60' };
    const results = await Promise.all(cveIds.map(id =>
      this.api.searchExploits(id).then(r => ({ cveId: id, exploits: r.exploits || [] })).catch(() => ({ cveId: id, exploits: [] }))
    ));

    const totalExploits = results.reduce((n, r) => n + r.exploits.length, 0);
    if (totalExploits === 0) {
      container.innerHTML = `<span style="font-size:12px;color:var(--text-muted)">No public exploits found on Exploit-DB for any of the ${cveIds.length} CVE${cveIds.length !== 1 ? 's' : ''}.</span>`;
      return;
    }

    const sectionsHtml = results.filter(r => r.exploits.length > 0).map(r => {
      const rows = r.exploits.map(ex => {
        const typeKey = (ex.type || '').toLowerCase();
        const typeColor = typeColors[typeKey] || '#7f8c8d';
        return `
          <div style="display:flex;align-items:flex-start;gap:10px;padding:7px 10px;margin-bottom:5px;background:var(--surface);border:1px solid var(--border);border-radius:4px">
            <div style="flex:1;min-width:0">
              <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:3px">
                <a href="${Utils.escapeHtml(ex.url)}" target="_blank" rel="noopener" style="font-size:12px;font-weight:600;color:var(--accent-blue)">#${Utils.escapeHtml(ex.id)}</a>
                ${ex.type ? `<span style="padding:1px 6px;border-radius:3px;background:${typeColor}22;border:1px solid ${typeColor}55;color:${typeColor};font-size:10px;font-weight:600">${Utils.escapeHtml(ex.type.toUpperCase())}</span>` : ''}
                ${ex.platform ? `<span class="badge badge-type" style="font-size:10px">${Utils.escapeHtml(ex.platform)}</span>` : ''}
                ${ex.verified ? `<span style="font-size:10px;color:#27ae60;font-weight:600">&#x2713; Verified</span>` : ''}
                ${ex.date ? `<span style="font-size:10px;color:var(--text-muted);margin-left:auto">${Utils.escapeHtml(ex.date)}</span>` : ''}
              </div>
              <div style="font-size:12px;color:var(--text-secondary);margin-bottom:3px">${Utils.escapeHtml(ex.title || '')}</div>
              ${ex.author ? `<div style="font-size:11px;color:var(--text-muted)">by ${Utils.escapeHtml(ex.author)}</div>` : ''}
            </div>
            <div style="display:flex;flex-direction:column;gap:4px;flex-shrink:0">
              <a href="${Utils.escapeHtml(ex.url)}" target="_blank" rel="noopener" class="btn btn-sm" style="font-size:11px;padding:3px 8px">View</a>
              <a href="${Utils.escapeHtml(ex.download_url)}" target="_blank" rel="noopener" class="btn btn-ghost btn-sm" style="font-size:11px;padding:3px 8px">&#x2193; Raw</a>
            </div>
          </div>`;
      }).join('');
      return `
        <div style="margin-bottom:12px">
          <div style="font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">
            ${Utils.escapeHtml(r.cveId)} &mdash; ${r.exploits.length} exploit${r.exploits.length !== 1 ? 's' : ''}
          </div>
          ${rows}
        </div>`;
    }).join('');

    container.innerHTML = `
      <div style="margin-bottom:8px;font-size:12px;font-weight:600;color:var(--severity-critical)">
        &#x1F4A5; ${totalExploits} exploit${totalExploits !== 1 ? 's' : ''} found across ${results.filter(r=>r.exploits.length>0).length} CVE${results.filter(r=>r.exploits.length>0).length !== 1 ? 's' : ''}
      </div>
      ${sectionsHtml}`;
  },

  // Called from the "Search Exploits" button inside the threats tab.
  async searchExploitsForCVE(cveId, containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML = `<span style="font-size:12px;color:var(--text-muted)">Searching Exploit-DB\u2026</span>`;
    try {
      const result = await this.api.searchExploits(cveId);
      const exploits = result.exploits || [];
      if (exploits.length === 0) {
        container.innerHTML = `<span style="font-size:12px;color:var(--text-muted)">No public exploits found on Exploit-DB for ${Utils.escapeHtml(cveId)}.</span>`;
        return;
      }
      const typeColors = { webapps: '#e67e22', remote: '#e74c3c', local: '#c0392b', dos: '#8e44ad', shellcode: '#2980b9', papers: '#27ae60' };
      container.innerHTML = `
        <div style="margin-top:2px">
          <div style="font-size:11px;font-weight:600;color:var(--severity-critical);margin-bottom:8px">&#x1F4A5; ${exploits.length} Exploit${exploits.length !== 1 ? 's' : ''} Found on Exploit-DB</div>
          ${exploits.map(ex => {
            const typeKey = (ex.type || '').toLowerCase();
            const typeColor = typeColors[typeKey] || '#7f8c8d';
            return `
              <div style="display:flex;align-items:flex-start;gap:10px;padding:8px 10px;margin-bottom:6px;background:var(--surface);border:1px solid var(--border);border-radius:4px">
                <div style="flex:1;min-width:0">
                  <div style="display:flex;align-items:center;gap:6px;margin-bottom:3px;flex-wrap:wrap">
                    <a href="${Utils.escapeHtml(ex.url)}" target="_blank" rel="noopener" style="font-size:12px;font-weight:600;color:var(--accent-blue)">#${Utils.escapeHtml(ex.id)}</a>
                    ${ex.type ? `<span style="padding:1px 6px;border-radius:3px;background:${typeColor}22;border:1px solid ${typeColor}55;color:${typeColor};font-size:10px;font-weight:600">${Utils.escapeHtml(ex.type.toUpperCase())}</span>` : ''}
                    ${ex.platform ? `<span class="badge badge-type" style="font-size:10px">${Utils.escapeHtml(ex.platform)}</span>` : ''}
                    ${ex.verified ? `<span style="font-size:10px;color:#27ae60;font-weight:600">&#x2713; Verified</span>` : ''}
                    ${ex.date ? `<span style="font-size:10px;color:var(--text-muted);margin-left:auto">${Utils.escapeHtml(ex.date)}</span>` : ''}
                  </div>
                  <div style="font-size:12px;color:var(--text-secondary);margin-bottom:4px">${Utils.escapeHtml(ex.title || '')}</div>
                  ${ex.author ? `<div style="font-size:11px;color:var(--text-muted)">by ${Utils.escapeHtml(ex.author)}</div>` : ''}
                </div>
                <div style="display:flex;flex-direction:column;gap:4px;flex-shrink:0">
                  <a href="${Utils.escapeHtml(ex.url)}" target="_blank" rel="noopener" class="btn btn-sm" style="font-size:11px;padding:3px 8px">View</a>
                  <a href="${Utils.escapeHtml(ex.download_url)}" target="_blank" rel="noopener" class="btn btn-ghost btn-sm" style="font-size:11px;padding:3px 8px">Download</a>
                </div>
              </div>`;
          }).join('')}
        </div>`;
    } catch(e) {
      container.innerHTML = `<span style="font-size:12px;color:var(--text-muted)">Search failed: ${Utils.escapeHtml(e.message || 'unknown error')}</span>`;
    }
  },

  async showAsset(assetId) {
    const el = document.getElementById('page-content');
    if (!el) return;
    try {
      const [asset, scanResults, findings, enrichment] = await Promise.all([
        this.api.getAsset(assetId),
        this.api.getAssetScanResults(assetId).catch(() => []),
        this.api.getAssetFindings(assetId).catch(() => []),
        this.api.getAssetEnrichment(assetId).catch(() => []),
      ]);
      const isDomainType = asset.type === 'domain' || asset.type === 'subdomain';
      const isIPType = asset.type === 'ip';
      const [dnsRecords, subdomains, tlsResult, snmpRec, otProbeRec, bgpRec, ipWhoisRec, cveRec, vulnNotesData, iec61850Rec, historianRec, hmiRec, icscertRec, nercCipData, iec104Rec, modbusDeepRec, dnp3DeepRec, iccpRec, enipDeepRec, profinetRec, opcuaRec, defaultCredsRec, censysRec] = await Promise.all([
        this.api.getAssetDNSRecords(assetId).catch(() => []),
        isDomainType ? this.api.getAssetSubdomains(assetId).catch(() => []) : Promise.resolve([]),
        isDomainType ? this.api.getTLSScan(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getSNMP(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getOTProbe(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getBGP(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getIPWhois(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getCVECorrelate(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getVulnNotes(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getIEC61850(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getHistorian(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getHMI(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getICSCert(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getNERCCIP(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getIEC104(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getModbusDeep(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getDNP3Deep(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getICCP(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getEtherNetIPDeep(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getProfinet(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getOPCUA(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getDefaultCreds(assetId).catch(() => null) : Promise.resolve(null),
        isIPType ? this.api.getCensys(assetId).catch(() => null) : Promise.resolve(null),
      ]);
      el.innerHTML = renderAssetDetail(asset, scanResults, dnsRecords, findings, enrichment, subdomains, tlsResult, snmpRec, otProbeRec, bgpRec, ipWhoisRec, cveRec, vulnNotesData, iec61850Rec, historianRec, hmiRec, icscertRec, nercCipData, iec104Rec, modbusDeepRec, dnp3DeepRec, iccpRec, enipDeepRec, profinetRec, opcuaRec, defaultCredsRec, censysRec);
      this._bindTabListeners();
      this._animateStatCards();
    } catch(err) {
      this.showToast('Failed to reload asset: ' + (err.message || 'unknown error'), 'error');
    }
  },

  // -----------------------------------------------------------------------
  // Page: Global Findings
  // -----------------------------------------------------------------------
  async _renderFindingsGlobalPage() {
    this._setAppHTML('findings', 'findings',
      'All Findings', [],
      '',
      renderEmptyState('Select an identity', 'Navigate to an identity to view its findings.'),
    );
  },

  // -----------------------------------------------------------------------
  // Page: Not Found
  // -----------------------------------------------------------------------
  _renderNotFound() {
    const appEl = document.getElementById('app');
    if (!appEl) return;
    appEl.innerHTML = `
      ${renderNav('')}
      <div class="app-body">
        <main class="main-content">
          ${renderEmptyState('Page Not Found', 'The route you requested does not exist.',
            `<a href="#/identities" class="btn btn-primary">Back to Identities</a>`
          )}
        </main>
      </div>
    `;
  },

  // -----------------------------------------------------------------------
  // Modal: Create Identity
  // -----------------------------------------------------------------------
  showCreateIdentityModal() {
    this.showModal(renderCreateIdentityModal());
    setTimeout(() => {
      const el = document.getElementById('fi-name');
      if (el) el.focus();
    }, 50);
  },

  async submitCreateIdentity(event) {
    if (event) event.preventDefault();

    const nameEl = document.getElementById('fi-name');
    const orgEl = document.getElementById('fi-org');
    const sectorEl = document.getElementById('fi-sector');
    const notesEl = document.getElementById('fi-notes');
    const tagsEl = document.getElementById('fi-tags');
    const domainsEl = document.getElementById('fi-domains');
    const ipsEl = document.getElementById('fi-ips');

    if (!nameEl || !orgEl) return;

    const name = nameEl.value.trim();
    const orgName = orgEl.value.trim();

    if (!name || !orgName) {
      this.showToast('Name and Organization are required', 'error');
      return;
    }

    const rawTags = tagsEl ? tagsEl.value : '';
    const tags = rawTags
      ? rawTags.split(',').map(t => t.trim()).filter(Boolean)
      : [];

    const submitBtn = document.getElementById('create-identity-submit');
    if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = 'Creating...'; }

    try {
      const identity = await this.api.createIdentity({
        name,
        org_name: orgName,
        sector: sectorEl ? sectorEl.value : '',
        notes: notesEl ? notesEl.value.trim() : '',
        tags: tags,
      });

      // Create seeds
      const seedPromises = [];
      const domains = domainsEl ? domainsEl.value.split('\n').map(s => s.trim()).filter(Boolean) : [];
      const ips = ipsEl ? ipsEl.value.split('\n').map(s => s.trim()).filter(Boolean) : [];

      for (const d of domains) {
        seedPromises.push(this.api.createSeed(identity.id, { type: 'domain', value: d }).catch(() => null));
      }
      for (const ip of ips) {
        const type = ip.includes('/') ? 'cidr' : 'ip';
        seedPromises.push(this.api.createSeed(identity.id, { type, value: ip }).catch(() => null));
      }

      await Promise.all(seedPromises);

      this.hideModal();
      this.showToast(`Identity "${name}" created successfully`, 'success');
      this.navigate(`/identities/${identity.id}`);
    } catch (err) {
      if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = 'Create Identity'; }
      this.showToast(err.message || 'Failed to create identity', 'error');
    }
  },

  // -----------------------------------------------------------------------
  // Modal: Create Seed
  // -----------------------------------------------------------------------
  showCreateSeedModal(identityId) {
    this.showModal(renderCreateSeedModal(identityId));
    setTimeout(() => {
      const el = document.getElementById('fs-type');
      if (el) el.focus();
    }, 50);
  },

  async submitCreateSeed(event, identityId) {
    if (event) event.preventDefault();

    const typeEl = document.getElementById('fs-type');
    const valueEl = document.getElementById('fs-value');

    if (!typeEl || !valueEl) return;

    const type = typeEl.value;
    const value = valueEl.value.trim();

    if (!type || !value) {
      this.showToast('Type and value are required', 'error');
      return;
    }

    try {
      await this.api.createSeed(identityId, { type, value });
      this.hideModal();
      this.showToast('Seed added successfully', 'success');
      // Reload current page
      this._renderIdentityDetailPage({ id: identityId });
    } catch (err) {
      this.showToast(err.message || 'Failed to add seed', 'error');
    }
  },

  // -----------------------------------------------------------------------
  // Identity: Start Discovery
  // -----------------------------------------------------------------------
  async startDiscovery(identityId) {
    try {
      const result = await this.api.createRun(identityId, { triggered_by: 'ui' });
      this.showToast('Discovery run started', 'success');
      this.navigate(`/identities/${identityId}/runs/${result.run.id}`);
    } catch (err) {
      this.showToast(err.message || 'Failed to start discovery', 'error');
    }
  },

  // -----------------------------------------------------------------------
  // Identity: Delete
  // -----------------------------------------------------------------------
  confirmDeleteIdentity(id, name) {
    this.showModal(renderConfirmModal(
      'Delete Identity',
      `Are you sure you want to delete "${name}"? This action cannot be undone and will remove all associated assets, findings, and runs.`,
      'Delete',
      'btn-danger',
      `App.deleteIdentity('${Utils.escapeHtml(id)}')`
    ));
  },

  async deleteIdentity(id) {
    try {
      await this.api.deleteIdentity(id);
      this.hideModal();
      this.showToast('Identity deleted', 'success');
      this.navigate('/identities');
    } catch (err) {
      this.showToast(err.message || 'Failed to delete identity', 'error');
    }
  },

  // -----------------------------------------------------------------------
  // Pagination
  // -----------------------------------------------------------------------
  changePage(page) {
    this._currentPage_num = page;
    this.filterAssets();
  },

  // -----------------------------------------------------------------------
  // Modal
  // -----------------------------------------------------------------------
  showModal(html) {
    const container = document.getElementById('modal-container');
    if (container) {
      container.innerHTML = html;
      document.addEventListener('keydown', this._modalKeyHandler);
    }
  },

  hideModal() {
    const container = document.getElementById('modal-container');
    if (container) {
      container.innerHTML = '';
      document.removeEventListener('keydown', this._modalKeyHandler);
    }
  },

  _modalKeyHandler(e) {
    if (e.key === 'Escape') App.hideModal();
  },

  _onModalOverlayClick(event) {
    if (event.target.id === 'modal-overlay') {
      this.hideModal();
    }
  },

  // -----------------------------------------------------------------------
  // Toast
  // -----------------------------------------------------------------------
  showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const icons = { success: '&#10003;', error: '&#10007;', warning: '&#9888;', info: '&#8505;' };
    const id = `toast-${Date.now()}`;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.id = id;
    toast.innerHTML = `
      <span class="toast-icon">${icons[type] || icons.info}</span>
      <div class="toast-content">
        <div class="toast-message">${Utils.escapeHtml(message)}</div>
      </div>
    `;

    container.appendChild(toast);

    setTimeout(() => {
      toast.classList.add('toast-out');
      setTimeout(() => { if (toast.parentNode) toast.parentNode.removeChild(toast); }, 200);
    }, 4000);
  },

  // -----------------------------------------------------------------------
  // Asset Network Graph
  // -----------------------------------------------------------------------
  _initAssetGraph(assets, findingCounts, dnsLinks, identityId) {
    const wrap = document.getElementById('asset-graph-wrap');
    const canvas = document.getElementById('asset-graph-canvas');
    if (!wrap || !canvas) return;

    const W = wrap.clientWidth;
    const H = wrap.clientHeight;
    canvas.width  = W;
    canvas.height = H;
    const ctx = canvas.getContext('2d');

    // ---- node colours & sizes by type ----
    const NODE_COLORS = { ip: '#3b82f6', domain: '#f59e0b', subdomain: '#8b5cf6', endpoint: '#10b981', default: '#6b7280' };
    const NODE_RADIUS = { ip: 9, domain: 11, subdomain: 7, endpoint: 6, default: 7 };

    // ---- cloud/CDN detection (mirrors backend quickdiscover logic) ----
    const CLOUD_ORG_PATTERNS = [
      'amazon','aws','cloudflare','akamai','fastly','microsoft','azure',
      'google','digitalocean','linode','vultr','choopa','ovh','hetzner',
      'leaseweb','rackspace','cdn77','stackpath','imperva','incapsula',
      'sucuri','zscaler','alibaba','aliyun','tencent','oracle cloud',
      'ibm cloud','softlayer',
    ];
    const CLOUD_RDNS_PATTERNS = [
      'amazonaws.com','compute.internal','googleusercontent.com',
      'cloud.google.com','azure.com','cloudapp.net','cloudapp.azure.com',
      'windows.net','cloudflare.com','fastly.net','akamaiedge.net',
      'akadns.net','akamaihd.net','edgekey.net','edgesuite.net',
      'digitalocean.com','linode.com','vultr.com','choopa.net',
      'ovh.net','hetzner.com','hetzner.de',
    ];
    function isCloudAsset(a) {
      if (a.is_cloud) return true;
      const org = (a.asn_org || '').toLowerCase();
      if (org && CLOUD_ORG_PATTERNS.some(p => org.includes(p))) return true;
      const rdns = (a.reverse_dns || '').toLowerCase();
      if (rdns && CLOUD_RDNS_PATTERNS.some(p => rdns.includes(p))) return true;
      return false;
    }

    // ---- build node map ----
    const nodeMap = {};
    assets.forEach(a => {
      nodeMap[a.id] = {
        id: a.id, asset: a,
        x: W / 2 + (Math.random() - 0.5) * W * 0.6,
        y: H / 2 + (Math.random() - 0.5) * H * 0.6,
        vx: 0, vy: 0,
        r: NODE_RADIUS[a.type] || NODE_RADIUS.default,
        color: NODE_COLORS[a.type] || NODE_COLORS.default,
        label: a.value || a.id,
        findingCount: findingCounts[a.id] || 0,
        isCloud: a.type === 'ip' && isCloudAsset(a),
      };
    });
    const nodes = Object.values(nodeMap);

    // ---- build IP value → node lookup ----
    const ipByValue = {};
    nodes.forEach(n => { if (n.asset.type === 'ip') ipByValue[n.asset.value] = n; });

    // ---- edges ----
    const edgeSet = new Set();
    const edges = [];

    function addEdge(a, b, kind) {
      const key = [a.id, b.id].sort().join(':');
      if (!edgeSet.has(key)) {
        edgeSet.add(key);
        edges.push({ source: a, target: b, kind });
      }
    }

    // subdomain → parent domain (suffix match)
    const domainNodes = nodes.filter(n => n.asset.type === 'domain');
    nodes.forEach(n => {
      if (n.asset.type === 'subdomain') {
        const parent = domainNodes.find(d => n.asset.value && n.asset.value.endsWith('.' + d.asset.value));
        if (parent) addEdge(n, parent, 'subdomain');
      }
    });

    // domain → IP via DNS A/AAAA records returned by server
    dnsLinks.forEach(({ domain_asset_id, ip }) => {
      const domainNode = nodeMap[domain_asset_id];
      const ipNode = ipByValue[ip];
      if (domainNode && ipNode) addEdge(domainNode, ipNode, 'dns');
    });

    // ---- simulation constants ----
    const K  = 90;    // ideal spring length
    const KS = 0.04;  // spring stiffness
    const KR = 4000;  // repulsion constant
    const DAMP = 0.82;
    let running = true;
    let animFrame;

    function simulate() {
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i], b = nodes[j];
          const dx = b.x - a.x, dy = b.y - a.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const f = KR / (dist * dist);
          const fx = f * dx / dist, fy = f * dy / dist;
          a.vx -= fx; a.vy -= fy;
          b.vx += fx; b.vy += fy;
        }
      }
      edges.forEach(({ source: a, target: b }) => {
        const dx = b.x - a.x, dy = b.y - a.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const f = KS * (dist - K);
        const fx = f * dx / dist, fy = f * dy / dist;
        a.vx += fx; a.vy += fy;
        b.vx -= fx; b.vy -= fy;
      });
      const cx = W / 2, cy = H / 2;
      nodes.forEach(n => {
        n.vx += (cx - n.x) * 0.003;
        n.vy += (cy - n.y) * 0.003;
        n.vx *= DAMP; n.vy *= DAMP;
        n.x += n.vx; n.y += n.vy;
      });
    }

    // ---- pan / zoom ----
    let pan = { x: 0, y: 0 }, zoom = 1;
    let dragging = false, dragStart = { x: 0, y: 0 }, panStart = { x: 0, y: 0 };
    let selectedNode = null;

    function toWorld(cx, cy) { return { x: (cx - pan.x) / zoom, y: (cy - pan.y) / zoom }; }

    canvas.addEventListener('wheel', (e) => {
      e.preventDefault();
      const factor = e.deltaY < 0 ? 1.1 : 0.9;
      const rect = canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left, my = e.clientY - rect.top;
      pan.x = mx - (mx - pan.x) * factor;
      pan.y = my - (my - pan.y) * factor;
      zoom *= factor;
    }, { passive: false });

    canvas.addEventListener('mousedown', (e) => {
      dragging = true;
      dragStart = { x: e.offsetX, y: e.offsetY };
      panStart  = { x: pan.x, y: pan.y };
    });
    canvas.addEventListener('mousemove', (e) => {
      if (!dragging) return;
      pan.x = panStart.x + (e.offsetX - dragStart.x);
      pan.y = panStart.y + (e.offsetY - dragStart.y);
    });
    canvas.addEventListener('mouseup', (e) => {
      const moved = Math.abs(e.offsetX - dragStart.x) + Math.abs(e.offsetY - dragStart.y);
      dragging = false;
      if (moved < 5) {
        const w = toWorld(e.offsetX, e.offsetY);
        let hit = null;
        for (const n of nodes) {
          const dx = n.x - w.x, dy = n.y - w.y;
          if (Math.sqrt(dx * dx + dy * dy) <= n.r + 6) { hit = n; break; }
        }
        selectedNode = hit;
        if (hit) showNodePanel(hit);
        else { const p = document.getElementById('graph-node-panel'); if (p) p.remove(); }
      }
    });
    canvas.addEventListener('mouseleave', () => { dragging = false; });

    // ---- node info panel ----
    function showNodePanel(node) {
      let p = document.getElementById('graph-node-panel');
      if (!p) {
        p = document.createElement('div');
        p.id = 'graph-node-panel';
        p.className = 'graph-node-panel';
        wrap.appendChild(p);
      }
      const asset = node.asset;
      const fc = node.findingCount;
      const typeLabels = { ip: 'IP Address', domain: 'Domain', subdomain: 'Subdomain', endpoint: 'Endpoint' };
      const typeColors = { ip: '#3b82f6', domain: '#f59e0b', subdomain: '#8b5cf6', endpoint: '#10b981' };
      const tc = typeColors[asset.type] || '#6b7280';

      // Connected nodes via edges
      const connected = edges
        .filter(e => e.source.id === node.id || e.target.id === node.id)
        .map(e => e.source.id === node.id ? e.target : e.source);

      const connectedHTML = connected.length
        ? `<div class="graph-panel-meta" style="margin-top:6px"><span style="color:var(--text-muted)">Linked to:</span>
            ${connected.slice(0, 5).map(c =>
              `<div style="font-family:var(--font-mono);font-size:11px;color:${typeColors[c.asset.type]||'#6b7280'};padding-top:2px">
                ${Utils.escapeHtml(c.asset.value || c.id)}
              </div>`
            ).join('')}
            ${connected.length > 5 ? `<div style="font-size:11px;color:var(--text-muted)">+${connected.length - 5} more</div>` : ''}
          </div>`
        : '';

      const findingBadge = fc > 0
        ? `<span style="background:#ef444422;color:#ef4444;font-size:10px;padding:2px 7px;border-radius:10px;font-weight:600;margin-left:6px">&#9888; ${fc} finding${fc > 1 ? 's' : ''}</span>`
        : '';
      const cloudBadge = node.isCloud
        ? `<span style="background:#0ea5e922;color:#38bdf8;font-size:10px;padding:2px 7px;border-radius:10px;font-weight:600;margin-left:6px">&#9729; Cloud</span>`
        : '';

      p.innerHTML = `
        <div class="graph-panel-header">
          <div style="display:flex;align-items:center;flex-wrap:wrap;gap:4px">
            <span style="background:${tc}22;color:${tc};font-size:10px;padding:2px 7px;border-radius:10px;font-weight:600">${typeLabels[asset.type] || asset.type}</span>
            ${findingBadge}
            ${cloudBadge}
          </div>
          <button onclick="document.getElementById('graph-node-panel').remove()" style="background:none;border:none;cursor:pointer;color:var(--text-muted);font-size:16px;line-height:1;padding:0;flex-shrink:0">&times;</button>
        </div>
        <div class="graph-panel-value">${Utils.escapeHtml(asset.value || '—')}</div>
        <div style="padding:6px 14px 0;display:flex;flex-direction:column;gap:3px">
          ${asset.country_code ? `<div class="graph-panel-meta">Country: <strong>${Utils.escapeHtml(asset.country_code)}</strong></div>` : ''}
          ${asset.asn ? `<div class="graph-panel-meta">ASN: <strong>AS${asset.asn}${asset.asn_org ? ' — ' + Utils.escapeHtml(asset.asn_org) : ''}</strong></div>` : ''}
          ${asset.reverse_dns ? `<div class="graph-panel-meta">rDNS: <strong style="font-family:var(--font-mono);font-size:11px">${Utils.escapeHtml(asset.reverse_dns)}</strong></div>` : ''}
          ${asset.is_public !== undefined ? `<div class="graph-panel-meta">Visibility: <strong>${asset.is_public ? 'Public' : 'Private'}</strong></div>` : ''}
          ${asset.is_cloud ? `<div class="graph-panel-meta">Cloud: <strong>Yes</strong></div>` : ''}
          ${asset.provenance ? `<div class="graph-panel-meta">Source: <strong>${Utils.escapeHtml(asset.provenance)}</strong></div>` : ''}
          ${connectedHTML}
        </div>
        <div style="padding:10px 14px 12px;display:flex;flex-direction:column;gap:6px">
          <button class="btn btn-sm" id="graph-discover-btn"
            style="display:block;text-align:center;background:var(--accent-green,#10b981);color:#fff;border:none;cursor:pointer;border-radius:var(--border-radius-sm);padding:6px 0;font-size:12px;font-weight:600"
            onclick="App.triggerQuickDiscover('${asset.id}','${Utils.escapeHtml(asset.type)}')">
            &#128270; Discover
          </button>
          <a class="btn btn-sm btn-primary" style="display:block;text-align:center" href="#/assets/${asset.id}">Explore Asset</a>
        </div>
        <div id="graph-discover-result" style="display:none;padding:0 14px 12px;font-size:11px;color:var(--text-muted)"></div>
      `;
    }

    // ---- draw ----
    const EDGE_COLORS = { dns: 'rgba(59,130,246,0.35)', subdomain: 'rgba(139,92,246,0.25)', default: 'rgba(148,163,184,0.2)' };

    function draw() {
      ctx.clearRect(0, 0, W, H);
      ctx.save();
      ctx.translate(pan.x, pan.y);
      ctx.scale(zoom, zoom);

      // edges
      edges.forEach(({ source: a, target: b, kind }) => {
        ctx.beginPath();
        ctx.strokeStyle = EDGE_COLORS[kind] || EDGE_COLORS.default;
        ctx.lineWidth = (kind === 'dns' ? 1.5 : 1) / zoom;
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.stroke();
      });

      // nodes
      nodes.forEach(n => {
        const selected = selectedNode && selectedNode.id === n.id;

        // selection glow
        if (selected) {
          ctx.beginPath();
          ctx.arc(n.x, n.y, n.r + 5, 0, Math.PI * 2);
          ctx.fillStyle = n.color + '55';
          ctx.fill();
        }

        // main circle
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.fillStyle = n.color;
        ctx.fill();
        ctx.strokeStyle = 'rgba(255,255,255,0.18)';
        ctx.lineWidth = 1.5 / zoom;
        ctx.stroke();

        // red finding indicator (top-right of node)
        if (n.findingCount > 0) {
          const ir = Math.max(4, 5 / zoom);
          const ix = n.x + n.r * 0.7;
          const iy = n.y - n.r * 0.7;
          ctx.beginPath();
          ctx.arc(ix, iy, ir, 0, Math.PI * 2);
          ctx.fillStyle = '#ef4444';
          ctx.fill();
          ctx.strokeStyle = '#1e293b';
          ctx.lineWidth = 1.2 / zoom;
          ctx.stroke();
          // count label inside dot (only if zoomed in and small count)
          if (zoom > 0.7 && n.findingCount <= 9) {
            ctx.fillStyle = '#fff';
            ctx.font = `bold ${Math.round(7 / zoom)}px sans-serif`;
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText(String(n.findingCount), ix, iy);
            ctx.textBaseline = 'alphabetic';
          }
        }

        // cloud icon (bottom-left of node)
        if (n.isCloud) {
          const cs = Math.round(Math.max(9, 11 / zoom));
          ctx.font = `${cs}px sans-serif`;
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillStyle = 'rgba(148,213,252,0.95)'; // sky blue tint
          ctx.fillText('☁', n.x - n.r * 0.65, n.y + n.r * 0.65);
          ctx.textBaseline = 'alphabetic';
        }

        // label
        if (zoom > 0.45) {
          ctx.fillStyle = selected ? '#f1f5f9' : 'rgba(203,213,225,0.85)';
          ctx.font = `${Math.round(10 / zoom)}px var(--font-mono, monospace)`;
          ctx.textAlign = 'center';
          const maxLen = 22;
          const lbl = n.label.length > maxLen ? n.label.slice(0, maxLen) + '…' : n.label;
          ctx.fillText(lbl, n.x, n.y + n.r + Math.round(13 / zoom));
        }
      });

      ctx.restore();
    }

    let tick = 0;
    function loop() {
      if (!running) return;
      if (tick < 300) { simulate(); tick++; }
      draw();
      animFrame = requestAnimationFrame(loop);
    }

    const obs = new MutationObserver(() => {
      if (!document.getElementById('asset-graph-wrap')) {
        running = false;
        cancelAnimationFrame(animFrame);
        obs.disconnect();
      }
    });
    obs.observe(document.body, { childList: true, subtree: true });

    loop();
  },

  // -----------------------------------------------------------------------
  // Quick Discover (graph node panel)
  // -----------------------------------------------------------------------
  async triggerQuickDiscover(assetId, assetType) {
    const btn = document.getElementById('graph-discover-btn');
    const resultEl = document.getElementById('graph-discover-result');
    if (!btn || !resultEl) return;

    btn.disabled = true;
    btn.textContent = 'Discovering…';
    resultEl.style.display = 'none';
    resultEl.innerHTML = '';

    try {
      const res = await this.api.post(`/assets/${assetId}/quick-discover`, {});

      const newCount  = (res.new_assets  || []).length;
      const rdnsCount = (res.dns_links   || []).length;
      const subCount  = (res.subdomains  || []).length;

      let html = `<div style="color:var(--accent-green,#10b981);font-weight:600;margin-bottom:4px">&#10003; Discovery complete</div>`;
      html += `<div>${res.message || ''}</div>`;

      if (newCount > 0) {
        html += `<div style="margin-top:6px;color:var(--text-secondary)"><strong>${newCount}</strong> new IP${newCount > 1 ? 's' : ''} found:</div>`;
        html += `<div style="font-family:var(--font-mono);margin-top:2px">`;
        (res.new_assets || []).slice(0, 8).forEach(a => {
          html += `<div style="padding:1px 0">${Utils.escapeHtml(a.value)}</div>`;
        });
        if (newCount > 8) html += `<div style="color:var(--text-muted)">+${newCount - 8} more</div>`;
        html += `</div>`;
      }

      if (rdnsCount > 0) {
        html += `<div style="margin-top:6px;color:var(--text-secondary)"><strong>${rdnsCount}</strong> reverse DNS hit${rdnsCount > 1 ? 's' : ''}:</div>`;
        html += `<div style="font-family:var(--font-mono);margin-top:2px">`;
        (res.dns_links || []).slice(0, 5).forEach(d => {
          html += `<div style="padding:1px 0;color:var(--text-muted)">${Utils.escapeHtml(d.ip)} → ${Utils.escapeHtml(d.hostname)}</div>`;
        });
        if (rdnsCount > 5) html += `<div style="color:var(--text-muted)">+${rdnsCount - 5} more</div>`;
        html += `</div>`;
      }

      if (subCount > 0) {
        html += `<div style="margin-top:6px;color:var(--text-secondary)"><strong>${subCount}</strong> subdomain${subCount > 1 ? 's' : ''} found:</div>`;
        html += `<div style="font-family:var(--font-mono);margin-top:2px">`;
        (res.subdomains || []).slice(0, 6).forEach(s => {
          html += `<div style="padding:1px 0">${Utils.escapeHtml(s.value)}</div>`;
        });
        if (subCount > 6) html += `<div style="color:var(--text-muted)">+${subCount - 6} more</div>`;
        html += `</div>`;
      }

      if (newCount === 0 && rdnsCount === 0 && subCount === 0) {
        html += `<div style="margin-top:4px;color:var(--text-muted)">No new assets found.</div>`;
      } else {
        // Reload the graph to show new nodes
        html += `<button class="btn btn-sm" style="margin-top:8px;width:100%;font-size:11px" onclick="App.switchAssetView('graph')">Refresh graph</button>`;
      }

      resultEl.innerHTML = html;
      resultEl.style.display = 'block';

      btn.textContent = '↺ Discover again';
      btn.disabled = false;

    } catch (err) {
      resultEl.innerHTML = `<div style="color:var(--text-critical,#ef4444)">${Utils.escapeHtml(err.message)}</div>`;
      resultEl.style.display = 'block';
      btn.textContent = '&#128270; Discover';
      btn.disabled = false;
    }
  },

  // -----------------------------------------------------------------------
  // Error helper
  // -----------------------------------------------------------------------
  _showError(err) {
    const el = document.getElementById('page-content');
    const msg = err && err.status === 404
      ? 'Resource not found'
      : (err && err.message) || 'An unexpected error occurred';

    if (el) {
      el.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">&#9888;</div>
          <div class="empty-state-title text-critical">Error</div>
          <div class="empty-state-desc">${Utils.escapeHtml(msg)}</div>
          <button class="btn btn-secondary" onclick="window.history.back()">Go Back</button>
        </div>
      `;
    }
    this.showToast(msg, 'error');
  },
};

/* -------------------------------------------------------------------------
   Bootstrap
   ------------------------------------------------------------------------- */
document.addEventListener('DOMContentLoaded', () => {
  App.init();
});
