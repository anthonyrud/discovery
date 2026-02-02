let lastJson = null;

const $ = (id) => document.getElementById(id);

function normDomain(input){
  const x = String(input || '').trim();
  if (!x) return '';
  // strip protocol/path if pasted
  try {
    if (x.includes('://')) {
      const u = new URL(x);
      return u.hostname;
    }
  } catch {}
  return x.replace(/^\.+/, '').replace(/\/$/, '');
}

function tag(label, value){
  if (value == null || value === '') return '';
  return `<span class="tag"><strong>${escapeHtml(label)}:</strong>&nbsp;${escapeHtml(String(value))}</span>`;
}

function escapeHtml(s){
  return String(s)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function renderSection(title, rows, extraHtml=''){
  const inner = rows
    .filter(r => r && r.k)
    .map(r => `<div class="kv"><div class="k">${escapeHtml(r.k)}</div><div class="v">${r.v}</div></div>`)
    .join('');
  return `<section class="card"><h2>${escapeHtml(title)}</h2>${inner}${extraHtml}</section>`;
}

const PROVIDERS = {
  'Cloudflare DNS': { site: 'https://www.cloudflare.com/', logo: 'https://www.cloudflare.com/favicon.ico' },
  'AWS Route 53': { site: 'https://aws.amazon.com/route53/', logo: 'https://aws.amazon.com/favicon.ico' },
  'Azure DNS': { site: 'https://azure.microsoft.com/en-gb/products/dns/', logo: 'https://azure.microsoft.com/favicon.ico' },
  'Amazon CloudFront': { site: 'https://aws.amazon.com/cloudfront/', logo: 'https://aws.amazon.com/favicon.ico' },
  'Fastly': { site: 'https://www.fastly.com/', logo: 'https://www.fastly.com/favicon.ico' },
  'Akamai': { site: 'https://www.akamai.com/', logo: 'https://www.akamai.com/favicon.ico' },
  'Azure Front Door / CDN': { site: 'https://azure.microsoft.com/en-gb/products/frontdoor/', logo: 'https://azure.microsoft.com/favicon.ico' },
  "Let's Encrypt": { site: 'https://letsencrypt.org/', logo: 'https://letsencrypt.org/favicon.ico' },
  'Google Workspace': { site: 'https://workspace.google.com/', logo: 'https://workspace.google.com/favicon.ico' },
  'Microsoft 365 (Exchange Online)': { site: 'https://www.microsoft.com/microsoft-365', logo: 'https://www.microsoft.com/favicon.ico' },
  'Proofpoint': { site: 'https://www.proofpoint.com/', logo: 'https://www.proofpoint.com/favicon.ico' },
  'Mimecast': { site: 'https://www.mimecast.com/', logo: 'https://www.mimecast.com/favicon.ico' },
  'Mailgun': { site: 'https://www.mailgun.com/', logo: 'https://www.mailgun.com/favicon.ico' },
  'SendGrid': { site: 'https://sendgrid.com/', logo: 'https://sendgrid.com/favicon.ico' },
  'Amazon SES': { site: 'https://aws.amazon.com/ses/', logo: 'https://aws.amazon.com/favicon.ico' },
};

function isProviderFinding(f){
  if (!f || !f.kind) return false;
  if (f.kind === 'http') return false;
  const v = String(f.value || '');
  if (!v) return false;
  if (v.includes('=')) return false;
  if (f.kind === 'email' && v === 'Unknown') return false;
  return true;
}

function listProviders(data){
  const xs = (data.findings || []).filter(isProviderFinding).map(f => String(f.value));
  return Array.from(new Set(xs));
}

function providerMeta(name){
  return PROVIDERS[name] || { site: null, logo: null };
}

function openProviderModal(providerName, data){
  const modal = $('providerModal');
  const meta = providerMeta(providerName);

  $('modalTitle').textContent = providerName;
  $('modalSub').innerHTML = meta.site ? `<a href="${escapeHtml(meta.site)}" target="_blank" rel="noopener noreferrer">${escapeHtml(meta.site)}</a>` : '';

  const matches = (data.findings || []).filter(f => isProviderFinding(f) && String(f.value) === providerName);
  const body = matches.map((f) => {
    const pct = Math.round((f.confidence || 0) * 100);
    const ev = f.evidence || null;
    return `
      <div class="card" style="margin:10px 0">
        <h2>${escapeHtml(f.kind)} (${pct}%)</h2>
        <pre>${escapeHtml(JSON.stringify(ev, null, 2))}</pre>
      </div>
    `;
  }).join('') || `<div class="hint">No evidence found.</div>`;

  $('modalBody').innerHTML = body;

  if (typeof modal.showModal === 'function') modal.showModal();
}

function renderProvidersCard(data){
  const providers = listProviders(data);
  if (!providers.length) return '';

  const buttons = providers.map((p) => {
    const meta = providerMeta(p);
    const logo = meta.logo
      ? `<img class="providerLogo" src="${escapeHtml(meta.logo)}" alt="${escapeHtml(p)} logo" loading="lazy" />`
      : `<div class="providerLogo" style="display:flex;align-items:center;justify-content:center;border-radius:7px;background:rgba(255,255,255,.06);border:1px solid var(--stroke);font-size:11px;font-weight:900">${escapeHtml(p.slice(0,2).toUpperCase())}</div>`;

    const sub = meta.site ? `Official: ${meta.site.replace(/^https?:\/\//,'').replace(/\/$/,'')}` : 'Click to view evidence';

    return `
      <button type="button" class="providerBtn" data-provider="${escapeHtml(p)}">
        ${logo}
        <div>
          <div class="providerName">${escapeHtml(p)}</div>
          <div class="providerMeta">${escapeHtml(sub)}</div>
        </div>
      </button>
    `;
  }).join('');

  return `<section class="card"><h2>Providers discovered</h2><div class="providers">${buttons}</div></section>`;
}

function render(data){
  lastJson = data;
  $('copyJson').disabled = false;

  const providersCard = renderProvidersCard(data);

  const dns = renderSection('DNS overview', [
    { k: 'Domain', v: `<span class="mono">${escapeHtml(data.domain)}</span>` },
    { k: 'NS', v: (data.dns?.ns||[]).map(x=>`<span class="mono">${escapeHtml(x)}</span>`).join('<br>') || '—' },
    { k: 'SOA', v: data.dns?.soa ? `<span class="mono">${escapeHtml(data.dns.soa)}</span>` : '—' },
    { k: 'A / AAAA', v: [...(data.dns?.a||[]), ...(data.dns?.aaaa||[])].map(x=>`<span class="mono">${escapeHtml(x)}</span>`).join('<br>') || '—' },
    { k: 'CNAME', v: (data.dns?.cname||[]).map(x=>`<span class="mono">${escapeHtml(x)}</span>`).join('<br>') || '—' },
    { k: 'MX', v: (data.dns?.mx||[]).map(x=>`<span class="mono">${escapeHtml(x.exchange)}</span> <span class="mono">(prio ${x.priority})</span>`).join('<br>') || '—' },
    { k: 'TXT (SPF/verify)', v: (data.dns?.txt||[]).slice(0,8).map(x=>`<span class="mono">${escapeHtml(x)}</span>`).join('<br>') || '—' },
    { k: 'DMARC', v: data.email?.dmarc ? `<span class="mono">${escapeHtml(data.email.dmarc)}</span>` : '—' },
  ]);

  const http = renderSection('HTTP / TLS', [
    { k: 'HTTPS URL', v: data.http?.https?.url ? `<a href="${escapeHtml(data.http.https.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(data.http.https.url)}</a>` : '—' },
    { k: 'HTTPS status', v: data.http?.https?.status ? `<span class="mono">${escapeHtml(data.http.https.status)}</span>` : '—' },
    { k: 'HTTPS server', v: data.http?.https?.headers?.server ? `<span class="mono">${escapeHtml(data.http.https.headers.server)}</span>` : '—' },
    { k: 'HTTPS via', v: data.http?.https?.headers?.via ? `<span class="mono">${escapeHtml(data.http.https.headers.via)}</span>` : '—' },
    { k: 'HSTS', v: data.http?.https?.headers?.['strict-transport-security'] ? `<span class="mono">${escapeHtml(data.http.https.headers['strict-transport-security'])}</span>` : '—' },
    { k: 'Certificate issuer', v: data.tls?.issuer ? escapeHtml(data.tls.issuer) : '—' },
    { k: 'Certificate subject', v: data.tls?.subject ? escapeHtml(data.tls.subject) : '—' },
    { k: 'Valid (from → to)', v: (data.tls?.valid_from && data.tls?.valid_to) ? `<span class="mono">${escapeHtml(data.tls.valid_from)} → ${escapeHtml(data.tls.valid_to)}</span>` : '—' },
    { k: 'SANs (first 10)', v: (data.tls?.sans||[]).slice(0,10).map(x=>`<span class="mono">${escapeHtml(x)}</span>`).join('<br>') || '—' },
  ]);

  const email = renderSection('Email hints', [
    { k: 'MX provider', v: data.email?.mxProvider ? escapeHtml(data.email.mxProvider) : '—' },
    { k: 'SPF', v: data.email?.spf ? `<span class="mono">${escapeHtml(data.email.spf)}</span>` : '—' },
    { k: 'SPF includes', v: (data.email?.spfIncludes||[]).map(x=>`<span class="mono">${escapeHtml(x)}</span>`).join('<br>') || '—' },
  ]);

  const rdap = renderSection('IP ownership (RDAP best-effort)', [
    { k: 'A/AAAA RDAP', v: (data.rdap||[]).map(r => `<div><span class="mono">${escapeHtml(r.ip)}</span> — ${escapeHtml(r.name || 'unknown')} ${r.handle ? `(<span class="mono">${escapeHtml(r.handle)}</span>)` : ''}</div>`).join('') || '—' },
  ]);

  const raw = `<section class="card"><h2>Raw JSON</h2><pre>${escapeHtml(JSON.stringify(data, null, 2))}</pre></section>`;

  $('out').innerHTML = `${providersCard}<div class="grid">${dns}${http}</div>${email}${rdap}${raw}`;

  // wire buttons
  document.querySelectorAll('.providerBtn').forEach((btn) => {
    btn.addEventListener('click', () => openProviderModal(btn.dataset.provider, data));
  });
}

async function scan(domain){
  $('err').textContent = '';
  $('out').innerHTML = '';
  $('copyJson').disabled = true;
  lastJson = null;

  const r = await fetch(`/api/discover?domain=${encodeURIComponent(domain)}`, { cache: 'no-store' });
  if (!r.ok) {
    const t = await r.text();
    throw new Error(`${r.status} ${r.statusText}: ${t}`);
  }
  const j = await r.json();
  render(j);
}

$('form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    const d = normDomain($('domain').value);
    if (!d) return;
    await scan(d);
  } catch (err) {
    $('err').textContent = String(err?.message || err);
  }
});

$('copyJson').addEventListener('click', async () => {
  if (!lastJson) return;
  try {
    await navigator.clipboard.writeText(JSON.stringify(lastJson, null, 2));
  } catch {
    // ignore
  }
});

// modal wiring
$('modalClose').addEventListener('click', () => {
  const m = $('providerModal');
  if (m?.open) m.close();
});

$('providerModal').addEventListener('click', (e) => {
  // click outside the card to close
  const card = document.querySelector('#providerModal .modalCard');
  if (!card) return;
  const r = card.getBoundingClientRect();
  const inCard = e.clientX >= r.left && e.clientX <= r.right && e.clientY >= r.top && e.clientY <= r.bottom;
  if (!inCard) {
    const m = $('providerModal');
    if (m?.open) m.close();
  }
});
