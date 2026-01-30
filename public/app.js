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

function render(data){
  lastJson = data;
  $('copyJson').disabled = false;

  const findings = (data.findings || []).map(f => tag(f.kind, `${f.value} (${Math.round((f.confidence||0)*100)}%)`)).join('');

  const dns = renderSection('DNS overview', [
    { k: 'Domain', v: `<span class="mono">${escapeHtml(data.domain)}</span>` },
    { k: 'NS', v: (data.dns?.ns||[]).map(x=>`<span class="mono">${escapeHtml(x)}</span>`).join('<br>') || '—' },
    { k: 'SOA', v: data.dns?.soa ? `<span class="mono">${escapeHtml(data.dns.soa)}</span>` : '—' },
    { k: 'A / AAAA', v: [...(data.dns?.a||[]), ...(data.dns?.aaaa||[])].map(x=>`<span class="mono">${escapeHtml(x)}</span>`).join('<br>') || '—' },
    { k: 'CNAME', v: (data.dns?.cname||[]).map(x=>`<span class="mono">${escapeHtml(x)}</span>`).join('<br>') || '—' },
    { k: 'MX', v: (data.dns?.mx||[]).map(x=>`<span class="mono">${escapeHtml(x.exchange)}</span> <span class="mono">(prio ${x.priority})</span>`).join('<br>') || '—' },
    { k: 'TXT (SPF/verify)', v: (data.dns?.txt||[]).slice(0,8).map(x=>`<span class="mono">${escapeHtml(x)}</span>`).join('<br>') || '—' },
    { k: 'DMARC', v: data.email?.dmarc ? `<span class="mono">${escapeHtml(data.email.dmarc)}</span>` : '—' },
  ], findings ? `<div style="margin-top:10px">${findings}</div>` : '');

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

  $('out').innerHTML = `<div class="grid">${dns}${http}</div>${email}${rdap}${raw}`;
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
