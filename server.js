import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dns from 'dns/promises';
import tls from 'tls';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.disable('x-powered-by');

const PORT = Number(process.env.PORT || 5050);
const PUBLIC_DIR = path.join(__dirname, 'public');

// Minimal security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader(
    'Permissions-Policy',
    [
      'camera=()',
      'microphone=()',
      'geolocation=()',
      'payment=()',
      'usb=()',
      'xr-spatial-tracking=()',
      'display-capture=()',
      'fullscreen=(self)',
    ].join(', '),
  );
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "base-uri 'self'",
      "object-src 'none'",
      "frame-ancestors 'none'",
      "form-action 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self' data:",
      "connect-src 'self'",
      'upgrade-insecure-requests',
    ].join('; '),
  );
  next();
});

app.use('/assets', express.static(PUBLIC_DIR, { maxAge: 0 }));

function nowIso() {
  return new Date().toISOString();
}

function normaliseDomain(input) {
  const s = String(input || '').trim();
  if (!s) return '';
  const clean = s
    .replace(/^https?:\/\//i, '')
    .replace(/\/.*/, '')
    .replace(/^\.+/, '')
    .replace(/\.$/, '')
    .toLowerCase();
  // basic sanity
  if (!/^[a-z0-9.-]+$/.test(clean)) return '';
  if (!clean.includes('.')) return '';
  return clean;
}

async function safe(fn) {
  try {
    return await fn();
  } catch {
    return null;
  }
}

function uniq(arr) {
  return Array.from(new Set((arr || []).filter(Boolean)));
}

function detectMxProvider(mx) {
  const hosts = (mx || []).map(r => (r.exchange || '').toLowerCase());
  const h = hosts.join(' ');
  if (h.includes('google.com') || h.includes('googlemail.com')) return 'Google Workspace';
  if (h.includes('outlook.com') || h.includes('protection.outlook.com')) return 'Microsoft 365 (Exchange Online)';
  if (h.includes('pphosted.com') || h.includes('proofpoint.com')) return 'Proofpoint';
  if (h.includes('mimecast.com')) return 'Mimecast';
  if (h.includes('mailgun.org')) return 'Mailgun';
  if (h.includes('sendgrid.net')) return 'SendGrid';
  if (h.includes('amazonses.com')) return 'Amazon SES';
  return hosts.length ? 'Unknown' : null;
}

function spfIncludes(txts) {
  const spf = (txts || []).find(t => /^v=spf1\b/i.test(t));
  if (!spf) return { spf: null, includes: [] };
  const includes = [];
  for (const part of spf.split(/\s+/)) {
    const m = part.match(/^(?:include:)(.+)$/i);
    if (m) includes.push(m[1]);
  }
  return { spf, includes: uniq(includes) };
}

function classifyFindings({ dnsData, httpData, tlsData, email }) {
  const findings = [];
  const push = (kind, value, confidence, evidence) => {
    findings.push({ kind, value, confidence, evidence });
  };

  const ns = (dnsData.ns || []).join(' ').toLowerCase();
  if (ns.includes('cloudflare.com')) push('dns', 'Cloudflare DNS', 0.9, { ns: dnsData.ns });
  if (ns.includes('awsdns-') || ns.includes('amazonaws.com')) push('dns', 'AWS Route 53', 0.8, { ns: dnsData.ns });
  if (ns.includes('azure-dns') || ns.includes('azuredns')) push('dns', 'Azure DNS', 0.8, { ns: dnsData.ns });

  const cn = (dnsData.cname || []).join(' ').toLowerCase();
  if (cn.includes('cloudfront.net')) push('edge', 'Amazon CloudFront', 0.85, { cname: dnsData.cname });
  if (cn.includes('fastly.net')) push('edge', 'Fastly', 0.85, { cname: dnsData.cname });
  if (cn.includes('akamaiedge.net') || cn.includes('akamai')) push('edge', 'Akamai', 0.75, { cname: dnsData.cname });
  if (cn.includes('azureedge.net') || cn.includes('trafficmanager.net')) push('edge', 'Azure Front Door / CDN', 0.75, { cname: dnsData.cname });

  if (email?.mxProvider) push('email', email.mxProvider, email.mxProvider === 'Unknown' ? 0.4 : 0.9, { mx: dnsData.mx });

  const server = httpData?.https?.headers?.server;
  const via = httpData?.https?.headers?.via;
  if (server) push('http', `server=${server}`, 0.4, { server });
  if (via) push('http', `via=${via}`, 0.4, { via });

  const issuer = tlsData?.issuer || '';
  if (issuer.toLowerCase().includes('let\'s encrypt')) push('tls', "Let's Encrypt", 0.7, { issuer });

  return findings;
}

async function fetchHttps(domain) {
  const url = `https://${domain}/`;
  const out = { url, ok: false, status: null, headers: {}, finalUrl: null };
  try {
    const r = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      headers: { 'user-agent': 'antdev-discovery/0.1 (+https://antdev.uk)' },
    });
    out.ok = r.ok;
    out.status = `${r.status}`;
    out.finalUrl = r.url;
    const h = {};
    for (const [k, v] of r.headers.entries()) h[k.toLowerCase()] = v;
    out.headers = h;
    // drain body
    await r.arrayBuffer().catch(() => null);
  } catch (e) {
    out.error = String(e?.message || e);
  }
  return out;
}

async function getTlsCert(domain) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: domain, port: 443, servername: domain, timeout: 8000 }, () => {
      const cert = socket.getPeerCertificate(true);
      socket.end();
      if (!cert || !cert.subject) return resolve(null);
      const issuer = cert.issuer ? Object.entries(cert.issuer).map(([k, v]) => `${k}=${v}`).join(', ') : null;
      const subject = cert.subject ? Object.entries(cert.subject).map(([k, v]) => `${k}=${v}`).join(', ') : null;
      const sans = cert.subjectaltname
        ? cert.subjectaltname.split(/\s*,\s*/).map(x => x.replace(/^DNS:/, '').trim())
        : [];
      resolve({
        issuer,
        subject,
        valid_from: cert.valid_from,
        valid_to: cert.valid_to,
        sans,
      });
    });
    socket.on('error', () => resolve(null));
    socket.on('timeout', () => {
      socket.destroy();
      resolve(null);
    });
  });
}

async function rdapLookup(ip) {
  const url = `https://rdap.org/ip/${encodeURIComponent(ip)}`;
  try {
    const r = await fetch(url, { headers: { 'user-agent': 'antdev-discovery/0.1' } });
    if (!r.ok) return null;
    const j = await r.json();
    return {
      ip,
      name: j?.name || j?.handle || null,
      handle: j?.handle || null,
      startAddress: j?.startAddress || null,
      endAddress: j?.endAddress || null,
      country: j?.country || null,
    };
  } catch {
    return null;
  }
}

async function discover(domain) {
  const dnsData = {
    ns: await safe(() => dns.resolveNs(domain)) || [],
    soa: await safe(() => dns.resolveSoa(domain).then(x => `${x.nsname} ${x.hostmaster}`)) || null,
    a: await safe(() => dns.resolve4(domain)) || [],
    aaaa: await safe(() => dns.resolve6(domain)) || [],
    cname: await safe(() => dns.resolveCname(domain)) || [],
    mx: await safe(() => dns.resolveMx(domain)) || [],
    txt: await safe(() => dns.resolveTxt(domain).then(rows => rows.map(r => r.join('')))) || [],
  };

  const dmarc = await safe(() => dns.resolveTxt(`_dmarc.${domain}`).then(rows => rows.map(r => r.join(''))).then(xs => xs[0] || null));

  const email = {
    mxProvider: detectMxProvider(dnsData.mx),
    ...spfIncludes(dnsData.txt),
    dmarc,
  };

  const https = await fetchHttps(domain);
  const tlsData = await getTlsCert(domain);

  const ips = uniq([...(dnsData.a || []), ...(dnsData.aaaa || [])]).slice(0, 4);
  const rdap = [];
  for (const ip of ips) {
    const r = await rdapLookup(ip);
    if (r) rdap.push(r);
  }

  const out = {
    ok: true,
    generatedAt: nowIso(),
    domain,
    dns: {
      ns: dnsData.ns,
      soa: dnsData.soa,
      a: dnsData.a,
      aaaa: dnsData.aaaa,
      cname: dnsData.cname,
      mx: dnsData.mx,
      txt: dnsData.txt,
    },
    email,
    http: {
      https,
    },
    tls: tlsData,
    rdap,
  };

  out.findings = classifyFindings({ dnsData, httpData: out.http, tlsData: out.tls, email: out.email });

  return out;
}

app.get('/api/discover', async (req, res) => {
  const domain = normaliseDomain(req.query.domain);
  if (!domain) return res.status(400).send('Missing/invalid domain');

  try {
    const data = await discover(domain);
    res.json(data);
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e?.message || e), generatedAt: nowIso() });
  }
});

app.get('/', (_req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));

app.listen(PORT, () => {
  console.log(`discovery listening on http://127.0.0.1:${PORT}`);
});
