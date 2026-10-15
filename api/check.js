// Vercel serverless function (Node 18+). Deploy next to index.html as api/check.js.
const net = require('net');
const dns = require('dns').promises;

function isPrivate(ip) {
  if (net.isIPv6(ip)) return ip === '::1' || /^(fc|fd|fe80)/i.test(ip) || ip.startsWith('::ffff:');
  const [a, b] = ip.split('.').map(Number);
  return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
}

// Blocks private and local addresses (SSRF) and re-checks every redirect hop.
async function get(href, hops = 0) {
  const url = new URL(href);
  if (!/^https?:$/.test(url.protocol)) throw new Error('Only http and https addresses work');
  const { address } = await dns.lookup(url.hostname);
  if (isPrivate(address)) throw new Error('That address is not allowed');
  const r = await fetch(url, {
    redirect: 'manual',
    signal: AbortSignal.timeout(6000),
    headers: { 'user-agent': 'AICrawlerAccessChecker/1.0' }
  });
  const loc = r.headers.get('location');
  if (r.status >= 300 && r.status < 400 && loc && hops < 3) return get(new URL(loc, url).href, hops + 1);
  return r;
}

const isText = r => r && r.ok && !/html/i.test(r.headers.get('content-type') || '');

module.exports = async (req, res) => {
  if (req.query.ping) return res.json({ ok: true });
  let base;
  try {
    let raw = String(req.query.url || '').trim();
    if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;
    base = new URL(raw);
  } catch {
    return res.status(400).json({ error: 'That is not a valid address' });
  }
  try {
    const origin = base.origin;
    const rr = await get(origin + '/robots.txt');
    const robots = isText(rr) ? (await rr.text()).slice(0, 200000) : '';
    const [llms, sitemap, home] = await Promise.all([
      get(origin + '/llms.txt').catch(() => null),
      get(origin + '/sitemap.xml').catch(() => null),
      get(origin + '/').catch(() => null)
    ]);
    let meta = '';
    if (home) {
      const xr = home.headers.get('x-robots-tag');
      if (xr) meta += 'X-Robots-Tag: ' + xr + '\n';
      if (/html/i.test(home.headers.get('content-type') || '')) {
        const html = (await home.text()).slice(0, 300000);
        (html.match(/<meta[^>]+name=["']robots["'][^>]*>/gi) || []).forEach(m => (meta += m + '\n'));
      }
    }
    res.json({ robots, robotsStatus: rr.status, llms: isText(llms), sitemap: isText(sitemap), meta });
  } catch (e) {
    const m = /ENOTFOUND|EAI_AGAIN/.test(e.message) ? 'We could not find that website. Check the address.'
      : e.name === 'TimeoutError' ? 'The site took too long to respond.'
      : e.message;
    res.status(502).json({ error: m });
  }
};
