/* Vercel serverless function: save as  api/license.js  in your Vercel project.
 *
 * Environment variables (Vercel -> Project -> Settings -> Environment Variables):
 *   TURSO_URL       libsql://your-db.turso.io
 *   TURSO_TOKEN     a Turso token (a READ-ONLY token is enough and safer)
 *   LICENSE_SECRET  the Master Secret from Licence Portal -> Settings (optional but recommended)
 *   ALLOWED_ORIGIN  e.g. https://yourportal.vercel.app  (optional; default allows any site)
 */
function cyrb53(str, seed) {
  seed = seed || 0;
  var h1 = 0xdeadbeef ^ seed, h2 = 0x41c6ce57 ^ seed;
  for (var i = 0, ch; i < str.length; i++) {
    ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
  h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
  h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return 4294967296 * (2097151 & h2) + (h1 >>> 0);
}

async function turso(sql, args) {
  const host = process.env.TURSO_URL.replace(/^libsql:\/\//, 'https://').replace(/\/+$/, '');
  const r = await fetch(host + '/v2/pipeline', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + process.env.TURSO_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify({ requests: [
      { type: 'execute', stmt: { sql: sql, args: args.map(function (v) { return { type: 'text', value: String(v) }; }) } },
      { type: 'close' }
    ] })
  });
  const j = await r.json();
  const x = j.results && j.results[0];
  if (!r.ok || !x || x.type === 'error') throw new Error('Database error');
  const res = x.response.result;
  return res.rows.map(function (row) {
    const o = {};
    res.cols.forEach(function (c, i) { o[c.name] = row[i].type === 'null' ? null : row[i].value; });
    return o;
  });
}

module.exports = async function (req, res) {
  res.setHeader('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGIN || '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ ok: false, msg: 'Method not allowed' });

  function bad(msg) { return res.status(200).json({ ok: false, msg: msg }); }
  try {
    var b = req.body;
    if (typeof b === 'string') b = JSON.parse(b);
    const key = String((b && b.key) || '').replace(/\D/g, '');
    const p = Number(b && b.p);
    if (key.length !== 16) return bad('Invalid licence key.');

    if (process.env.LICENSE_SECRET) {
      var sig = String(cyrb53(process.env.LICENSE_SECRET + '|' + key.slice(0, 11)) % 100000);
      while (sig.length < 5) sig = '0' + sig;
      if (sig !== key.slice(11)) return bad('Invalid licence key.');
    }

    const rows = await turso('SELECT product_id, client_id, expiry_month, revoked FROM licenses WHERE license_key = ?', [key]);
    if (!rows.length) return bad('Licence not found.');
    const l = rows[0];
    if (Number(l.product_id) !== p) return bad('This key belongs to a different portal.');
    if (l.revoked === '1') return bad('This licence has been revoked.');

    const m = Number(l.expiry_month);
    if (m !== 9999) {
      /* end of the expiry month, 23:59:59 India time (UTC+05:30) */
      const exp = Date.UTC(2024, m + 1, 0, 18, 29, 59);
      if (Date.now() > exp) return bad('Licence expired.');
    }
    return res.status(200).json({ ok: true, c: Number(l.client_id), m: m });
  } catch (e) {
    return res.status(500).json({ ok: false, msg: 'Server error' });
  }
};
