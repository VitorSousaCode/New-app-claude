// Servidor sem dependências (Node 18+).
// BRAPI_TOKEN: token da Brapi (fica só aqui). APP_PASSWORD: senha de acesso ao app.
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const TOKEN = process.env.BRAPI_TOKEN || process.env.BRAPI_API_KEY || '';
const PASS = process.env.APP_PASSWORD || '';
const BASE = process.env.BRAPI_BASE || 'https://brapi.dev/api/v2';
const PORT = process.env.PORT || 3000, TTL = 5 * 60 * 1000, LOCK = 15 * 60 * 1000;
if (!PASS && process.env.ALLOW_NO_PASSWORD !== '1') {
  console.error('Defina APP_PASSWORD (ou ALLOW_NO_PASSWORD=1 só para uso local).');
  process.exit(1);
}
const ROUTES = {
  '/api/quote':        { to: '/stocks/quote',     q: ['symbols'] },
  '/api/dividends':    { to: '/stocks/dividends', q: ['symbols', 'startDate', 'endDate'] },
  '/api/fii-dividends':{ to: '/fii/dividends',    q: ['symbols', 'startDate', 'endDate'] },
  '/api/tickers':      { to: '/tickers',          q: ['search', 'limit'] },
  '/api/crypto':       { to: '/crypto',           q: ['coin'] },
};
const OK = /^[\w.,\- ]{1,200}$/;
const cache = new Map(), fails = new Map();
const h256 = s => crypto.createHash('sha256').update(s).digest();
const send = (res, s, b, h) => {
  res.writeHead(s, Object.assign({ 'Content-Type': 'application/json; charset=utf-8' }, h || {}));
  res.end(b);
};
function authorized(req, res) {
  if (!PASS) return true;
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  const f = fails.get(ip), live = f && Date.now() - f.t < LOCK;
  if (live && f.n >= 10) {
    send(res, 429, '{"error":true,"message":"Muitas tentativas. Aguarde 15 minutos."}', { 'Retry-After': '900' });
    return false;
  }
  const m = /^Basic (.+)$/.exec(req.headers.authorization || '');
  let pw = '';
  if (m) { const s = Buffer.from(m[1], 'base64').toString(); pw = s.slice(s.indexOf(':') + 1); }
  if (m && crypto.timingSafeEqual(h256(pw), h256(PASS))) { fails.delete(ip); return true; }
  if (m) fails.set(ip, { n: (live ? f.n : 0) + 1, t: Date.now() });
  res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="Controle financeiro", charset="UTF-8"', 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Senha necessária');
  return false;
}
http.createServer(async (req, res) => {
  if (!authorized(req, res)) return;
  const url = new URL(req.url, 'http://x');
  if (req.method !== 'GET') return send(res, 405, '{"error":true,"message":"Método não permitido"}');
  if (url.pathname === '/') {
    const f = [path.join(__dirname, 'public', 'index.html'), path.join(__dirname, 'index.html')].find(p => fs.existsSync(p));
    if (!f) return send(res, 500, '{"error":true,"message":"index.html ausente"}');
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(fs.readFileSync(f));
  }
  const r = ROUTES[url.pathname];
  if (!r) return send(res, 404, '{"error":true,"message":"Rota inexistente"}');
  const qs = new URLSearchParams();
  for (const k of r.q) {
    const v = url.searchParams.get(k);
    if (v === null) continue;
    if (!OK.test(v)) return send(res, 400, '{"error":true,"message":"Parâmetro inválido"}');
    qs.set(k, v);
  }
  const target = BASE + r.to + '?' + qs;
  const hit = cache.get(target);
  if (hit && Date.now() - hit.t < TTL) return send(res, 200, hit.body, { 'X-Cache': 'HIT' });
  try {
    const up = await fetch(target, { headers: TOKEN ? { Authorization: 'Bearer ' + TOKEN } : {} });
    const body = await up.text();
    const h = {};
    if (up.status === 429) h['Retry-After'] = up.headers.get('Retry-After') || '60';
    if (up.ok) cache.set(target, { t: Date.now(), body });
    send(res, up.status, body, h);
  } catch (e) {
    send(res, 502, '{"error":true,"message":"Brapi inacessível"}');
  }
}).listen(PORT, () => console.log('Rodando na porta ' + PORT + (TOKEN ? '' : ' (sem BRAPI_TOKEN: só PETR4, VALE3, MGLU3 e ITUB4)')));
