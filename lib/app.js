'use strict';
/*
 * Приватный VPN (VLESS / Xray) для bot-hosting.net + Telegram-бот + админ-панель.
 *
 *   Интернет ──HTTPS──▶ домен хостинга ──HTTP──▶ этот Node-сервер (PORT)
 *     /<tunnel>/ws        → Xray VLESS + WebSocket
 *     /<tunnel>/xh        → Xray VLESS + XHTTP
 *     /sub/<token>        → подписка пользователя для Happ
 *     /p/<token>          → страница подключения пользователя
 *     /admin              → админ-панель
 *     /<secret>, /<secret>/sub — старые адреса владельца (из первой версии), продолжают работать
 *
 * Состояние хранится в data.json, настройки — в config.json.
 */
const fs = require('fs');
const path = require('path');
const http = require('http');
const net = require('net');
const crypto = require('crypto');

const U = require('./util');
const { Store, userState, isEnabled, grant, STATE_LABEL } = require('./store');
const { createXray, PORTS, PATHS } = require('./xray');
const { createBot } = require('./bot');
const { createPanel } = require('./panel');
const { createTunnel } = require('./tunnel');
const { createNgrok } = require('./ngrok');
const { createTailscale } = require('./tailscale');

// В exe (Node SEA) файлы лежат рядом с программой, в обычном запуске — в корне проекта.
const IS_SEA = (() => { try { return require('node:sea').isSea(); } catch { return false; } })();
const DIR = IS_SEA ? path.dirname(process.execPath) : path.resolve(__dirname, '..');
U.setLogFile(path.join(DIR, 'qvpn.log'));
for (const m of ['log', 'error', 'warn']) {
  const orig = console[m].bind(console);
  console[m] = (...a) => { orig(...a); U.fileLog(a.map(String).join(' ')); };
}
const CONFIG_FILE = path.join(DIR, 'config.json');
const DEFAULT_LOCATION = 'Helsinki, Финляндия';

// ---------- config.json ----------
function readConfigFile() {
  try { return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8').replace(/^\uFEFF/, '')); } catch (e) {
    if (e.code === 'ENOENT') return {};
    throw new Error(`config.json содержит ошибку (${e.message}) — проверь запятые и кавычки`);
  }
}

const cleanDomain = (d) => String(d || '').trim()
  .replace(/^[a-z]+:\/\//i, '').replace(/[/?#].*$/, '').replace(/:\d+$/, '');

function loadConfig() {
  const cfg = readConfigFile();
  let changed = false;
  if (!cfg.secret) { cfg.secret = U.randHex(8); changed = true; }
  if (!/^[A-Za-z0-9_-]{6,64}$/.test(cfg.secret)) throw new Error('secret в config.json: только латиница, цифры, - и _, от 6 символов');
  if (!cfg.adminPassword) {
    cfg.adminPassword = crypto.randomBytes(9).toString('base64url');
    changed = true;
    console.log(`\n  🔑 Пароль админ-панели: ${cfg.adminPassword}\n     (сохранён в config.json → adminPassword)\n`);
  }
  if (!('location' in cfg)) { cfg.location = DEFAULT_LOCATION; changed = true; }
  if (!('telegramToken' in cfg)) { cfg.telegramToken = ''; changed = true; }
  if (!('peers' in cfg)) { cfg.peers = []; changed = true; }
  if (!('peerSecret' in cfg)) { cfg.peerSecret = ''; changed = true; }
  if (changed) fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2) + '\n');
  return cfg;
}

const cfg = loadConfig();
const store = new Store(path.join(DIR, 'data.json'));

// служебные ключи
if (!store.meta.tunnel) store.meta.tunnel = 't' + U.randHex(7);
if (!store.meta.sessionKey) store.meta.sessionKey = U.randHex(32);
// перенос владельца из первой версии: его старый ключ и ссылка продолжают работать
if (!store.users.some((u) => u.owner)) {
  const legacyUuid = /^[0-9a-f-]{36}$/i.test(cfg.uuid || '') ? cfg.uuid : crypto.randomUUID();
  store.createUser({ name: 'Владелец', owner: true, status: 'active', uuid: legacyUuid, approvedAt: Date.now() });
}
store.flush();

/** Память всего контейнера (Node + Xray) по cgroup v2 или v1; null, если недоступно. */
function containerMemory() {
  const read = (f) => { try { return fs.readFileSync(f, 'utf8').trim(); } catch { return null; } };
  let used = read('/sys/fs/cgroup/memory.current');
  let max = read('/sys/fs/cgroup/memory.max');
  if (used === null) {
    used = read('/sys/fs/cgroup/memory/memory.usage_in_bytes');
    max = read('/sys/fs/cgroup/memory/memory.limit_in_bytes');
  }
  if (used === null) return null;
  const maxN = Number(max);
  return { used: Number(used), max: Number.isFinite(maxN) && maxN < 2 ** 50 ? maxN : null };
}

const PORT = Number(process.env.PORT || process.env.SERVER_PORT || cfg.port || 8080);
const NO_XRAY = !!process.env.NO_XRAY;
let exitInfo = null;

// ---------- приложение ----------
const app = {
  cfg,
  store,
  log: U.log,
  name: () => process.env.VPN_NAME || cfg.name || 'Scientist VPN',
  location: () => cfg.location || DEFAULT_LOCATION,
  tgToken: () => (process.env.TG_TOKEN || cfg.telegramToken || '').trim(),
  adminPassword: () => process.env.ADMIN_PASSWORD || cfg.adminPassword,
  peers: () => (process.env.PEERS ? process.env.PEERS.split(',').map((s) => s.trim()).filter(Boolean) : (cfg.peers || []).map((s) => String(s).trim()).filter(Boolean)),
  peerSecret: () => (process.env.PEER_SECRET || cfg.peerSecret || '').trim(),
  checkPassword: (p) => !!p && U.safeEqual(p, app.adminPassword()),
  host: () => cleanDomain(process.env.DOMAIN || cfg.domain) || store.meta.lastHost || '',
  fmtDate: (ms) => U.fmtDate(ms, cfg.timezone || 'Europe/Moscow'),
  exitInfo: () => exitInfo,
  memory: containerMemory,
  subUrl: (u, host = app.host()) => (host ? `https://${host}/sub/${u.token}` : ''),
  pageUrl: (u, host = app.host()) => (host ? `https://${host}/p/${u.token}` : ''),
  requestHost,
  /** Запоминает домен только после входа в админку (пароль подтверждает, что запрос от владельца). */
  rememberHost(host) {
    if (host && store.meta.lastHost !== host) { store.meta.lastHost = host; store.save(); }
  },

  saveConfig(patch) {
    const file = readConfigFile();
    Object.assign(file, patch);
    Object.assign(cfg, patch);
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(file, null, 2) + '\n');
  },

  /** Вызывать после любого изменения пользователей: сохраняет и при необходимости перезапускает Xray. */
  changed() { store.save(); syncXray(); },

  addUser({ name, days, gb }) {
    const u = store.createUser({ name, status: 'pending', limitBytes: Math.max(0, gb) * 1024 ** 3 });
    grant(u, days);
    app.changed();
    app.syncUserToPeers(u).catch(() => {});
    U.log(`Панель: создан пользователь ${u.name}`);
    return u;
  },
  approve(u, days) {
    grant(u, days);
    app.changed();
    app.syncUserToPeers(u).catch(() => {});
    U.log(`Одобрено: ${u.name} — ${days ? days + ' дн.' : 'бессрочно'}`);
    bot.approved(u, days);
  },
  reject(u) {
    const wasRenew = u.status === 'active' && u.renewRequested;
    if (wasRenew) u.renewRequested = false; else u.status = 'rejected';
    app.changed();
    bot.rejected(u, wasRenew);
  },
  disable(u) { u.status = 'disabled'; app.changed(); bot.disabled(u); },
  enable(u) {
    u.status = 'active';
    u.approvedAt = u.approvedAt || Date.now();
    app.changed();
    bot.enabled(u);
  },
  resetKey(u) { u.uuid = crypto.randomUUID(); u.token = U.randHex(12); app.changed(); bot.keyReset(u); },
  deleteUser(u) { store.removeUser(u.id); app.changed(); },
  /** Синхронизирует пользователя на peer-серверы (если настроены). */
  async syncUserToPeers(u) {
    const peers = app.peers();
    const secret = app.peerSecret();
    if (!peers.length || !secret) return;
    const body = JSON.stringify({
      secret,
      user: { id: u.id, uuid: u.uuid, token: u.token, name: u.name, tgId: u.tgId, tgUsername: u.tgUsername, status: u.status, expiresAt: u.expiresAt, limitBytes: u.limitBytes, approvedAt: u.approvedAt },
    });
    for (const peer of peers) {
      try {
        const r = await fetch(`${peer}/api/sync-user`, { method: 'POST', headers: { 'content-type': 'application/json' }, body, signal: AbortSignal.timeout(10000) });
        if (r.ok) U.log(`Синхронизировано с ${peer}: ${u.name}`);
        else U.log(`Ошибка синхронизации с ${peer}: HTTP ${r.status}`);
      } catch (e) {
        U.log(`Ошибка синхронизации с ${peer}: ${e.message}`);
      }
    }
  },
};

const xray = createXray({ dir: DIR, log: U.log, disabled: NO_XRAY });
const bot = createBot(app);
app.xray = xray;
app.bot = bot;
const panel = createPanel(app);

// Туннель нужен только exe на ПК: там нет публичного адреса. На хостинге он выключен.
const TUNNEL_TOKEN = (process.env.CF_TUNNEL_TOKEN || cfg.tunnelToken || '').trim();
const NGROK_TOKEN = (process.env.NGROK_AUTHTOKEN || cfg.ngrokToken || '').trim();
const NGROK_DOMAIN = cleanDomain(cfg.domain);
const PROVIDER = (process.env.TUNNEL_PROVIDER || cfg.tunnelProvider || '').trim();

function announce(url) {
  app.rememberHost(url.replace(/^https:\/\//, ''));
  const owner = store.users.find((u) => u.owner);
  U.log(`Публичный адрес: ${url}`);
  if (owner) U.log(`Твоя подписка: ${app.subUrl(owner)}`);
}

const tailscale = PROVIDER === 'tailscale'
  ? createTailscale({ port: PORT, log: U.log, onUrl: announce })
  : null;
const ngrok = !tailscale && NGROK_TOKEN && NGROK_DOMAIN
  ? createNgrok({ dir: DIR, port: PORT, log: U.log, authtoken: NGROK_TOKEN, domain: NGROK_DOMAIN })
  : null;
const tunnel = createTunnel({
  dir: DIR,
  port: PORT,
  log: U.log,
  token: TUNNEL_TOKEN,
  onUrl: announce,
});
const TUNNEL_ON = IS_SEA && process.platform === 'win32' && !process.env.NO_TUNNEL;

function startTunnel() {
  if (tailscale) {
    tailscale.ensure().then(() => tailscale.start()).catch((e) => U.log('Tailscale:', e.message));
    return;
  }
  const active = ngrok || tunnel;
  const tryStart = async () => {
    try {
      await active.ensure();
      active.start();
      const domain = cleanDomain(process.env.DOMAIN || cfg.domain);
      if ((ngrok || TUNNEL_TOKEN) && domain) {
        const owner = store.users.find((u) => u.owner);
        U.log(`Публичный адрес: https://${domain}`);
        if (owner) U.log(`Твоя подписка: ${app.subUrl(owner)}`);
      }
      return true;
    } catch (e) { U.log('Туннель:', e.message); return false; }
  };
  tryStart().then((ok) => {
    if (ok) return;
    U.log('Повторю запуск туннеля через минуту');
    const retry = setInterval(async () => { if (await tryStart()) clearInterval(retry); }, 60000);
  });
}

let lastSig = null;
function syncXray() {
  const active = store.users.filter(isEnabled);
  const sig = active.map((u) => `${u.id}:${u.uuid}`).sort().join(',');
  if (sig === lastSig) return;
  lastSig = sig;
  xray.apply(active);
}

// ---------- ссылки и подписка ----------
/** Домен из заголовков запроса. Его может подставить любой клиент, поэтому сам по себе он не сохраняется. */
function requestHost(req) {
  const raw = String(req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim().replace(/:\d+$/, '');
  const looksPublic = raw.includes('.') && !/^[\d.]+$/.test(raw) && !raw.startsWith('[');
  return looksPublic ? raw : '';
}

/** Домен для ссылок: из настроек, иначе адрес текущего запроса, иначе запомненный (туннель, вход в админку). */
function publicHost(req) {
  return cleanDomain(process.env.DOMAIN || cfg.domain) || requestHost(req) || store.meta.lastHost || '';
}

function makeLinks(u, host) {
  const base = { encryption: 'none', security: 'tls', sni: host, fp: 'chrome', host };
  const tunnel = store.meta.tunnel;
  const ws = new URLSearchParams({ ...base, alpn: 'http/1.1', type: 'ws', path: `/${tunnel}/ws` });
  const xh = new URLSearchParams({ ...base, type: 'xhttp', mode: 'packet-up', path: `/${tunnel}/xh` });
  const loc = app.location();
  // XHTTP первым: WebSocket к зарубежным хостингам часто режут провайдеры
  return [
    `vless://${u.uuid}@${host}:443?${xh}#${encodeURIComponent(loc)}`,
    `vless://${u.uuid}@${host}:443?${ws}#${encodeURIComponent(loc + ' · WS')}`,
  ];
}

async function sendSub(u, req, res) {
  const host = publicHost(req);
  const st = userState(u);
  let links;
  if (st === 'active') {
    links = makeLinks(u, host);
    // Агрегация: добавляем серверы с peer-инстансов
    const peers = app.peers();
    for (const peer of peers) {
      try {
        const peerRes = await fetch(`${peer}/sub/${u.token}`, { signal: AbortSignal.timeout(10000) });
        if (peerRes.ok) {
          const b64 = await peerRes.text();
          const peerLinks = Buffer.from(b64, 'base64').toString('utf8').split('\n').filter((l) => l.startsWith('vless://'));
          for (const link of peerLinks) links.push(link);
        }
      } catch (e) {
        U.log(`Ошибка получения подписки от ${peer}: ${e.message}`);
      }
    }
  } else {
    links = [`vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?encryption=none&type=tcp#${encodeURIComponent('⛔ Подписка ' + STATE_LABEL[st])}`];
  }
  const headers = {
    'content-type': 'text/plain; charset=utf-8',
    'cache-control': 'no-store',
    'profile-title': 'base64:' + Buffer.from(app.name()).toString('base64'),
    'profile-update-interval': '1',
    'subscription-userinfo': `upload=${Math.round(u.up || 0)}; download=${Math.round(u.down || 0)}; total=${Math.round(u.limitBytes || 0)}; expire=${u.expiresAt ? Math.floor(u.expiresAt / 1000) : 0}`,
    'content-disposition': 'attachment; filename="vpn"',
  };
  const botName = bot.username();
  if (botName) headers['support-url'] = `https://t.me/${botName}`;
  res.writeHead(200, headers);
  res.end(Buffer.from(links.join('\n')).toString('base64'));
}

function sendPage(u, req, res) {
  const host = publicHost(req);
  const st = userState(u);
  const esc = U.esc;
  const subUrl = `https://${host}/sub/${u.token}`;
  const used = (u.up || 0) + (u.down || 0);
  const botName = bot.username();
  const body = st === 'active'
    ? `<a class="btn" href="happ://add/${esc(subUrl)}">Добавить в Happ</a>
<p class="note">Если кнопка не сработала, скопируй ссылку ниже и в Happ нажми «+» → «Вставить из буфера».</p>
<h2>Ссылка подписки</h2><textarea readonly>${esc(subUrl)}</textarea>
<button onclick="navigator.clipboard.writeText(this.previousElementSibling.value).then(()=>this.textContent='Скопировано')">Копировать</button>
<p class="note">Нет Happ? Установи его из App Store или Google Play: поиск «Happ Proxy».</p>`
    : `<p>⛔ Подписка ${esc(STATE_LABEL[st])}.</p>${botName ? `<a class="btn" href="https://t.me/${esc(botName)}">Написать в бот</a>` : ''}`;
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-robots-tag': 'noindex', 'referrer-policy': 'no-referrer' });
  res.end(`<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>${esc(app.name())}</title><style>
:root{color-scheme:light dark}body{font:16px/1.5 system-ui,-apple-system,sans-serif;max-width:560px;margin:0 auto;padding:16px}
h1{font-size:22px;margin-bottom:4px}h2{font-size:15px;margin:22px 0 6px}.meta{opacity:.75;font-size:14px;margin:2px 0}
textarea{width:100%;box-sizing:border-box;height:72px;font:12px ui-monospace,monospace;word-break:break-all}
button,.btn{display:inline-block;margin-top:10px;padding:11px 18px;border:0;border-radius:12px;background:#3b5bfd;color:#fff;font:inherit;text-decoration:none;cursor:pointer}
p.note{opacity:.75;font-size:14px}a{color:#3b5bfd}</style></head><body>
<h1>${esc(app.name())}</h1>
<p class="meta">📍 ${esc(app.location())}</p>
<p class="meta">⏳ ${u.expiresAt ? 'до ' + esc(app.fmtDate(u.expiresAt)) : 'бессрочно'} · 📊 ${U.fmtBytes(used)}${u.limitBytes ? ' из ' + U.fmtBytes(u.limitBytes) : ''}</p>
${body}
<p class="note">Не пересылай эту страницу: по ссылке кто угодно сможет пользоваться твоим доступом.</p>
</body></html>`);
}

// ---------- проксирование в Xray ----------
const HOP = new Set(['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te', 'trailer']);
// заголовки прокси хостинга Xray не нужны: из-за них он пишет предупреждение на каждый пакет
const DROP_TO_XRAY = new Set(['x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-host', 'x-real-ip', 'forwarded', 'via']);
const agent = new http.Agent({ keepAlive: true, maxSockets: 512 });

function proxyHttp(req, res, port, upstreamPath) {
  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) if (!HOP.has(k) && !DROP_TO_XRAY.has(k)) headers[k] = v;
  const up = http.request({ host: '127.0.0.1', port, method: req.method, path: upstreamPath, headers, agent }, (ur) => {
    const out = {};
    for (const [k, v] of Object.entries(ur.headers)) if (!HOP.has(k)) out[k] = v;
    out['x-accel-buffering'] = 'no';
    out['cache-control'] = out['cache-control'] || 'no-store';
    res.writeHead(ur.statusCode, out);
    res.flushHeaders();
    ur.pipe(res);
  });
  up.on('error', () => {
    if (!res.headersSent) res.writeHead(502);
    res.end();
  });
  res.on('close', () => up.destroy());
  req.pipe(up);
}

function proxyUpgrade(req, sock, head, port, upstreamPath) {
  const up = net.connect(port, '127.0.0.1', () => {
    let h = `${req.method} ${upstreamPath} HTTP/1.1\r\n`;
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      if (!DROP_TO_XRAY.has(req.rawHeaders[i].toLowerCase())) h += `${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}\r\n`;
    }
    up.write(h + '\r\n');
    if (head && head.length) up.write(head);
    up.pipe(sock);
    sock.pipe(up);
  });
  up.setNoDelay(true);
  sock.setNoDelay(true);
  const kill = () => { up.destroy(); sock.destroy(); };
  up.on('error', kill); sock.on('error', kill);
  up.on('close', kill); sock.on('close', kill);
}

/** '/<tunnel>/xh/abc?x' → '/xh/abc?x' для туннеля и для старого пути владельца. */
function tunnelTarget(url, kind) {
  const q = url.indexOf('?');
  const p = q < 0 ? url : url.slice(0, q);
  const query = q < 0 ? '' : url.slice(q);
  for (const prefix of [store.meta.tunnel, cfg.secret]) {
    const base = `/${prefix}/${kind}`;
    if (p === base || (kind === 'xh' && p.startsWith(base + '/'))) return PATHS[kind] + p.slice(base.length) + query;
  }
  return null;
}

// ---------- HTTP-сервер ----------
const server = http.createServer((req, res) => {
  const rawUrl = req.url || '/';
  const xh = tunnelTarget(rawUrl, 'xh');
  if (xh) return proxyHttp(req, res, PORTS.xh, xh);

  let url;
  try { url = new URL(rawUrl, 'http://local'); } catch { res.writeHead(400); res.end(); return; }
  const p = url.pathname;

  // Синхронизация пользователей между серверами (для объединённой подписки)
  if (p === '/api/sync-user' && req.method === 'POST') {
    let body = '';
    req.on('data', (c) => { body += c; if (body.length > 64 * 1024) req.destroy(); });
    req.on('end', () => {
      try {
        const j = JSON.parse(body || '{}');
        if (!app.peerSecret() || j.secret !== app.peerSecret()) { res.writeHead(403); res.end(); return; }
        const u = j.user;
        if (!u || !u.uuid || !u.token) { res.writeHead(400); res.end(); return; }
        let existing = store.byToken(u.token) || store.users.find((x) => x.uuid === u.uuid);
        if (existing) {
          Object.assign(existing, { name: u.name, tgId: u.tgId, tgUsername: u.tgUsername, status: u.status, expiresAt: u.expiresAt, limitBytes: u.limitBytes, approvedAt: u.approvedAt });
        } else {
          store.createUser({ id: u.id, uuid: u.uuid, token: u.token, name: u.name, tgId: u.tgId, tgUsername: u.tgUsername, status: u.status, expiresAt: u.expiresAt, limitBytes: u.limitBytes, approvedAt: u.approvedAt, live: false });
        }
        store.save();
        syncXray();
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch (e) {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  if (p === '/admin' || p.startsWith('/admin/')) {
    panel.handle(req, res, url, publicHost(req)).catch((e) => { U.log('Панель:', e.message); if (!res.headersSent) res.writeHead(500); res.end(); });
    return;
  }

  let m = /^\/(sub|p)\/([0-9a-f]{24})\/?$/.exec(p);
  if (m) {
    const u = store.byToken(m[2]);
    if (u) return m[1] === 'sub' ? sendSub(u, req, res).catch(() => { if (!res.headersSent) { res.writeHead(500); res.end(); } }) : sendPage(u, req, res);
  }
  // старые адреса владельца из первой версии
  m = new RegExp(`^/${cfg.secret}(/sub)?/?$`).exec(p);
  if (m) {
    const owner = store.users.find((u) => u.owner);
    if (owner) return m[1] ? sendSub(owner, req, res).catch(() => { if (!res.headersSent) { res.writeHead(500); res.end(); } }) : sendPage(owner, req, res);
  }
  res.writeHead(p === '/' ? 200 : 404, { 'content-type': 'text/plain; charset=utf-8' });
  res.end(p === '/' ? 'ok\n' : 'not found\n');
});

server.on('upgrade', (req, sock, head) => {
  const target = tunnelTarget(req.url || '/', 'ws');
  if (target) return proxyUpgrade(req, sock, head, PORTS.ws, target);
  sock.end('HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n');
});
server.requestTimeout = 0;
server.timeout = 0;
server.headersTimeout = 60000;
server.keepAliveTimeout = 75000;

// ---------- фоновые задачи ----------
async function collectStats() {
  const s = await xray.stats();
  if (!s) return;
  let any = false;
  for (const [id, t] of Object.entries(s)) {
    const u = store.user(id);
    if (!u || (!t.up && !t.down)) continue;
    u.up = (u.up || 0) + t.up;
    u.down = (u.down || 0) + t.down;
    any = true;
  }
  if (any) store.save();
}

function checkLifecycle() {
  const now = Date.now();
  for (const u of store.users) {
    const en = isEnabled(u);
    if (en && u.expiresAt && u.expiresAt - now < U.DAY && !u.warned) {
      u.warned = true;
      bot.warn(u);
      store.save();
    }
    if (u.live && !en && ['expired', 'limit'].includes(userState(u))) {
      U.log(`Подписка закончилась: ${u.name} (${userState(u)})`);
      bot.ended(u);
    }
    if (u.live !== en) { u.live = en; store.save(); }
  }
  syncXray();
}

async function detectExit() {
  try {
    const r = await fetch('https://ipinfo.io/json', { signal: AbortSignal.timeout(10000) });
    const j = await r.json();
    exitInfo = { ip: j.ip, city: j.city, country: j.country, org: j.org };
    U.log(`Внешний IP сервера: ${j.ip} (${[j.city, j.country].filter(Boolean).join(', ')}; ${j.org || ''})`);
  } catch {
    // не критично
  }
}

async function ensureXray() {
  try { await xray.ensure(); return true; } catch (e) { U.log('Xray:', e.message); return false; }
}

async function main() {
  // Сервер и панель стартуют даже без Xray, чтобы можно было поправить настройки; Xray догружается в фоне
  if (!(await ensureXray())) {
    U.log('Повторю загрузку Xray через минуту');
    const retry = setInterval(async () => {
      if (!(await ensureXray())) return;
      clearInterval(retry);
      lastSig = null;
      syncXray();
    }, 60000);
  }
  checkLifecycle();
  server.listen(PORT, '0.0.0.0', () => {
    const host = app.host();
    U.log(`Сервер слушает порт ${PORT}`);
    U.log('──────────────────────────────────────────────');
    U.log(`Админ-панель:  https://${host || '<твой-домен>'}/admin`);
    U.log(`Твоя подписка: https://${host || '<твой-домен>'}/${cfg.secret}/sub`);
    U.log(`Локация:       ${app.location()}`);
    if (!app.tgToken()) U.log('Telegram-бот выключен: вставь токен от @BotFather в панели или в config.json → telegramToken');
    U.log('──────────────────────────────────────────────');
  });
  bot.start();
  detectExit();
  if (TUNNEL_ON) startTunnel();
  setInterval(() => collectStats().then(checkLifecycle).catch((e) => U.log('stats:', e.message)), 120000);
}

function shutdown() {
  try { store.flush(); } catch { /* ignore */ }
  bot.stop();
  xray.stop();
  tunnel.stop();
  if (ngrok) ngrok.stop();
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

main().catch((e) => {
  console.error('ОШИБКА:', e.message);
  process.exit(1);
});
