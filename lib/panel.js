'use strict';
const crypto = require('crypto');
const { userState, STATE_LABEL } = require('./store');
const { limiter } = require('./util');

/*
 * Админ-панель: /admin (HTML) и /admin/api/* (JSON).
 * Вход по паролю, сессия — подписанная HMAC cookie (HttpOnly, Secure, SameSite=Strict).
 * Все POST требуют заголовок x-panel: 1 — его нельзя отправить с чужого сайта без CORS.
 */
function createPanel(app) {
  const loginIp = limiter(8, 10 * 60 * 1000);
  const loginAll = limiter(40, 10 * 60 * 1000);
  const SESSION_MS = 14 * 86400000;

  const sign = (v) => crypto.createHmac('sha256', app.store.meta.sessionKey + '|' + app.adminPassword()).update(v).digest('hex');

  function makeSession() {
    const exp = String(Date.now() + SESSION_MS);
    return `${exp}.${sign(exp)}`;
  }

  function authed(req) {
    const m = /(?:^|;\s*)lp=([0-9]+)\.([0-9a-f]{64})/.exec(req.headers.cookie || '');
    if (!m || Number(m[1]) < Date.now()) return false;
    const want = Buffer.from(sign(m[1]), 'hex');
    const got = Buffer.from(m[2], 'hex');
    return got.length === want.length && crypto.timingSafeEqual(got, want);
  }

  function json(res, code, obj, extraHeaders = {}) {
    res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extraHeaders });
    res.end(JSON.stringify(obj));
  }

  function readBody(req) {
    return new Promise((resolve, reject) => {
      let size = 0;
      const chunks = [];
      req.on('data', (c) => {
        size += c.length;
        if (size > 32 * 1024) { reject(new Error('слишком большой запрос')); req.destroy(); return; }
        chunks.push(c);
      });
      req.on('end', () => {
        try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); } catch { reject(new Error('неверный JSON')); }
      });
      req.on('error', reject);
    });
  }

  function serializeUser(u, host) {
    return {
      id: u.id, name: u.name, tgId: u.tgId, tgUsername: u.tgUsername, owner: !!u.owner,
      status: u.status, state: userState(u), stateLabel: STATE_LABEL[userState(u)],
      createdAt: u.createdAt, approvedAt: u.approvedAt, expiresAt: u.expiresAt,
      limitBytes: u.limitBytes || 0, up: u.up || 0, down: u.down || 0,
      renewRequested: !!u.renewRequested, note: u.note || '',
      sub: app.subUrl(u, host), page: app.pageUrl(u, host),
    };
  }

  function state(host) {
    const bot = app.bot.status();
    return {
      name: app.name(),
      location: app.location(),
      host,
      exit: app.exitInfo(),
      mem: app.memory(),
      xray: app.xray.status(),
      bot: { running: bot.running, username: bot.username, error: bot.error, admins: bot.admins },
      settings: {
        name: app.cfg.name || '', location: app.cfg.location || '', domain: app.cfg.domain || '',
        timezone: app.cfg.timezone || '',
        tokenSet: !!app.tgToken(), tokenFromEnv: !!process.env.TG_TOKEN,
        passwordFromEnv: !!process.env.ADMIN_PASSWORD,
      },
      users: app.store.users.slice().sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0)).map((u) => serializeUser(u, host)),
    };
  }

  const ACTIONS = {
    approve: (u, b) => app.approve(u, int(b.days)),
    extend: (u, b) => app.approve(u, int(b.days)),
    reject: (u) => app.reject(u),
    disable: (u) => app.disable(u),
    enable: (u) => app.enable(u),
    resetKey: (u) => app.resetKey(u),
    resetTraffic: (u) => { u.up = 0; u.down = 0; app.changed(); },
    limit: (u, b) => { u.limitBytes = Math.max(0, Number(b.gb) || 0) * 1024 ** 3; app.changed(); },
    rename: (u, b) => { u.name = String(b.name || '').trim().slice(0, 64) || u.name; app.changed(); },
    note: (u, b) => { u.note = String(b.note || '').slice(0, 300); app.changed(); },
    setExpiry: (u, b) => {
      const t = b.expiresAt ? Date.parse(b.expiresAt) : null;
      if (b.expiresAt && Number.isNaN(t)) throw new Error('неверная дата');
      u.expiresAt = t;
      u.warned = false;
      app.changed();
    },
    delete: (u) => {
      if (u.owner) throw new Error('владельца удалить нельзя — его можно отключить');
      app.deleteUser(u);
    },
  };

  function int(v) {
    const n = Math.floor(Number(v));
    if (!Number.isFinite(n) || n < 0 || n > 36500) throw new Error('неверное число дней');
    return n;
  }

  async function handle(req, res, url, host) {
    const p = url.pathname;
    if (p === '/admin' || p === '/admin/') {
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-robots-tag': 'noindex',
        'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer',
        'content-security-policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
      });
      res.end(PAGE);
      return;
    }
    if (!p.startsWith('/admin/api/')) { json(res, 404, { error: 'not found' }); return; }
    const route = p.slice('/admin/api/'.length);

    if (req.method === 'POST' && req.headers['x-panel'] !== '1') { json(res, 403, { error: 'forbidden' }); return; }

    try {
      if (route === 'login' && req.method === 'POST') {
        const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
        if (!loginIp(ip) || !loginAll('all')) { json(res, 429, { error: 'Слишком много попыток. Подожди 10 минут.' }); return; }
        const b = await readBody(req);
        if (!app.checkPassword(String(b.password || ''))) { json(res, 401, { error: 'Неверный пароль' }); return; }
        app.log(`Панель: вход с ${ip}`);
        app.rememberHost(app.requestHost(req));
        json(res, 200, { ok: true }, {
          'set-cookie': `lp=${makeSession()}; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_MS / 1000}`,
        });
        return;
      }
      if (route === 'logout' && req.method === 'POST') {
        json(res, 200, { ok: true }, { 'set-cookie': 'lp=; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=0' });
        return;
      }

      if (!authed(req)) { json(res, 401, { error: 'нужен вход' }); return; }

      if (route === 'state' && req.method === 'GET') {
        app.rememberHost(app.requestHost(req));
        json(res, 200, state(app.host()));
        return;
      }

      if (route === 'users' && req.method === 'POST') {
        const b = await readBody(req);
        const u = app.addUser({ name: String(b.name || '').trim().slice(0, 64) || 'Без имени', days: int(b.days), gb: Number(b.gb) || 0 });
        json(res, 200, { ok: true, user: serializeUser(u, host) });
        return;
      }

      if (route === 'action' && req.method === 'POST') {
        const b = await readBody(req);
        const u = app.store.user(String(b.id || ''));
        if (!u) { json(res, 404, { error: 'пользователь не найден' }); return; }
        const fn = ACTIONS[b.action];
        if (!fn) { json(res, 400, { error: 'неизвестное действие' }); return; }
        fn(u, b);
        json(res, 200, { ok: true });
        return;
      }

      if (route === 'admins/remove' && req.method === 'POST') {
        const b = await readBody(req);
        app.store.data.admins = app.store.admins.filter((a) => a.tgId !== Number(b.tgId));
        app.store.save();
        json(res, 200, { ok: true });
        return;
      }

      if (route === 'settings' && req.method === 'POST') {
        const b = await readBody(req);
        const patch = {};
        for (const k of ['name', 'location', 'domain', 'timezone']) {
          if (typeof b[k] === 'string') patch[k] = b[k].trim().slice(0, 100);
        }
        if (patch.timezone) {
          try { new Intl.DateTimeFormat('ru-RU', { timeZone: patch.timezone }); } catch { throw new Error('неизвестный часовой пояс'); }
        }
        if (typeof b.telegramToken === 'string' && b.telegramToken.trim()) {
          const t = b.telegramToken.trim();
          if (!/^\d+:[A-Za-z0-9_-]{30,}$/.test(t)) throw new Error('токен бота выглядит неправильно (формат 123456:ABC…)');
          patch.telegramToken = t;
        }
        if (b.clearToken) patch.telegramToken = '';
        if (typeof b.newPassword === 'string' && b.newPassword) {
          if (b.newPassword.length < 8) throw new Error('пароль — минимум 8 символов');
          patch.adminPassword = b.newPassword;
        }
        app.saveConfig(patch);
        const extra = {};
        if (patch.adminPassword) {
          // старые сессии стали недействительны — сразу выдаём новую текущему админу
          extra['set-cookie'] = `lp=${makeSession()}; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_MS / 1000}`;
        }
        if ('telegramToken' in patch) await app.bot.start();
        json(res, 200, { ok: true }, extra);
        return;
      }

      json(res, 404, { error: 'not found' });
    } catch (e) {
      json(res, 400, { error: e.message });
    }
  }

  return { handle };
}

const PAGE = `<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex"><title>Админ-панель VPN</title>
<style>
:root{--bg:#f4f5f8;--card:#fff;--text:#16181d;--muted:#6b7180;--line:#e3e5ea;--accent:#3b5bfd;--accent-2:#e9edff;
--ok:#14843b;--ok-bg:#e3f6e8;--warn:#a15c00;--warn-bg:#fff2dc;--bad:#c0262d;--bad-bg:#fde7e8;--idle:#5d6370;--idle-bg:#eceef2;
--r:14px;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#181b21;--text:#e9ebf0;--muted:#959cab;--line:#2a2e37;--accent:#7d93ff;--accent-2:#232a48;
--ok:#5fd585;--ok-bg:#163222;--warn:#ffbe5c;--warn-bg:#3a2a10;--bad:#ff7a7f;--bad-bg:#3b1a1c;--idle:#aab0bd;--idle-bg:#262a32;color-scheme:dark}}
*{box-sizing:border-box}html,body{margin:0}body{background:var(--bg);color:var(--text);font:15px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
padding:16px max(16px,env(safe-area-inset-right)) 48px max(16px,env(safe-area-inset-left))}
.wrap{max-width:880px;margin:0 auto}
h1{font-size:20px;margin:0}h2{font-size:15px;margin:28px 0 10px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.top{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:6px}
.sub{color:var(--muted);font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:14px;margin-bottom:10px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:14px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:10px 12px}
.stat b{display:block;font-size:20px;font-variant-numeric:tabular-nums}.stat span{color:var(--muted);font-size:12px}
@media (max-width:560px){.stats{grid-template-columns:repeat(2,1fr)}}
.row{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.grow{flex:1 1 auto;min-width:0}
.name{font-weight:600;overflow-wrap:anywhere}.meta{color:var(--muted);font-size:13px;margin-top:2px;overflow-wrap:anywhere}
.badge{font-size:12px;font-weight:600;padding:2px 8px;border-radius:999px;white-space:nowrap}
.b-active{color:var(--ok);background:var(--ok-bg)}.b-pending{color:var(--warn);background:var(--warn-bg)}
.b-expired,.b-limit,.b-rejected{color:var(--bad);background:var(--bad-bg)}.b-disabled{color:var(--idle);background:var(--idle-bg)}
button,.btn{font:inherit;font-size:14px;border:1px solid var(--line);background:var(--card);color:var(--text);border-radius:10px;padding:7px 12px;cursor:pointer;min-height:36px}
button:hover{border-color:var(--accent)}button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button.danger{color:var(--bad)}button.soft{background:var(--accent-2);border-color:transparent;color:var(--accent)}
button:disabled{opacity:.5;cursor:default}
.actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}
input,select{font:inherit;font-size:16px;padding:8px 10px;border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--text);min-height:40px;width:100%}
label{display:block;font-size:13px;color:var(--muted);margin:10px 0 4px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}@media (max-width:560px){.grid2{grid-template-columns:1fr}}
details{margin-top:8px}summary{cursor:pointer;color:var(--muted);font-size:13px}
.empty{color:var(--muted);text-align:center;padding:18px}
.toast{position:fixed;left:50%;bottom:20px;transform:translateX(-50%);background:var(--text);color:var(--bg);padding:10px 16px;border-radius:12px;font-size:14px;
opacity:0;transition:opacity .2s;pointer-events:none;max-width:calc(100% - 32px);z-index:9}.toast.show{opacity:1}
.login{max-width:360px;margin:12vh auto}.hint{font-size:13px;color:var(--muted)}
.filters{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}.filters button.on{background:var(--accent-2);color:var(--accent);border-color:transparent}
code{font-family:ui-monospace,Menlo,monospace;font-size:12px;background:var(--bg);padding:2px 5px;border-radius:6px;overflow-wrap:anywhere}
.ok{color:var(--ok)}.bad{color:var(--bad)}
</style></head><body><div class="wrap" id="app"></div><div class="toast" id="toast"></div>
<script>
const $ = (s, r = document) => r.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let S = null, filter = 'all', query = '', busy = false;

function toast(t){ const el=$('#toast'); el.textContent=t; el.classList.add('show'); clearTimeout(el._t); el._t=setTimeout(()=>el.classList.remove('show'),2600); }
async function api(path, body){
  const r = await fetch('/admin/api/' + path, { method: body ? 'POST' : 'GET', credentials: 'same-origin',
    headers: { 'x-panel': '1', 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  const j = await r.json().catch(() => ({}));
  if (r.status === 401 && path !== 'login') { S = null; renderLogin(); throw new Error('auth'); }
  if (!r.ok) throw new Error(j.error || ('Ошибка ' + r.status));
  return j;
}
const fmtBytes = (n) => { n = +n || 0; const u = ['Б','КБ','МБ','ГБ','ТБ']; let i = 0; while (n >= 1024 && i < 4) { n /= 1024; i++; } return (i ? n.toFixed(n < 10 ? 2 : 1) : n) + ' ' + u[i]; };
const fmtDate = (ms) => new Date(ms).toLocaleString('ru-RU', { day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit' });
function left(ms){ const d = ms - Date.now(); if (d <= 0) return 'истекла'; const days = Math.floor(d / 864e5); return days >= 1 ? 'ещё ' + days + ' дн.' : 'ещё ' + Math.max(1, Math.round(d / 36e5)) + ' ч.'; }
async function copy(t){ try { await navigator.clipboard.writeText(t); toast('Скопировано'); } catch { prompt('Скопируй ссылку:', t); } }

function renderLogin(err){
  $('#app').innerHTML = '<form class="card login" id="lf"><h1>Вход в панель</h1>'
    + '<label for="pw">Пароль администратора</label><input id="pw" type="password" autocomplete="current-password" required>'
    + '<div class="actions"><button class="primary" type="submit">Войти</button></div>'
    + '<p class="hint">Пароль лежит в <code>config.json</code> (поле <code>adminPassword</code>) и печатается в консоли при первом запуске.</p>'
    + (err ? '<p class="bad">' + esc(err) + '</p>' : '') + '</form>';
  $('#pw').focus();
  $('#lf').onsubmit = async (e) => { e.preventDefault();
    try { await api('login', { password: $('#pw').value }); await load(); } catch (x) { if (x.message !== 'auth') renderLogin(x.message); } };
}

async function load(){ try { S = await api('state'); render(); } catch (e) { if (e.message !== 'auth') toast(e.message); } }

async function act(id, action, extra = {}, confirmText){
  if (confirmText && !confirm(confirmText)) return;
  if (busy) return; busy = true;
  try { await api('action', { id, action, ...extra }); await load(); toast('Готово'); }
  catch (e) { if (e.message !== 'auth') toast(e.message); } finally { busy = false; }
}

function userCard(u, pendingMode){
  const used = u.up + u.down;
  const exp = u.expiresAt ? 'до ' + fmtDate(u.expiresAt) + ' · ' + left(u.expiresAt) : (u.state === 'pending' ? '' : 'бессрочно');
  const tg = u.tgUsername ? '@' + esc(u.tgUsername) : (u.tgId ? 'id ' + u.tgId : 'без Telegram');
  let h = '<div class="card"><div class="row"><div class="grow"><div class="name">' + esc(u.name) + (u.owner ? ' 👑' : '') + '</div>'
    + '<div class="meta">' + tg + (exp ? ' · ' + exp : '') + '</div>'
    + (u.state !== 'pending' ? '<div class="meta">Трафик: ' + fmtBytes(used) + (u.limitBytes ? ' из ' + fmtBytes(u.limitBytes) : '') + '</div>' : '')
    + (u.note ? '<div class="meta">📝 ' + esc(u.note) + '</div>' : '')
    + '</div><span class="badge b-' + u.state + '">' + esc(u.renewRequested ? 'просит продление' : u.stateLabel) + '</span></div>';
  if (pendingMode) {
    h += '<div class="actions">' + [30, 90, 365].map(d => '<button class="primary" data-a="approve" data-days="' + d + '" data-id="' + u.id + '">✅ ' + d + ' дн.</button>').join('')
      + '<button class="soft" data-a="approve" data-days="0" data-id="' + u.id + '">♾ Бессрочно</button>'
      + '<button class="danger" data-a="reject" data-id="' + u.id + '">Отклонить</button></div>';
  } else if (u.state !== 'pending') {
    h += '<div class="actions">'
      + (u.sub ? '<button data-copy="' + esc(u.sub) + '">🔗 Ссылка</button>' : '')
      + '<button data-a="extend" data-days="30" data-id="' + u.id + '">+30 дн.</button>'
      + (u.status === 'disabled' ? '<button data-a="enable" data-id="' + u.id + '">Включить</button>'
        : (u.status === 'active' ? '<button data-a="disable" data-id="' + u.id + '">Отключить</button>' : ''))
      + '</div><details><summary>Ещё</summary><div class="actions">'
      + '<button data-a="extend" data-days="90" data-id="' + u.id + '">+90 дн.</button>'
      + '<button data-a="extend" data-days="365" data-id="' + u.id + '">+365 дн.</button>'
      + '<button data-a="extend" data-days="0" data-id="' + u.id + '">♾ Бессрочно</button>'
      + '<button data-prompt="expiry" data-id="' + u.id + '">📅 Дата окончания</button>'
      + '<button data-prompt="limit" data-id="' + u.id + '">📦 Лимит трафика</button>'
      + '<button data-a="resetTraffic" data-id="' + u.id + '">Обнулить трафик</button>'
      + '<button data-prompt="rename" data-id="' + u.id + '">✏️ Имя</button>'
      + '<button data-prompt="note" data-id="' + u.id + '">📝 Заметка</button>'
      + '<button data-a="resetKey" data-id="' + u.id + '" data-confirm="Выдать новый ключ? Старая ссылка перестанет работать.">🔑 Новый ключ</button>'
      + (u.owner ? '' : '<button class="danger" data-a="delete" data-id="' + u.id + '" data-confirm="Удалить пользователя ' + esc(u.name) + '?">Удалить</button>')
      + (u.page ? '<button data-copy="' + esc(u.page) + '">Страница подключения</button>' : '')
      + '</div></details>';
  }
  return h + '</div>';
}

function render(){
  const users = S.users;
  const pending = users.filter(u => u.status === 'pending' || u.renewRequested);
  const count = (st) => users.filter(u => u.state === st).length;
  const traffic = users.reduce((a, u) => a + u.up + u.down, 0);
  const groups = { all: 'Все', active: 'Активные', ended: 'Истёкшие', disabled: 'Отключённые', rejected: 'Отклонённые' };
  let list = users.filter(u => u.status !== 'pending');
  if (filter === 'active') list = list.filter(u => u.state === 'active');
  if (filter === 'ended') list = list.filter(u => u.state === 'expired' || u.state === 'limit');
  if (filter === 'disabled') list = list.filter(u => u.state === 'disabled');
  if (filter === 'rejected') list = list.filter(u => u.state === 'rejected');
  if (query) { const q = query.toLowerCase(); list = list.filter(u => (u.name + ' ' + (u.tgUsername || '') + ' ' + (u.tgId || '') + ' ' + u.note).toLowerCase().includes(q)); }

  const bot = S.bot;
  const botLine = bot.running ? '<span class="ok">● @' + esc(bot.username) + ' работает</span>' : '<span class="bad">● бот не запущен' + (bot.error ? ': ' + esc(bot.error) : '') + '</span>';
  const exit = S.exit ? esc(S.exit.ip) + (S.exit.country ? ' · ' + esc([S.exit.city, S.exit.country].filter(Boolean).join(', ')) : '') : 'определяется…';

  $('#app').innerHTML =
    '<div class="top"><div><h1>' + esc(S.name) + '</h1><div class="sub">📍 ' + esc(S.location) + ' · Xray ' + (S.xray.running ? '<span class="ok">работает</span>' : '<span class="bad">остановлен</span>')
    + (S.mem ? ' · память ' + (S.mem.max ? '<span class="' + (S.mem.used / S.mem.max > 0.85 ? 'bad' : '') + '">' + fmtBytes(S.mem.used) + ' из ' + fmtBytes(S.mem.max) + '</span>' : fmtBytes(S.mem.used)) : '') + '</div></div>'
    + '<button id="logout">Выйти</button></div>'
    + '<div class="stats"><div class="stat"><b>' + count('active') + '</b><span>активных</span></div>'
    + '<div class="stat"><b>' + pending.length + '</b><span>ждут решения</span></div>'
    + '<div class="stat"><b>' + users.length + '</b><span>всего</span></div>'
    + '<div class="stat"><b>' + fmtBytes(traffic) + '</b><span>трафик</span></div></div>'
    + (pending.length ? '<h2>Заявки</h2>' + pending.map(u => userCard(u, true)).join('') : '')
    + '<h2>Пользователи</h2><div class="filters">' + Object.entries(groups).map(([k, v]) => '<button data-f="' + k + '" class="' + (filter === k ? 'on' : '') + '">' + v + '</button>').join('')
    + '</div><input id="q" placeholder="Поиск по имени, @нику, заметке" value="' + esc(query) + '" style="margin-bottom:10px">'
    + (list.length ? list.map(u => userCard(u, false)).join('') : '<div class="card empty">Никого нет</div>')
    + '<h2>Добавить вручную</h2><form class="card" id="addf"><div class="grid2"><div><label for="an">Имя</label><input id="an" required maxlength="64" placeholder="Например, Мама"></div>'
    + '<div><label for="ad">Срок</label><select id="ad"><option value="30">30 дней</option><option value="90">90 дней</option><option value="365">365 дней</option><option value="0">Бессрочно</option></select></div></div>'
    + '<label for="ag">Лимит трафика, ГБ (0 — без лимита)</label><input id="ag" type="number" min="0" step="1" value="0">'
    + '<div class="actions"><button class="primary" type="submit">Создать и скопировать ссылку</button></div></form>'
    + '<h2>Telegram-бот</h2><div class="card"><div>' + botLine + '</div>'
    + '<div class="meta" style="margin-top:6px">Админы бота: ' + (bot.admins.length ? bot.admins.map(a => esc(a.name) + ' <button data-rmadmin="' + a.tgId + '" style="min-height:28px;padding:2px 8px">×</button>').join(' ') : 'нет — напиши боту <code>/admin пароль</code>') + '</div>'
    + '<label for="tt">Токен бота от @BotFather' + (S.settings.tokenFromEnv ? ' (задан переменной TG_TOKEN)' : '') + '</label>'
    + '<input id="tt" type="password" autocomplete="off" placeholder="' + (S.settings.tokenSet ? 'задан — введи новый, чтобы заменить' : '123456789:AA…') + '"' + (S.settings.tokenFromEnv ? ' disabled' : '') + '>'
    + '<div class="actions"><button class="primary" id="savetok"' + (S.settings.tokenFromEnv ? ' disabled' : '') + '>Сохранить токен</button></div></div>'
    + '<h2>Настройки</h2><form class="card" id="setf"><div class="grid2">'
    + '<div><label for="sn">Название VPN (заголовок в Happ)</label><input id="sn" maxlength="100" value="' + esc(S.settings.name) + '" placeholder="' + esc(S.name) + '"></div>'
    + '<div><label for="sl">Название локации (имя сервера в Happ)</label><input id="sl" maxlength="100" value="' + esc(S.settings.location) + '" placeholder="' + esc(S.location) + '"></div>'
    + '<div><label for="sd">Домен (пусто — определяется сам)</label><input id="sd" maxlength="100" value="' + esc(S.settings.domain) + '" placeholder="' + esc(S.host || 'xxxx.apps.bot-hosting.cloud') + '"></div>'
    + '<div><label for="sz">Часовой пояс для бота</label><input id="sz" maxlength="60" value="' + esc(S.settings.timezone) + '" placeholder="Europe/Moscow"></div></div>'
    + '<label for="sp">Новый пароль панели' + (S.settings.passwordFromEnv ? ' (задан переменной ADMIN_PASSWORD)' : '') + '</label><input id="sp" type="password" autocomplete="new-password" minlength="8" placeholder="оставь пустым, чтобы не менять"' + (S.settings.passwordFromEnv ? ' disabled' : '') + '>'
    + '<div class="actions"><button class="primary" type="submit">Сохранить</button></div>'
    + '<p class="hint">Реальный внешний IP сервера: ' + exit + '</p></form>';

  $('#logout').onclick = async () => { await api('logout', {}).catch(() => {}); renderLogin(); };
  $('#q').oninput = (e) => { query = e.target.value; const pos = e.target.selectionStart; render(); const q = $('#q'); q.focus(); q.setSelectionRange(pos, pos); };
  document.querySelectorAll('[data-f]').forEach(b => b.onclick = () => { filter = b.dataset.f; render(); });
  document.querySelectorAll('[data-copy]').forEach(b => b.onclick = () => copy(b.dataset.copy));
  document.querySelectorAll('[data-a]').forEach(b => b.onclick = () => act(b.dataset.id, b.dataset.a, { days: b.dataset.days }, b.dataset.confirm));
  document.querySelectorAll('[data-rmadmin]').forEach(b => b.onclick = async () => { if (!confirm('Убрать этого админа бота?')) return; await api('admins/remove', { tgId: b.dataset.rmadmin }); load(); });
  document.querySelectorAll('[data-prompt]').forEach(b => b.onclick = () => {
    const u = S.users.find(x => x.id === b.dataset.id); const kind = b.dataset.prompt;
    if (kind === 'limit') { const v = prompt('Лимит трафика в ГБ (0 — без лимита):', u.limitBytes ? Math.round(u.limitBytes / 1073741824) : 0); if (v !== null) act(u.id, 'limit', { gb: v }); }
    if (kind === 'rename') { const v = prompt('Имя:', u.name); if (v) act(u.id, 'rename', { name: v }); }
    if (kind === 'note') { const v = prompt('Заметка (видишь только ты):', u.note); if (v !== null) act(u.id, 'note', { note: v }); }
    if (kind === 'expiry') {
      const cur = u.expiresAt ? new Date(u.expiresAt) : new Date(Date.now() + 30 * 864e5);
      const v = prompt('Дата окончания в формате ГГГГ-ММ-ДД (пусто — бессрочно):', cur.toISOString().slice(0, 10));
      if (v !== null) act(u.id, 'setExpiry', { expiresAt: v.trim() ? v.trim() + 'T23:59:59' : '' });
    }
  });
  $('#addf').onsubmit = async (e) => { e.preventDefault();
    try { const r = await api('users', { name: $('#an').value, days: $('#ad').value, gb: $('#ag').value }); await load(); if (r.user.sub) copy(r.user.sub); else toast('Создан'); }
    catch (x) { if (x.message !== 'auth') toast(x.message); } };
  $('#savetok').onclick = async () => { const t = $('#tt').value.trim(); if (!t) return toast('Вставь токен');
    try { await api('settings', { telegramToken: t }); toast('Токен сохранён, бот перезапущен'); await load(); } catch (x) { if (x.message !== 'auth') toast(x.message); } };
  $('#setf').onsubmit = async (e) => { e.preventDefault();
    const body = { name: $('#sn').value, location: $('#sl').value, domain: $('#sd').value, timezone: $('#sz').value };
    if ($('#sp').value) body.newPassword = $('#sp').value;
    try { await api('settings', body); toast('Сохранено'); await load(); } catch (x) { if (x.message !== 'auth') toast(x.message); } };
}

setInterval(() => { if (S && !document.hidden && !busy && !document.activeElement.matches('input,select')) load(); }, 20000);
load();
</script></body></html>`;

module.exports = { createPanel };
