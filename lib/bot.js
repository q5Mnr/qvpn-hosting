'use strict';
const { userState } = require('./store');
const { DAY, esc, fmtBytes, sleep, limiter } = require('./util');

/*
 * Telegram-бот без зависимостей: long polling через fetch.
 * Пользователь: /start → «Запросить доступ» → ждёт одобрения → получает ссылку.
 * Админ: /admin <пароль> один раз, затем заявки приходят с кнопками.
 */
function createBot(app) {
  const API = process.env.TG_API || 'https://api.telegram.org';
  const pwTries = limiter(5, 10 * 60 * 1000);
  let token = '';
  let me = null;
  let lastError = 'токен не задан';
  let running = false;
  let gen = 0;
  let offset = 0;
  let pollCtrl = null;

  async function call(method, params = {}, timeoutMs = 15000, signal) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    if (signal) signal.addEventListener('abort', () => ctrl.abort(), { once: true });
    try {
      const r = await fetch(`${API}/bot${token}/${method}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(params),
        signal: ctrl.signal,
      });
      let j;
      try { j = await r.json(); } catch { throw new Error('HTTP ' + r.status); }
      if (!j.ok) {
        const e = new Error(j.description || 'HTTP ' + r.status);
        e.code = j.error_code;
        throw e;
      }
      return j.result;
    } finally {
      clearTimeout(t);
    }
  }

  const btn = (text, data) => ({ text, callback_data: data });

  function send(chatId, text, kb) {
    if (!running) return Promise.resolve();
    return call('sendMessage', {
      chat_id: chatId, text, parse_mode: 'HTML', disable_web_page_preview: true,
      ...(kb ? { reply_markup: { inline_keyboard: kb } } : {}),
    }).catch((e) => app.log('Telegram sendMessage:', e.message));
  }

  function edit(msg, text, kb) {
    return call('editMessageText', {
      chat_id: msg.chat.id, message_id: msg.message_id, text, parse_mode: 'HTML', disable_web_page_preview: true,
      reply_markup: { inline_keyboard: kb || [] },
    }).catch((e) => {
      if (!/not modified/i.test(e.message)) app.log('Telegram editMessageText:', e.message);
    });
  }

  // ---------- что видит пользователь ----------
  function view(tgId) {
    const u = app.store.byTg(tgId);
    if (!u) {
      return {
        text: `👋 Привет! Это <b>${esc(app.name())}</b> — приватный VPN.\n\n`
          + 'Доступ выдаётся вручную, после одобрения администратором.',
        kb: [[btn('📝 Запросить доступ', 'req')]],
      };
    }
    const st = userState(u);
    if (st === 'pending') {
      return { text: '⏳ Заявка на рассмотрении. Напишу, как только администратор её одобрит.', kb: [[btn('🔄 Проверить', 'me')]] };
    }
    if (st === 'rejected') {
      const can = Date.now() - (u.lastRequestAt || 0) > DAY;
      return {
        text: '❌ Заявка отклонена.' + (can ? '' : '\nПовторно отправить можно через сутки.'),
        kb: can ? [[btn('📝 Отправить заново', 'req')]] : undefined,
      };
    }
    if (st === 'disabled') return { text: '🚫 Доступ отключён администратором.' };
    if (st === 'expired' || st === 'limit') {
      const head = st === 'expired' ? '⌛ Срок подписки закончился.' : '📦 Лимит трафика исчерпан.';
      return u.renewRequested
        ? { text: head + '\n\n⏳ Запрос на продление отправлен.' }
        : { text: head, kb: [[btn('🔁 Попросить продление', 'renew')]] };
    }
    const sub = app.subUrl(u);
    const page = app.pageUrl(u);
    const used = (u.up || 0) + (u.down || 0);
    let text = `✅ <b>Подписка активна</b>\n`
      + `📍 ${esc(app.location())}\n`
      + `⏳ ${u.expiresAt ? 'до ' + esc(app.fmtDate(u.expiresAt)) : 'бессрочно'}\n`
      + `📊 Трафик: ${fmtBytes(used)}${u.limitBytes ? ' из ' + fmtBytes(u.limitBytes) : ''}`;
    if (sub) {
      text += `\n\n🔗 Ссылка подписки (нажми, чтобы скопировать):\n<code>${esc(sub)}</code>\n\n`
        + 'Подключение: установи <b>Happ</b>, нажми «+» → «Вставить из буфера».';
    } else {
      text += '\n\n⚠️ Адрес сервера пока неизвестен — напиши администратору.';
    }
    const kb = [];
    if (page) kb.push([{ text: '📲 Подключить в Happ', url: page }]);
    kb.push([btn('🔄 Обновить', 'me')]);
    return { text, kb };
  }

  function sendView(tgId, prefix = '') {
    const v = view(tgId);
    return send(tgId, (prefix ? prefix + '\n\n' : '') + v.text, v.kb);
  }

  // ---------- уведомления администраторам ----------
  function adminCard(u, kind) {
    const who = `👤 <b>${esc(u.name)}</b>${u.tgUsername ? ' (@' + esc(u.tgUsername) + ')' : ''}\n🆔 <code>${u.tgId}</code>`;
    if (kind === 'renew') {
      const st = userState(u);
      return `🔁 <b>Просит продление</b>\n${who}\nСейчас: ${st === 'limit' ? 'лимит исчерпан' : 'срок истёк'}`;
    }
    return `🆕 <b>Новая заявка</b>\n${who}`;
  }

  function decisionKb(u) {
    return [
      [btn('✅ 30 дней', `ap:${u.id}:30`), btn('✅ 90 дней', `ap:${u.id}:90`), btn('✅ 365 дней', `ap:${u.id}:365`)],
      [btn('♾ Бессрочно', `ap:${u.id}:0`), btn('❌ Отклонить', `rj:${u.id}`)],
    ];
  }

  function notifyAdmins(u, kind) {
    if (!app.store.admins.length) {
      app.log('⚠️ Заявка пришла, но у бота нет администраторов. Напиши боту: /admin <пароль из config.json>');
      return;
    }
    for (const a of app.store.admins) send(a.tgId, adminCard(u, kind), decisionKb(u));
  }

  // ---------- обработка входящих ----------
  async function onMessage(m) {
    if (!m.from || m.chat.type !== 'private') return;
    const text = (m.text || '').trim();
    const from = m.from;
    const [cmdRaw, ...rest] = text.split(/\s+/);
    const cmd = cmdRaw.toLowerCase().replace(/@\w+$/, '');
    const isAdmin = app.store.isAdmin(from.id);

    if (cmd === '/admin') {
      call('deleteMessage', { chat_id: m.chat.id, message_id: m.message_id }).catch(() => {});
      if (isAdmin) return send(from.id, '👑 Ты уже администратор.\n' + adminHelp());
      if (!pwTries(String(from.id))) return send(from.id, '⛔ Слишком много попыток, попробуй через 10 минут.');
      if (!rest.length || !app.checkPassword(rest.join(' '))) return send(from.id, '❌ Неверный пароль.');
      app.store.admins.push({ tgId: from.id, name: displayName(from) });
      app.store.save();
      app.log(`Telegram: ${displayName(from)} (${from.id}) стал администратором`);
      return send(from.id, '👑 Готово, теперь ты администратор. Заявки будут приходить сюда.\n' + adminHelp());
    }
    if (cmd === '/logout' && isAdmin) {
      app.store.data.admins = app.store.admins.filter((a) => a.tgId !== from.id);
      app.store.save();
      return send(from.id, 'Ты больше не администратор бота.');
    }
    if (cmd === '/users' && isAdmin) return send(from.id, summary());
    if (cmd === '/broadcast' && isAdmin) {
      const body = text.slice(cmdRaw.length).trim();
      if (!body) return send(from.id, 'Напиши так: /broadcast текст сообщения (уйдёт всем пользователям с Telegram). Поддерживаются премиум-эмодзи.');
      if (body.length > 4000) return send(from.id, 'Сообщение длиннее 4000 символов.');
      // Извлекаем custom_emoji (премиум-эмодзи) из исходного сообщения, корректируем смещения
      const bodyStart = text.indexOf(body);
      const emojiEntities = (m.entities || [])
        .filter((e) => e.type === 'custom_emoji' && e.custom_emoji_id)
        .map((e) => ({ type: e.type, offset: e.offset - bodyStart, length: e.length, custom_emoji_id: e.custom_emoji_id }))
        .filter((e) => e.offset >= 0 && e.offset + e.length <= body.length);
      broadcast(from.id, body, emojiEntities);
      return;
    }
    if (cmd === '/broadcaststicker' && isAdmin) {
      const fileId = text.slice(cmdRaw.length).trim();
      if (!fileId) return send(from.id, 'Напиши так: /broadcaststicker <file_id> (file_id стикера из Telegram).');
      broadcastSticker(from.id, fileId);
      return;
    }
    if (cmd === '/id') return send(from.id, `Твой Telegram ID: <code>${from.id}</code>`);
    if (cmd === '/help') {
      return send(from.id, 'Это бот приватного VPN.\n/start — моя подписка\n/id — мой Telegram ID'
        + (isAdmin ? '\n\n' + adminHelp() : ''));
    }
    return sendView(from.id);
  }

  // Рассылка идёт в фоне, чтобы не блокировать приём команд; пауза между сообщениями — из лимитов Telegram
  async function broadcast(adminId, body, entities) {
    const targets = app.store.users.filter((u) => u.tgId);
    let ok = 0;
    let fail = 0;
    const params = { text: body, disable_web_page_preview: true };
    if (entities && entities.length) params.entities = entities;
    for (const u of targets) {
      try {
        await call('sendMessage', { chat_id: u.tgId, ...params });
        ok++;
      } catch {
        fail++;
      }
      await sleep(60);
    }
    await send(adminId, `📣 Рассылка готова: доставлено ${ok}, не доставлено ${fail} (всего получателей ${targets.length}).`);
  }

  async function broadcastSticker(adminId, fileId) {
    const targets = app.store.users.filter((u) => u.tgId);
    let ok = 0;
    let fail = 0;
    for (const u of targets) {
      try {
        await call('sendSticker', { chat_id: u.tgId, sticker: fileId });
        ok++;
      } catch {
        fail++;
      }
      await sleep(60);
    }
    await send(adminId, `📣 Стикер разослан: доставлено ${ok}, не доставлено ${fail} (всего получателей ${targets.length}).`);
  }

  function adminHelp() {
    const host = app.host();
    return 'Команды администратора:\n/users — сводка и заявки\n/broadcast текст — рассылка всем (поддерживаются премиум-эмодзи)\n/broadcaststicker file_id — отправить стикер всем\n/logout — перестать быть админом'
      + (host ? `\n\nПанель: https://${host}/admin` : '');
  }

  function summary() {
    const users = app.store.users;
    const count = (s) => users.filter((u) => userState(u) === s).length;
    const pending = users.filter((u) => u.status === 'pending' || u.renewRequested);
    let t = `📊 <b>${esc(app.name())}</b>\nАктивных: ${count('active')}\nЖдут решения: ${pending.length}\n`
      + `Истекших: ${count('expired') + count('limit')}\nВсего: ${users.length}`;
    if (pending.length) t += '\n\nЗаявки:\n' + pending.slice(0, 20).map((u) => `• ${esc(u.name)}${u.tgUsername ? ' @' + esc(u.tgUsername) : ''}`).join('\n');
    const host = app.host();
    if (host) t += `\n\nПанель: https://${host}/admin`;
    return t;
  }

  async function onCallback(q) {
    const data = q.data || '';
    const from = q.from;
    const answer = (text) => call('answerCallbackQuery', { callback_query_id: q.id, text }).catch(() => {});

    if (data === 'me') {
      const v = view(from.id);
      await edit(q.message, v.text, v.kb);
      return answer();
    }

    if (data === 'req') {
      let u = app.store.byTg(from.id);
      if (u && u.status !== 'rejected') { answer('Заявка уже есть'); }
      else if (u && Date.now() - (u.lastRequestAt || 0) <= DAY) { answer('Повторно можно через сутки'); }
      else {
        if (!u) {
          u = app.store.createUser({ name: displayName(from), tgId: from.id, tgUsername: from.username || null });
        } else {
          u.status = 'pending';
          u.name = displayName(from);
          u.tgUsername = from.username || null;
        }
        u.lastRequestAt = Date.now();
        app.store.save();
        app.log(`Новая заявка: ${u.name} (${from.id})`);
        notifyAdmins(u, 'new');
        answer('Заявка отправлена');
      }
      const v = view(from.id);
      return edit(q.message, v.text, v.kb);
    }

    if (data === 'renew') {
      const u = app.store.byTg(from.id);
      const st = u && userState(u);
      if (u && (st === 'expired' || st === 'limit') && !u.renewRequested) {
        u.renewRequested = true;
        u.lastRequestAt = Date.now();
        app.store.save();
        notifyAdmins(u, 'renew');
        answer('Запрос отправлен');
      } else {
        answer();
      }
      const v = view(from.id);
      return edit(q.message, v.text, v.kb);
    }

    const m = /^(ap|rj):([0-9a-f]+)(?::(\d+))?$/.exec(data);
    if (m) {
      if (!app.store.isAdmin(from.id)) return answer('Только для администратора');
      const u = app.store.user(m[2]);
      if (!u) { await edit(q.message, esc(q.message.text) + '\n\n⚠️ Пользователь удалён'); return answer(); }
      if (!(u.status === 'pending' || u.renewRequested)) {
        await edit(q.message, esc(q.message.text) + '\n\nℹ️ Уже обработано');
        return answer('Уже обработано');
      }
      let result;
      if (m[1] === 'ap') {
        const days = Number(m[3]);
        app.approve(u, days);
        result = `✅ Одобрено: ${days ? days + ' дн.' : 'бессрочно'}`;
      } else {
        app.reject(u);
        result = '❌ Отклонено';
      }
      await edit(q.message, `${esc(q.message.text)}\n\n<b>${result}</b> — ${esc(displayName(from))}`);
      return answer(result);
    }
    return answer();
  }

  function displayName(from) {
    return [from.first_name, from.last_name].filter(Boolean).join(' ').slice(0, 64) || from.username || String(from.id);
  }

  async function loop(myGen, signal) {
    while (running && myGen === gen) {
      try {
        const updates = await call('getUpdates', {
          offset, timeout: 50, allowed_updates: ['message', 'callback_query'],
        }, 65000, signal);
        lastError = null;
        for (const up of updates) {
          offset = up.update_id + 1;
          try {
            if (up.message) await onMessage(up.message);
            else if (up.callback_query) await onCallback(up.callback_query);
          } catch (e) {
            app.log('Telegram: ошибка обработки:', e.message);
          }
        }
      } catch (e) {
        if (!running || myGen !== gen) break;
        lastError = e.message;
        if (e.code === 401) { app.log('Telegram: неверный токен бота'); running = false; break; }
        if (e.code === 409) {
          app.log('Telegram: этот токен уже опрашивает другая программа (или включён webhook) — снимаю webhook');
          await call('deleteWebhook', {}).catch(() => {});
        }
        await sleep(5000);
      }
    }
  }

  async function start() {
    gen++;
    if (pollCtrl) pollCtrl.abort();
    running = false;
    me = null;
    token = app.tgToken();
    if (!token) { lastError = 'токен не задан'; return; }
    const myGen = gen;
    try {
      me = await call('getMe');
    } catch (e) {
      lastError = e.message;
      app.log('Telegram: не удалось подключиться —', e.message);
      if (e.code !== 401) setTimeout(() => { if (myGen === gen) start(); }, 30000);
      return;
    }
    if (myGen !== gen) return;
    running = true;
    lastError = null;
    pollCtrl = new AbortController();
    app.log(`Telegram-бот @${me.username} запущен`);
    if (!app.store.admins.length) app.log(`Чтобы стать админом бота, напиши ему: /admin <пароль>`);
    call('setMyCommands', { commands: [{ command: 'start', description: 'Моя подписка' }, { command: 'help', description: 'Помощь' }] }).catch(() => {});
    loop(myGen, pollCtrl.signal);
  }

  return {
    start,
    stop() { gen++; running = false; if (pollCtrl) pollCtrl.abort(); },
    status: () => ({ running, username: me ? me.username : null, error: running ? null : lastError, admins: app.store.admins }),
    username: () => (me ? me.username : null),
    // уведомления от остального приложения
    approved(u, days) {
      if (!u.tgId) return;
      sendView(u.tgId, days === undefined ? '🎉 Доступ одобрен!' : `🎉 Доступ одобрен${days ? ` на ${days} дн.` : ' бессрочно'}!`);
    },
    rejected(u, wasRenew) { if (u.tgId) send(u.tgId, wasRenew ? '❌ Продление отклонено.' : '❌ Заявка отклонена.'); },
    disabled(u) { if (u.tgId) send(u.tgId, '🚫 Доступ отключён администратором.'); },
    enabled(u) { if (u.tgId) sendView(u.tgId, '✅ Доступ снова включён.'); },
    keyReset(u) { if (u.tgId) sendView(u.tgId, '🔑 Ключ обновлён. Старая ссылка больше не работает — добавь новую в Happ.'); },
    ended(u) { if (u.tgId) sendView(u.tgId); },
    warn(u) { if (u.tgId) send(u.tgId, `⏰ Подписка закончится ${esc(app.fmtDate(u.expiresAt))}. Когда истечёт, здесь появится кнопка продления.`); },
  };
}

module.exports = { createBot };
