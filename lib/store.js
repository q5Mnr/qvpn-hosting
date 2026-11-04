'use strict';
const fs = require('fs');
const crypto = require('crypto');
const { DAY, randHex } = require('./util');

/*
 * Хранилище в data.json:
 *   meta   — служебные ключи (путь туннеля, ключ сессий, последний известный домен)
 *   admins — Telegram-администраторы [{ tgId, name }]
 *   users  — пользователи VPN
 *
 * status пользователя: pending | active | rejected | disabled
 * Итоговое состояние (userState) дополнительно учитывает срок и лимит: expired | limit.
 */
class Store {
  constructor(file) {
    this.file = file;
    let data = {};
    try {
      data = JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
    } catch (e) {
      if (e.code !== 'ENOENT') throw new Error(`data.json повреждён (${e.message}). Восстанови его из data.json.bak или удали.`);
    }
    this.data = { meta: data.meta || {}, admins: data.admins || [], users: data.users || [] };
    this.timer = null;
  }

  get meta() { return this.data.meta; }
  get users() { return this.data.users; }
  get admins() { return this.data.admins; }

  save() {
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.flush(), 300);
  }

  flush() {
    clearTimeout(this.timer);
    const tmp = this.file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(this.data, null, 1));
    try { fs.copyFileSync(this.file, this.file + '.bak'); } catch { /* первого файла ещё нет */ }
    fs.renameSync(tmp, this.file);
  }

  user(id) { return this.users.find((u) => u.id === id); }
  byToken(token) { return token ? this.users.find((u) => u.token === token) : undefined; }
  byTg(tgId) { return this.users.find((u) => u.tgId === tgId); }

  createUser(fields = {}) {
    const u = {
      id: randHex(4),
      uuid: crypto.randomUUID(),
      token: randHex(12),
      name: 'Без имени',
      tgId: null,
      tgUsername: null,
      status: 'pending',
      createdAt: Date.now(),
      approvedAt: null,
      expiresAt: null,
      limitBytes: 0,
      up: 0,
      down: 0,
      renewRequested: false,
      lastRequestAt: null,
      warned: false,
      live: false,
      ...fields,
    };
    while (this.users.some((x) => x.id === u.id)) u.id = randHex(4);
    this.users.push(u);
    this.save();
    return u;
  }

  removeUser(id) {
    const i = this.users.findIndex((u) => u.id === id);
    if (i >= 0) { this.users.splice(i, 1); this.save(); }
  }

  isAdmin(tgId) { return this.admins.some((a) => a.tgId === tgId); }
}

function userState(u, now = Date.now()) {
  if (u.status === 'pending' || u.status === 'rejected' || u.status === 'disabled') return u.status;
  if (u.expiresAt && u.expiresAt <= now) return 'expired';
  if (u.limitBytes && (u.up || 0) + (u.down || 0) >= u.limitBytes) return 'limit';
  return 'active';
}

const isEnabled = (u) => userState(u) === 'active';

/** Выдать или продлить доступ на days дней (0 — бессрочно). Продление идёт от текущей даты окончания. */
function grant(u, days) {
  const now = Date.now();
  const stillValid = u.status === 'active' && u.expiresAt && u.expiresAt > now;
  const base = stillValid ? u.expiresAt : now;
  u.expiresAt = days ? base + days * DAY : null;
  // лимит исчерпан (статус при этом может остаться active) — новый период начинается с нуля
  if (u.limitBytes && u.up + u.down >= u.limitBytes) { u.up = 0; u.down = 0; }
  u.status = 'active';
  u.approvedAt = u.approvedAt || now;
  u.renewRequested = false;
  u.warned = false;
}

const STATE_LABEL = {
  active: 'активна', pending: 'ждёт одобрения', rejected: 'отклонена',
  disabled: 'отключена', expired: 'истекла', limit: 'лимит исчерпан',
};

module.exports = { Store, userState, isEnabled, grant, STATE_LABEL };
