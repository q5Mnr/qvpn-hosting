'use strict';
const crypto = require('crypto');
const fs = require('fs');

const DAY = 86400000;
const LOG_MAX = 5 * 1024 * 1024;
let logFile = null;

/** Дублирует вывод в файл (qvpn.log рядом с программой); файл переписывается, когда вырастает до 5 МБ. */
function setLogFile(file) { logFile = file; }
function fileLog(text) {
  if (!logFile) return;
  try {
    if (fs.existsSync(logFile) && fs.statSync(logFile).size > LOG_MAX) fs.renameSync(logFile, logFile + '.old');
    fs.appendFileSync(logFile, text + '\n');
  } catch { /* лог не должен ломать работу */ }
}

function log(...args) {
  console.log(new Date().toISOString().slice(11, 19), ...args);
}

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));

const randHex = (bytes) => crypto.randomBytes(bytes).toString('hex');

function fmtBytes(n) {
  n = Number(n) || 0;
  const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(n < 10 ? 2 : 1) : String(n)) + ' ' + units[i];
}

function fmtDate(ms, tz) {
  try {
    return new Date(ms).toLocaleString('ru-RU', {
      timeZone: tz, day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit',
    });
  } catch {
    return new Date(ms).toISOString().slice(0, 16).replace('T', ' ');
  }
}

function safeEqual(a, b) {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}

/** Простой ограничитель попыток: не больше `max` за `windowMs` на ключ. */
function limiter(max, windowMs) {
  const hits = new Map();
  return (key) => {
    const now = Date.now();
    const h = hits.get(key);
    if (!h || now - h.t > windowMs) { hits.set(key, { n: 1, t: now }); return true; }
    h.n++;
    if (hits.size > 5000) hits.clear();
    return h.n <= max;
  };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

module.exports = { DAY, log, esc, randHex, fmtBytes, fmtDate, safeEqual, limiter, sleep, setLogFile, fileLog };
