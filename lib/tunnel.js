'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

// Публичный HTTPS-адрес для exe на ПК: исходящий туннель Cloudflare, порты открывать не нужно.
const VERSION = '2026.10.7';
const ASSET = { file: 'cloudflared-windows-amd64.exe', sha256: '2493dbc168923bb3e59e5e7716f71deced92992eea9acd6e9d74f84ac7751343' };
const URL_RE = /https:\/\/[a-z0-9-]+\.trycloudflare\.com/;

// tunnelToken задан — именованный туннель Cloudflare с постоянным доменом; иначе случайный адрес trycloudflare.com
function createTunnel({ dir, port, log, onUrl, token = '' }) {
  const BIN = path.join(dir, 'bin', 'cloudflared.exe');
  let proc = null;
  let stopping = false;

  async function ensure() {
    if (fs.existsSync(BIN)) return;
    const url = `https://github.com/cloudflare/cloudflared/releases/download/${VERSION}/${ASSET.file}`;
    log(`Скачиваю cloudflared ${VERSION}…`);
    const res = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(120000) });
    if (!res.ok) throw new Error(`не удалось скачать cloudflared: HTTP ${res.status}`);
    const buf = Buffer.from(await res.arrayBuffer());
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    if (hash !== ASSET.sha256) throw new Error(`SHA-256 cloudflared не совпал (${hash}) — скачивание прервано`);
    fs.mkdirSync(path.dirname(BIN), { recursive: true });
    fs.writeFileSync(BIN + '.tmp', buf);
    fs.renameSync(BIN + '.tmp', BIN);
    log('cloudflared готов.');
  }

  function start() {
    if (stopping || proc || !fs.existsSync(BIN)) return;
    // HTTP/2 вместо QUIC (QUIC часто режется провайдерами); несколько соединений — чтобы один обрыв не клал туннель
    const common = ['tunnel', '--no-autoupdate', '--protocol', 'http2', '--ha-connections', '4'];
    const args = token
      ? [...common, 'run', '--token', token]
      : [...common, '--url', `http://localhost:${port}`];
    const p = spawn(BIN, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    proc = p;
    let announced = false;
    const scan = (chunk) => {
      if (announced || token) return;
      const m = URL_RE.exec(String(chunk));
      if (m) { announced = true; onUrl(m[0]); }
    };
    p.stdout.on('data', scan);
    p.stderr.on('data', scan);
    p.on('error', (e) => log('Туннель: не удалось запустить:', e.message));
    p.on('exit', (code) => {
      if (proc === p) proc = null;
      if (stopping) return;
      log(`Туннель остановился (code=${code}), перезапуск через 5 с…`);
      setTimeout(start, 5000);
    });
  }

  function stop() {
    stopping = true;
    if (proc) proc.kill();
  }

  return { ensure, start, stop };
}

module.exports = { createTunnel };
