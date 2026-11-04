'use strict';
const fs = require('fs');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const { extractFromZip } = require('./xray');

// Статический домен ngrok (бесплатный аккаунт выдаёт один): трафик идёт на порт QVpn.
const DOWNLOAD = 'https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-windows-amd64.zip';

function createNgrok({ dir, port, log, authtoken, domain }) {
  const BIN = path.join(dir, 'bin', 'ngrok.exe');
  let proc = null;
  let stopping = false;

  // Подпись проверяем, а не хеш: официальный агент подписан ngrok, Inc.
  function signedByNgrok() {
    if (!fs.existsSync(BIN)) return false;
    const script = `(Get-AuthenticodeSignature -LiteralPath '${BIN.replace(/'/g, "''")}').SignerCertificate.Subject`;
    const r = spawnSync('powershell', ['-NoProfile', '-Command', script], { encoding: 'utf8', windowsHide: true });
    return /ngrok/i.test(String(r.stdout || ''));
  }

  async function ensure() {
    if (signedByNgrok()) return;
    log('Скачиваю ngrok…');
    const res = await fetch(DOWNLOAD, { redirect: 'follow', signal: AbortSignal.timeout(120000) });
    if (!res.ok) throw new Error(`не удалось скачать ngrok: HTTP ${res.status}`);
    const zip = Buffer.from(await res.arrayBuffer());
    fs.mkdirSync(path.dirname(BIN), { recursive: true });
    fs.writeFileSync(BIN + '.tmp', extractFromZip(zip, 'ngrok.exe'));
    fs.renameSync(BIN + '.tmp', BIN);
    if (!signedByNgrok()) {
      throw new Error('ngrok.exe не прошёл проверку подписи (возможно, его удалил антивирус: разрешите ngrok в Защитнике Windows и перезапустите QVpn)');
    }
    log('ngrok готов.');
  }

  function start() {
    if (stopping || proc || !fs.existsSync(BIN)) return;
    const p = spawn(BIN, ['http', `localhost:${port}`, '--url', `https://${domain}`, '--log', 'stdout'], {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      env: { ...process.env, NGROK_AUTHTOKEN: authtoken },
    });
    proc = p;
    let announced = false;
    const scan = (chunk) => {
      const text = String(chunk);
      if (!announced && /started tunnel/.test(text)) { announced = true; log(`ngrok: туннель поднят, адрес https://${domain}`); }
      if (/ERR_NGROK|authentication failed|invalid/i.test(text)) log('ngrok:', text.trim().slice(0, 300));
    };
    p.stdout.on('data', scan);
    p.stderr.on('data', scan);
    p.on('error', (e) => log('ngrok: не удалось запустить:', e.message));
    p.on('exit', (code) => {
      if (proc === p) proc = null;
      if (stopping) return;
      log(`ngrok остановился (code=${code}), перезапуск через 5 с…`);
      setTimeout(start, 5000);
    });
  }

  function stop() {
    stopping = true;
    if (proc) proc.kill();
  }

  return { ensure, start, stop };
}

module.exports = { createNgrok };
