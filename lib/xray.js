'use strict';
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const { spawn, spawnSync, execFile } = require('child_process');

const XRAY_VERSION = 'v26.10.21';
const WIN = process.platform === 'win32';
const ASSETS = WIN
  ? { x64: { file: 'Xray-windows-64.zip', sha256: 'fc58c39ee2f2717b4c54d28d374362389e5319b20ae44aea76ea45a5243ec827' } }
  : {
    x64: { file: 'Xray-linux-64.zip', sha256: '0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978' },
    arm64: { file: 'Xray-linux-arm64-v8a.zip', sha256: 'd1304946c486d98e6b886e9b931eaaaebb23835b30e217638037b7f2721d4e9c' },
  };
// Внутренние адреса Xray: наружу торчит только Node-сервер, он переписывает пути.
const PORTS = { ws: 10001, xh: 10002, api: 10085 };
const PATHS = { ws: '/ws', xh: '/xh' };

function extractFromZip(buf, wanted) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('битый zip: нет EOCD');
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error('битый zip: central directory');
    const method = buf.readUInt16LE(p + 10);
    const compSize = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const local = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);
    if (name === wanted) {
      const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
      const data = buf.subarray(start, start + compSize);
      if (method === 0) return Buffer.from(data);
      if (method === 8) return zlib.inflateRawSync(data);
      throw new Error('zip: неподдерживаемое сжатие ' + method);
    }
    p += 46 + nameLen + extraLen + commentLen;
  }
  throw new Error(`в архиве нет файла ${wanted}`);
}

function createXray({ dir, log, disabled = false }) {
  const BIN = path.join(dir, 'bin', WIN ? 'xray.exe' : 'xray');
  const CONF = path.join(dir, 'bin', 'xray-config.json');
  let proc = null;
  let stopping = false;
  let expectRestart = false;
  let applyTimer = null;
  let startedAt = null;

  function works() {
    if (!fs.existsSync(BIN)) return false;
    try { fs.chmodSync(BIN, 0o755); } catch { /* ignore */ }
    const r = spawnSync(BIN, ['version'], { encoding: 'utf8', timeout: 15000 });
    return r.status === 0 && String(r.stdout).includes(XRAY_VERSION.slice(1));
  }

  async function ensure() {
    if (disabled || works()) return;
    const asset = ASSETS[process.arch];
    if (!asset) throw new Error(`${process.platform}/${process.arch} не поддерживается`);
    const url = `https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${asset.file}`;
    log(`Скачиваю Xray ${XRAY_VERSION} (${asset.file})…`);
    const res = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(120000) });
    if (!res.ok) throw new Error(`не удалось скачать Xray: HTTP ${res.status}`);
    const zip = Buffer.from(await res.arrayBuffer());
    const hash = crypto.createHash('sha256').update(zip).digest('hex');
    if (hash !== asset.sha256) throw new Error(`SHA-256 архива Xray не совпал (${hash}) — скачивание прервано`);
    fs.mkdirSync(path.dirname(BIN), { recursive: true });
    const tmp = BIN + '.tmp';
    fs.writeFileSync(tmp, extractFromZip(zip, WIN ? 'xray.exe' : 'xray'), { mode: 0o755 });
    fs.renameSync(tmp, BIN);
    if (!works()) throw new Error('Xray скачан, но не запускается');
    log('Xray готов.');
  }

  function buildConfig(users) {
    const clients = users.map((u) => ({ id: u.uuid, email: u.id, level: 0 }));
    const settings = { clients, decryption: 'none' };
    const sniffing = { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true };
    return {
      // access: куда и кто подключался (для отладки); файл растёт, его можно удалить
      log: { loglevel: 'warning', access: path.join(dir, 'bin', 'access.log') },
      dns: { servers: ['1.1.1.1', '8.8.8.8', '1.0.0.1'], queryStrategy: 'UseIPv4' },
      api: { tag: 'api', services: ['StatsService'] },
      stats: {},
      // Память — главный ограничитель на бесплатном тарифе (256 МБ на всё):
      // маленький буфер на соединение и быстрое закрытие простаивающих.
      policy: {
        levels: {
          0: {
            statsUserUplink: true, statsUserDownlink: true,
            bufferSize: 256, handshake: 15, connIdle: 120, uplinkOnly: 1, downlinkOnly: 1,
          },
        },
      },
      inbounds: [
        {
          tag: 'api', listen: '127.0.0.1', port: PORTS.api, protocol: 'dokodemo-door', settings: { address: '127.0.0.1' },
        },
        {
          tag: 'vless-ws', listen: '127.0.0.1', port: PORTS.ws, protocol: 'vless', settings,
          streamSettings: { network: 'ws', wsSettings: { path: PATHS.ws } }, sniffing,
        },
        {
          tag: 'vless-xhttp', listen: '127.0.0.1', port: PORTS.xh, protocol: 'vless', settings,
          streamSettings: {
            network: 'xhttp',
            // по умолчанию сервер копит до 30 POST-пакетов по 1 МБ на каждую сессию — на спидтесте это сотни МБ
            xhttpSettings: { path: PATHS.xh, mode: 'auto', scMaxBufferedPosts: 16, scMaxEachPostBytes: 500000 },
          },
          sniffing,
        },
      ],
      outbounds: [
        { tag: 'direct', protocol: 'freedom' },
        { tag: 'block', protocol: 'blackhole' },
      ],
      routing: {
        domainStrategy: 'IPIfNonMatch',
        rules: [
          { type: 'field', inboundTag: ['api'], outboundTag: 'api' },
          // не пускаем через VPN во внутреннюю сеть хостинга
          {
            type: 'field', outboundTag: 'block',
            ip: ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
              '172.16.0.0/12', '192.168.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10'],
          },
          { type: 'field', outboundTag: 'block', domain: ['full:localhost'] },
          // торренты блокируем: за них хостинг банит
          { type: 'field', outboundTag: 'block', protocol: ['bittorrent'] },
        ],
      },
    };
  }

  function start() {
    if (disabled || proc || stopping || !fs.existsSync(BIN)) return;
    const p = spawn(BIN, ['run', '-c', CONF], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, GOMEMLIMIT: process.env.XRAY_MEMLIMIT || '80MiB', GOGC: '50' },
    });
    proc = p;
    startedAt = Date.now();
    const fwd = (chunk) => String(chunk).split(/\r?\n/).filter(Boolean).forEach((l) => log('[xray]', l));
    p.stdout.on('data', fwd);
    p.stderr.on('data', fwd);
    p.on('error', (e) => log('Xray: не удалось запустить:', e.message));
    p.on('exit', (code, sig) => {
      if (proc === p) proc = null;
      if (stopping) return;
      if (expectRestart) { expectRestart = false; start(); return; }
      log(`Xray завершился (code=${code}, signal=${sig}), перезапуск через 3 с…`);
      setTimeout(start, 3000);
    });
  }

  /** Записать конфиг с активными пользователями и (пере)запустить Xray. */
  function apply(users) {
    fs.mkdirSync(path.dirname(CONF), { recursive: true });
    fs.writeFileSync(CONF, JSON.stringify(buildConfig(users), null, 2));
    if (disabled) { log(`[NO_XRAY] активных ключей: ${users.length}`); return; }
    clearTimeout(applyTimer);
    applyTimer = setTimeout(() => {
      if (!proc) { start(); return; }
      log(`Xray перезапускается: активных ключей ${users.length}`);
      expectRestart = true;
      proc.kill('SIGTERM');
    }, 800);
  }

  /** Трафик по пользователям с момента прошлого вызова: { userId: { up, down } } или null. */
  function stats() {
    if (disabled || !proc) return Promise.resolve(null);
    return new Promise((resolve) => {
      execFile(BIN, ['api', 'statsquery', `--server=127.0.0.1:${PORTS.api}`, '-pattern', 'user>>>', '-reset'],
        { timeout: 10000, maxBuffer: 4 * 1024 * 1024 }, (err, stdout) => {
          if (err) return resolve(null);
          try {
            const j = JSON.parse(stdout || '{}');
            const out = {};
            for (const s of j.stat || []) {
              const [kind, id, , dir] = String(s.name).split('>>>');
              if (kind !== 'user') continue;
              out[id] = out[id] || { up: 0, down: 0 };
              out[id][dir === 'uplink' ? 'up' : 'down'] += Number(s.value || 0);
            }
            resolve(out);
          } catch {
            resolve(null);
          }
        });
    });
  }

  function stop() {
    stopping = true;
    if (proc) proc.kill('SIGTERM');
  }

  return {
    ensure, apply, stats, stop,
    status: () => ({ running: !!proc || disabled, startedAt, version: XRAY_VERSION }),
  };
}

module.exports = { createXray, extractFromZip, PORTS, PATHS };
