'use strict';
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

// Постоянный адрес без домена: Tailscale Funnel выдаёт имя вида имя-пк.tailnet.ts.net.
// Сам Tailscale ставится и входит в аккаунт вручную, QVpn только включает Funnel.
const DEFAULT_BIN = 'C:\\Program Files\\Tailscale\\tailscale.exe';

function createTailscale({ port, log, onUrl }) {
  const BIN = fs.existsSync(DEFAULT_BIN) ? DEFAULT_BIN : 'tailscale';

  function cli(args) {
    return spawnSync(BIN, args, { encoding: 'utf8', windowsHide: true, timeout: 30000 });
  }

  function hostName() {
    const r = cli(['status', '--json']);
    if (r.error || r.status !== 0) {
      throw new Error('Tailscale не установлен или не запущен: установите его с tailscale.com и войдите в аккаунт');
    }
    const st = JSON.parse(r.stdout || '{}');
    if (st.BackendState !== 'Running' || !st.Self || !st.Self.DNSName) {
      throw new Error('Tailscale не подключён: откройте приложение Tailscale и войдите в аккаунт');
    }
    return st.Self.DNSName.replace(/\.$/, '');
  }

  async function ensure() {
    hostName();
  }

  function start() {
    let host;
    try { host = hostName(); } catch (e) { log(e.message); return; }
    // --bg: Funnel работает в фоне и сам возобновляется после перезапуска Tailscale
    const r = cli(['funnel', '--bg', '--https=443', `127.0.0.1:${port}`]);
    if (r.status !== 0) {
      log('Tailscale Funnel не включился:', String(r.stderr || r.stdout || '').trim().slice(0, 400));
      log('Проверьте: в админке tailscale.com включены MagicDNS и HTTPS Certificates, а для Funnel разрешён доступ в Access controls.');
      return;
    }
    onUrl(`https://${host}`);
  }

  function stop() {}

  return { ensure, start, stop, hostName };
}

module.exports = { createTailscale };
