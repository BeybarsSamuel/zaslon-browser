const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const { EncryptedVault } = require('../src/storage/encrypted-vault');
const { LanSyncManager } = require('../src/storage/lan-sync');
const { YtDlpManager } = require('../src/media/ytdlp-manager');

function httpRequest(port, reqPath, { method = 'GET', headers = {}, body = '' } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: reqPath,
        method,
        headers
      },
      res => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try {
            json = JSON.parse(text);
          } catch {}
          resolve({ status: res.statusCode, headers: res.headers, text, json });
        });
      }
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

test('EncryptedVault encrypts favcache/priv/search_hist and truncates SQLite WAL on panicWipe', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zaslon-vault-'));
  try {
    const vault = new EncryptedVault({ userDataPath: tmpDir });
    const secretSite = 'super-secret-onion-journal.example';
    vault.set('favcache', { [secretSite]: 'data:image/png;base64,AAAA' });
    vault.set('search_hist', [{ q: 'whistleblower drop', d: Date.now() }]);
    vault.set('priv', { dohProvider: 'quad9', dohCustomUrl: 'https://private.dns.example/query' });

    assert.equal(vault.get('favcache')[secretSite], 'data:image/png;base64,AAAA');
    assert.equal(vault.get('search_hist')[0].q, 'whistleblower drop');

    // Disk database must not store plaintext secrets
    const rawDb = fs.readFileSync(vault.dbPath);
    assert.equal(rawDb.includes(secretSite), false);
    assert.equal(rawDb.includes('whistleblower drop'), false);
    assert.equal(rawDb.includes('private.dns.example'), false);

    const wipeRes = vault.panicWipe(false);
    assert.equal(wipeRes.ok, true);
    assert.ok(wipeRes.shreddedKeys.includes('favcache'));
    assert.ok(wipeRes.shreddedKeys.includes('search_hist'));
    assert.deepEqual(vault.get('favcache'), {});
    assert.deepEqual(vault.get('search_hist'), []);
    if (vault.useSqlite) {
      assert.equal(vault.checkpointWal(), true);
      const walPath = vault.dbPath + '-wal';
      if (fs.existsSync(walPath)) {
        assert.equal(fs.statSync(walPath).size, 0);
      }
    }
    if (vault.db && typeof vault.db.close === 'function') {
      vault.db.close();
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('LanSyncManager enforces Origin blocking, auth on /api/ping, AES-256-GCM pull/push, XSS-safe HTML, and manual discovery', async () => {
  const received = [];
  const lan = new LanSyncManager({
    onStateRequest: () => ({
      tabs: [{ title: '<script>alert(1)</script>', url: 'https://example.com/' }],
      bms: [{ t: 'Docs', u: 'https://docs.example/' }],
      notes: 'classified note',
      rssFeeds: []
    }),
    onReceiveItem: item => received.push(item)
  });

  await lan.start(0); // Default: HTTP only, UDP discovery off
  try {
    assert.equal(lan.running, true);
    assert.equal(lan.discoveryActive, false);
    assert.equal(lan.udpSocket, null);

    // 1. Cross-origin request blocked without CORS wildcard
    const corsEvil = await httpRequest(lan.httpPort, '/api/ping', {
      headers: { Origin: 'https://evil.example' }
    });
    assert.equal(corsEvil.status, 403);
    assert.equal(corsEvil.headers['access-control-allow-origin'], undefined);

    const crossSite = await httpRequest(lan.httpPort, '/api/ping', {
      headers: { 'Sec-Fetch-Site': 'cross-site' }
    });
    assert.equal(crossSite.status, 403);

    // 2. Unauthenticated /api/ping does not leak Zaslon identity
    const anonPing = await httpRequest(lan.httpPort, '/api/ping');
    assert.equal(anonPing.status, 401);
    assert.equal(anonPing.text.includes('Zaslon Browser'), false);

    // Authenticated /api/ping rejects raw cleartext X-Zaslon-Pin and succeeds with HMAC X-Zaslon-Auth
    const legacyPinPing = await httpRequest(lan.httpPort, '/api/ping', {
      headers: { 'X-Zaslon-Pin': lan.pin }
    });
    assert.equal(legacyPinPing.status, 401);

    const authPing = await httpRequest(lan.httpPort, '/api/ping', {
      headers: { 'X-Zaslon-Auth': lan._buildPinAuthHeader(lan.pin, 'GET', '/api/ping') }
    });
    assert.equal(authPing.status, 200);
    assert.equal(authPing.json.ok, true);

    // 3. /api/sync/pull refuses wantEncrypted:false and ALWAYS emits AES-256-GCM envelope
    const plainPull = await httpRequest(lan.httpPort, '/api/sync/pull', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Zaslon-Auth': lan._buildPinAuthHeader(lan.pin, 'POST', '/api/sync/pull') },
      body: JSON.stringify({ wantEncrypted: false })
    });
    assert.equal(plainPull.status, 400);

    const encPull = await httpRequest(lan.httpPort, '/api/sync/pull', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Zaslon-Auth': lan._buildPinAuthHeader(lan.pin, 'POST', '/api/sync/pull') },
      body: '{}'
    });
    assert.equal(encPull.status, 200);
    assert.equal(encPull.json.tabs, undefined);
    assert.equal(encPull.json.notes, undefined);
    assert.equal(encPull.json.envelope.encrypted, true);
    const decrypted = lan.decryptLanPacket(encPull.json.envelope, lan.pin);
    assert.equal(decrypted.notes, 'classified note');
    assert.equal(decrypted.tabs[0].url, 'https://example.com/');

    // 4. /api/sync/push refuses unencrypted payload and accepts encrypted envelope
    const plainPush = await httpRequest(lan.httpPort, '/api/sync/push', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Zaslon-Auth': lan._buildPinAuthHeader(lan.pin, 'POST', '/api/sync/push') },
      body: JSON.stringify({ type: 'note', text: 'unencrypted' })
    });
    assert.equal(plainPush.status, 400);
    assert.equal(received.length, 0);

    const env = lan.encryptLanPacket({ type: 'note', text: 'encrypted-ok', deviceName: 'TestPeer' }, lan.pin);
    const encPush = await httpRequest(lan.httpPort, '/api/sync/push', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Zaslon-Auth': lan._buildPinAuthHeader(lan.pin, 'POST', '/api/sync/push') },
      body: JSON.stringify({ envelope: env })
    });
    assert.equal(encPush.status, 200);
    assert.equal(received.length, 1);
    assert.equal(received[0].text, 'encrypted-ok');

    // 4b. 5 failed auth attempts trigger HTTP 429 lockout and rotate PIN + pairToken
    const pinBeforeBrute = lan.pin;
    const tokenBeforeBrute = lan.pairToken;
    for (let i = 0; i < 4; i++) {
      const failResp = await httpRequest(lan.httpPort, '/api/ping', {
        headers: { 'X-Zaslon-Auth': '1.badnonce.0000' }
      });
      assert.equal(failResp.status, 401);
    }
    const lockoutResp = await httpRequest(lan.httpPort, '/api/ping', {
      headers: { 'X-Zaslon-Auth': '1.badnonce.0000' }
    });
    assert.equal(lockoutResp.status, 429);
    assert.equal(lockoutResp.headers['retry-after'], '30');
    assert.notEqual(lan.pairToken, tokenBeforeBrute);
    assert.equal(lan.pin.length, 6);
    assert.ok(pinBeforeBrute.length === 6);

    // 5. Companion HTML uses textContent + DOM creation without .innerHTML template concatenation
    const htmlResp = await httpRequest(lan.httpPort, `/?t=${lan.pairToken}`);
    assert.equal(htmlResp.status, 200);
    assert.equal(htmlResp.text.includes(".innerHTML = tabs.map"), false);
    assert.equal(htmlResp.text.includes('renderSafeList'), true);
    assert.equal(htmlResp.text.includes('textContent'), true);

    // 6. Discovery starts explicitly and stops cleanly
    assert.equal(lan.startDiscovery(5000), true);
    assert.equal(lan.discoveryActive, true);
    assert.equal(lan.stopDiscovery(), true);
    assert.equal(lan.discoveryActive, false);
  } finally {
    await lan.stop();
  }
});

test('YtDlpManager shreds temp files and main/ui route storage through EncryptedVault without cookies.txt', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zaslon-ytshred-'));
  try {
    const yt = new YtDlpManager({ userDataPath: tmpDir });
    const dummyCookieFile = path.join(tmpDir, 'legacy-cookies.txt');
    const secretPayload = 'example.com\tTRUE\t/\tTRUE\t9999999999\tsid\tSUPER_SECRET_COOKIE';
    fs.writeFileSync(dummyCookieFile, secretPayload, 'utf8');
    yt.cleanupTempFile(dummyCookieFile);
    assert.equal(fs.existsSync(dummyCookieFile), false);

    const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'main.js'), 'utf8');
    assert.equal(mainSrc.includes('zaslon-cookies-'), false);
    assert.equal(mainSrc.includes('ses.cookies.get({})'), false);
    assert.equal(mainSrc.includes('checkpointWal'), true);
    assert.equal(mainSrc.includes("ipcMain.handle('setLanDiscovery'"), true);

    const uiSrc = fs.readFileSync(path.join(__dirname, '..', 'ui.html'), 'utf8');
    assert.equal(uiSrc.includes("VAULT_SENSITIVE_KEYS=new Set(['bms','tiles','hist','search_hist'"), true);
    assert.equal(uiSrc.includes("localStorage.setItem('zas_favcache'"), false);
    assert.equal(uiSrc.includes("localStorage.setItem('zas_priv'"), false);
    assert.equal(uiSrc.includes("Z.setLanDiscovery(S.drawer==='lan')"), true);

    const legacyHtmlPath = path.join(__dirname, '..', '..', 'zaslon-browser.html');
    if (fs.existsSync(legacyHtmlPath)) {
      const legacyHtml = fs.readFileSync(legacyHtmlPath, 'utf8');
      assert.equal(legacyHtml.includes('[ARCHIVED / DEPRECATED'), true);
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Faz 1 & 9.2 regression: ytdlp blocks arg injection, showItem/external/CSP harden IPC, and Web Companion AES-256-GCM interoperates', async () => {
  const vm = require('node:vm');
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zaslon-faz1-92-'));
  try {
    const yt = new YtDlpManager({ userDataPath: tmpDir, downloadsPath: tmpDir });
    // 1. spawnYtDlpJob blocks non-http(s) URLs, '-' flag URLs, and CRLF/null injection
    const rFlag = await yt.spawnYtDlpJob('yt-dlp', '--exec=calc.exe', 'best', ['--exec', 'calc']);
    assert.equal(rFlag.ok, false);
    const rFile = await yt.spawnYtDlpJob('yt-dlp', 'file:///C:/Windows/win.ini', 'best', ['--exec', 'calc']);
    assert.equal(rFile.ok, false);
    const rStartFile = await yt.startDownload({ url: 'file:///etc/passwd', args: ['--exec', 'id'] });
    assert.equal(rStartFile.ok, false);

    const ytSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'media', 'ytdlp-manager.js'), 'utf8');
    assert.equal(ytSrc.includes('options.rawArgs'), false);
    assert.equal(ytSrc.includes("args.push('--', cleanUrl);"), true);

    // 2. main.js showItem UNC/traversal guard, external .onion guard, downloadMedia rt precedence, ui.html CSP
    const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'main.js'), 'utf8');
    assert.equal(mainSrc.includes("raw.startsWith('\\\\\\\\') || raw.startsWith('//')"), true);
    assert.equal(mainSrc.includes("host === 'onion' || host.endsWith('.onion')"), true);
    assert.equal(mainSrc.includes('{ ...safeOpts, ...ctx, ...rt, args: null }'), true);

    const uiSrc = fs.readFileSync(path.join(__dirname, '..', 'ui.html'), 'utf8');
    assert.equal(uiSrc.includes("img-src 'self' data: blob:; connect-src 'none'; frame-src 'none'"), true);

    // 3. LanSync Web Companion pure-JS scrypt + AES-256-GCM + X-Zaslon-Auth round-trip with LanSyncManager
    const lan = new LanSyncManager({ deviceName: 'DesktopHost' });
    lan.updateSharedState({
      tabs: [{ title: 'Example', url: 'https://example.org/' }],
      bms: [{ t: 'BM', u: 'https://bm.example/' }],
      notes: 'top secret note'
    });
    const html = lan._renderMobileCompanionHtml(lan.pairToken);
    assert.equal(html.includes('X-Zaslon-Pin'), false);
    assert.equal(html.includes('encryptEnvelope('), true);
    assert.equal(html.includes('decryptEnvelope('), true);

    const scriptMatch = html.match(/<script>([\s\S]*?)<\/script>/);
    assert.ok(scriptMatch, 'Web Companion script block missing');
    const sandbox = {
      TextEncoder,
      TextDecoder,
      Uint8Array,
      Int32Array,
      DataView,
      Array,
      String,
      Number,
      Math,
      Date,
      JSON,
      Error,
      URL,
      btoa: s => Buffer.from(s, 'latin1').toString('base64'),
      atob: s => Buffer.from(s, 'base64').toString('latin1'),
      crypto: { getRandomValues: arr => require('node:crypto').randomFillSync(arr) },
      document: { getElementById: () => null },
      setTimeout,
      fetch: async () => ({ json: async () => ({ ok: false }) })
    };
    vm.createContext(sandbox);
    vm.runInContext(scriptMatch[1], sandbox);

    // Server -> Web Companion decrypt
    const serverEnv = lan.encryptLanPacket({ msg: 'hello-from-desktop', count: 42 }, lan.pin);
    const clientDec = sandbox.decryptEnvelope(serverEnv, lan.pin);
    assert.equal(clientDec.msg, 'hello-from-desktop');
    assert.equal(clientDec.count, 42);

    // Web Companion -> Server decrypt
    const clientEnv = sandbox.encryptEnvelope({ type: 'note', text: 'hello-from-mobile' }, lan.pin);
    const serverDec = lan.decryptLanPacket(clientEnv, lan.pin);
    assert.equal(serverDec.type, 'note');
    assert.equal(serverDec.text, 'hello-from-mobile');

    // Wrong PIN fails GCM authentication tag
    assert.throws(() => sandbox.decryptEnvelope(serverEnv, '000000'), /Invalid PIN or tampered/);

    // Pure-JS HMAC X-Zaslon-Auth accepted by LanSyncManager._verifyRequestAuth
    const authHdr = sandbox.buildPinAuthHeader(lan.pin, 'POST', '/api/sync/pull');
    const okAuth = lan._verifyRequestAuth(
      { headers: { 'x-zaslon-auth': authHdr }, method: 'POST' },
      new URL('http://127.0.0.1:49440/api/sync/pull'),
      null
    );
    assert.equal(okAuth, true);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
