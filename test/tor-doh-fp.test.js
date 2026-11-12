const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const dns = require('node:dns');
const vm = require('node:vm');
const Module = require('node:module');

const {
  DOH_PROVIDERS,
  DohManager,
  buildDnsQueryPacket,
  parseDnsResponsePacket
} = require('../src/network/doh-manager');
const { DpiManager, buildFragmentedTlsChunks } = require('../src/network/dpi-manager');
const { TorManager, verifySocks5Listener } = require('../src/network/tor-manager');

function buildMockDnsAnswerPacket(queryBuf, records) {
  // Set QR=1, AA=0, TC=0, RD=1, RA=1, RCODE=0 -> flags = 0x8180, ANCOUNT = records.length
  const header = Buffer.alloc(12);
  queryBuf.copy(header, 0, 0, 2);
  header.writeUInt16BE(0x8180, 2);
  header.writeUInt16BE(1, 4); // QDCOUNT
  header.writeUInt16BE(records.length, 6); // ANCOUNT
  header.writeUInt16BE(0, 8);
  header.writeUInt16BE(0, 10);

  const question = queryBuf.subarray(12);
  const ansChunks = [];
  for (const rec of records) {
    const rdata =
      rec.type === 1
        ? Buffer.from(rec.ip.split('.').map(Number))
        : Buffer.from(rec.rawBytes);
    const rr = Buffer.alloc(12 + rdata.length);
    rr.writeUInt16BE(0xc00c, 0); // Compressed pointer to QNAME at offset 12
    rr.writeUInt16BE(rec.type, 2);
    rr.writeUInt16BE(1, 4); // IN
    rr.writeUInt32BE(rec.ttl || 60, 6);
    rr.writeUInt16BE(rdata.length, 10);
    rdata.copy(rr, 12);
    ansChunks.push(rr);
  }
  return Buffer.concat([header, question, ...ansChunks]);
}

test('DoH providers isolate Cloudflare cross-leaks and encode/decode RFC 8484 wireformat', async () => {
  const mgr = new DohManager();
  assert.equal(mgr.provider, 'quad9');

  for (const key of ['mullvad', 'adguard', 'custom']) {
    const p = DOH_PROVIDERS[key];
    assert.ok(p);
    const serialized = JSON.stringify(p);
    assert.equal(serialized.includes('cloudflare-dns.com'), false, `${key} must not contain cloudflare-dns.com`);
    assert.equal(serialized.includes('1.1.1.1'), false, `${key} must not contain 1.1.1.1`);
    assert.equal(serialized.includes('1.0.0.1'), false, `${key} must not contain 1.0.0.1`);
  }

  const q4 = buildDnsQueryPacket('privacy.example', 1);
  const a4 = buildMockDnsAnswerPacket(q4, [{ type: 1, ip: '93.184.216.34', ttl: 120 }]);
  const parsed4 = parseDnsResponsePacket(a4);
  assert.equal(parsed4.ip, '93.184.216.34');
  assert.equal(parsed4.ttl, 120);

  // Strict mode queries only selected provider via binary application/dns-message POST
  const requestedUrls = [];
  const fetchMgr = new DohManager({
    fetchFn: async (url, opts) => {
      requestedUrls.push({ url, headers: opts.headers, method: opts.method });
      const packet = buildMockDnsAnswerPacket(Buffer.from(opts.body), [{ type: 1, ip: '198.51.100.42', ttl: 90 }]);
      return { ok: true, arrayBuffer: async () => packet };
    }
  });
  fetchMgr.applyConfig({ enabled: true, provider: 'mullvad', strictMode: true });
  const resolvedIp = await fetchMgr.resolveHostViaDoH('onion.example');
  assert.equal(resolvedIp, '198.51.100.42');
  assert.equal(requestedUrls.length, 1);
  assert.ok(requestedUrls[0].url.includes('mullvad.net'));
  assert.equal(requestedUrls[0].method, 'POST');
  assert.equal(requestedUrls[0].headers['Content-Type'], 'application/dns-message');
});

test('DPI manager fails closed without ISP DNS in strict DoH mode and strips Yandex DNS', async () => {
  const dohMgr = new DohManager({
    fetchFn: async () => ({ ok: false })
  });
  dohMgr.applyConfig({ enabled: true, provider: 'quad9', strictMode: true });

  const origLookup = dns.promises.lookup;
  let ispLookupCalled = false;
  dns.promises.lookup = async () => {
    ispLookupCalled = true;
    return [{ address: '1.2.3.4', family: 4 }];
  };

  try {
    const dpi = new DpiManager({ dohManager: dohMgr });
    await assert.rejects(() => dpi.resolveTargetHost('blocked.example'), /Strict DoH resolution failed/);
    assert.equal(ispLookupCalled, false);
  } finally {
    dns.promises.lookup = origLookup;
  }

  const dpiSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'network', 'dpi-manager.js'), 'utf8');
  assert.equal(dpiSrc.includes('77.88.8.8'), false);
});

test('TorManager blocks unapproved external 9050/9150, isolates per-first-party gateways, auths via cookie, and wipes data', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zaslon-tor-'));
  let mockSocksServer = null;
  let mockControlServer = null;
  let mgr = null;

  try {
    // 1. Dummy TCP listener for SOCKS5 probe verification (rejects CONNECT so verifyTorExitIp settles immediately)
    mockSocksServer = net.createServer(sock => {
      sock.once('data', buf => {
        if (buf[0] === 0x05) {
          sock.write(Buffer.from([0x05, 0x00]));
          sock.once('data', () => {
            sock.end(Buffer.from([0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          });
        } else {
          sock.destroy();
        }
      });
    });
    await new Promise(resolve => mockSocksServer.listen(0, '127.0.0.1', resolve));
    const socksPort = mockSocksServer.address().port;
    assert.equal(await verifySocks5Listener(socksPort, '127.0.0.1', 1000), true);

    // 2. allowExternalTor defaults to false and rejects external daemon adoption without binary
    mgr = new TorManager({
      userDataPath: tmpDir,
      resourcesPath: tmpDir
    });
    assert.equal(mgr.allowExternalTor, false);
    const startRes = await mgr.start({ allowExternalTor: false });
    assert.equal(startRes.connected, false);
    assert.equal(startRes.lastError, 'TOR_BINARY_MISSING');

    // 3. Per-first-party SOCKS5 gateways assign distinct loopback ports & full proxy rules
    mgr.state = 'connected';
    mgr.socksPort = socksPort;
    const gwA = await mgr.ensureFirstPartyGateway('alpha.example');
    const gwB = await mgr.ensureFirstPartyGateway('beta.example');
    const gwA2 = await mgr.ensureFirstPartyGateway('sub.alpha.example');
    assert.notEqual(gwA, gwB);
    assert.equal(gwA, gwA2); // same eTLD+1 root shares circuit

    const rulesA = mgr.getTorSessionProxyRules('alpha.example');
    assert.equal(rulesA.mode, 'fixed_servers');
    assert.ok(rulesA.proxyRules.includes(`http=127.0.0.1:${gwA}`));
    assert.ok(rulesA.proxyRules.includes(`https=127.0.0.1:${gwA}`));
    assert.ok(rulesA.proxyRules.includes(`ftp=127.0.0.1:${gwA}`));
    assert.equal(rulesA.proxyBypassRules, '<-loopback>');

    // 4. ControlPort cookie authentication + SIGNAL NEWNYM
    const cookieBytes = Buffer.from('0123456789abcdef0123456789abcdef', 'hex');
    fs.mkdirSync(mgr.dataDir, { recursive: true });
    fs.writeFileSync(path.join(mgr.dataDir, 'control_auth_cookie'), cookieBytes);
    const seenControlLines = [];
    mockControlServer = net.createServer(sock => {
      sock.setEncoding('utf8');
      let buf = '';
      sock.on('data', chunk => {
        buf += chunk;
        const lines = buf.split('\r\n');
        buf = lines.pop();
        for (const line of lines) {
          seenControlLines.push(line);
          if (line.trim().toUpperCase() === 'QUIT') {
            sock.end('250 closing connection\r\n');
          } else {
            sock.write('250 OK\r\n');
          }
        }
      });
    });
    await new Promise(resolve => mockControlServer.listen(0, '127.0.0.1', resolve));
    mgr.controlPort = mockControlServer.address().port;
    const idRes = await mgr.newIdentity();
    assert.equal(idRes.connected, true);
    assert.equal(idRes.circuitEpoch, 2);
    assert.equal(seenControlLines[0], 'AUTHENTICATE 0123456789abcdef0123456789abcdef');
    assert.equal(seenControlLines[1], 'SIGNAL NEWNYM');

    // 5. clearTorData wipes tor-data directory
    assert.equal(fs.existsSync(mgr.dataDir), true);
    await mgr.stop(true);
    assert.equal(fs.existsSync(mgr.dataDir), false);
  } finally {
    if (mgr) await mgr.stop(false).catch(() => {});
    if (mockSocksServer) {
      if (typeof mockSocksServer.closeAllConnections === 'function') mockSocksServer.closeAllConnections();
      await new Promise(r => mockSocksServer.close(r));
    }
    if (mockControlServer) {
      if (typeof mockControlServer.closeAllConnections === 'function') mockControlServer.closeAllConnections();
      await new Promise(r => mockControlServer.close(r));
    }
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('page-preload.js hardens Tor/safest fingerprint surface without leaked globals', () => {
  const preloadPath = path.join(__dirname, '..', 'page-preload.js');
  const origLoad = Module._load;
  const origArgv = process.argv.slice();
  const origWindow = global.window;
  const origDocument = global.document;
  const captured = [];

  Module._load = function (request) {
    if (request === 'electron') {
      return {
        ipcRenderer: { send: () => {}, on: () => {} },
        webFrame: {
          executeJavaScript: code => {
            captured.push(String(code));
            return Promise.resolve();
          }
        }
      };
    }
    return origLoad.apply(this, arguments);
  };

  try {
    delete require.cache[require.resolve(preloadPath)];
    global.window = { addEventListener: () => {} };
    global.document = { addEventListener: () => {} };
    process.argv = [
      'electron',
      '--zaslon-fp=1',
      '--zaslon-sec=safest',
      '--zaslon-tor=1',
      '--zaslon-salt=unit-test-salt'
    ];
    require(preloadPath);
  } finally {
    Module._load = origLoad;
    process.argv = origArgv;
    global.window = origWindow;
    global.document = origDocument;
    delete require.cache[require.resolve(preloadPath)];
  }

  assert.ok(captured.length >= 1);
  for (const script of captured) {
    assert.doesNotThrow(() => new vm.Script(script));
    assert.equal(script.includes('__zaslonShieldActive'), false);
    assert.equal(script.includes('__zaslonYtAdShieldInstalled'), false);
  }

  // Execute main-world fingerprint shield inside an isolated VM context
  const shieldScript = captured.find(s => s.includes('Canvas Parmak'));
  assert.ok(shieldScript, 'Expected fingerprint shield script to be injected');

  let swRegisterResult = null;
  function NavigatorCtor() {}
  Object.defineProperty(NavigatorCtor.prototype, 'userAgent', { get: () => 'Mozilla/5.0', configurable: true });
  Object.defineProperty(NavigatorCtor.prototype, 'language', { get: () => 'tr-TR', configurable: true });
  Object.defineProperty(NavigatorCtor.prototype, 'languages', { get: () => ['tr-TR', 'tr'], configurable: true });
  Object.defineProperty(NavigatorCtor.prototype, 'platform', { get: () => 'Linux x86_64', configurable: true });
  Object.defineProperty(NavigatorCtor.prototype, 'serviceWorker', {
    get: () => ({ register: () => Promise.resolve('should-be-blocked') }),
    configurable: true
  });
  const fakeNav = Object.create(NavigatorCtor.prototype);

  function Canvas2D() {}
  Canvas2D.prototype.getImageData = () => ({ data: new Uint8ClampedArray(64) });
  Canvas2D.prototype.measureText = txt => ({ width: txt ? txt.length * 7.2 : 0 });

  function FakePerf() {}
  let perfTick = 101.437;
  FakePerf.prototype.now = () => perfTick;

  function FakeWorker(u) {
    this.url = u;
  }

  const sandbox = {
    Navigator: NavigatorCtor,
    navigator: fakeNav,
    HTMLCanvasElement: function () {},
    CanvasRenderingContext2D: Canvas2D,
    AudioBuffer: undefined,
    AnalyserNode: undefined,
    WebGLRenderingContext: undefined,
    WebGL2RenderingContext: undefined,
    RTCPeerConnection: function () {},
    webkitRTCPeerConnection: function () {},
    mozRTCPeerConnection: function () {},
    SharedWorker: function () {},
    Worker: FakeWorker,
    Blob: class FakeBlob {
      constructor(parts) {
        this.parts = parts;
      }
    },
    URL: {
      createObjectURL: b => `blob:${b.parts.join('')}`
    },
    location: { href: 'https://check.torproject.org/' },
    Performance: FakePerf,
    performance: new FakePerf(),
    Screen: function () {},
    screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24 },
    Intl,
    Date,
    Object,
    Math,
    Promise,
    DOMException,
    Error,
    Number,
    String,
    JSON,
    console
  };
  sandbox.window = sandbox;
  sandbox.devicePixelRatio = 2;

  vm.createContext(sandbox);
  vm.runInContext(shieldScript, sandbox);

  assert.equal(sandbox.navigator.language, 'en-US');
  assert.equal(sandbox.navigator.platform, 'Win32');
  assert.equal(sandbox.window.SharedWorker, undefined);
  assert.equal(sandbox.window.RTCPeerConnection, undefined);
  assert.equal(sandbox.performance.now(), 100); // 2ms coarsened in Tor/strict mode
  assert.equal(new Canvas2D().measureText('').width, 0);
  assert.notEqual(new Canvas2D().measureText('abc').width, 0);
  assert.equal(new sandbox.Date().getTimezoneOffset(), 0);
  assert.equal(new sandbox.Intl.DateTimeFormat().resolvedOptions().timeZone, 'UTC');

  swRegisterResult = sandbox.navigator.serviceWorker.register('/sw.js').then(
    () => 'ok',
    err => err.name
  );
  return swRegisterResult.then(res => {
    assert.equal(res, 'SecurityError');
  });
});

test('main.js & ui.html defaults use quad9 DoH, strip sec-ch-ua, and auto-letterbox Tor tabs', () => {
  const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'main.js'), 'utf8');
  const uiSrc = fs.readFileSync(path.join(__dirname, '..', 'ui.html'), 'utf8');

  assert.equal(mainSrc.includes("dohProvider: 'quad9'"), true);
  assert.equal(mainSrc.includes("dohProvider: 'cloudflare'"), false);
  assert.equal(uiSrc.includes("dohProvider||'cloudflare'"), false);
  assert.equal(uiSrc.includes("dohProvider||'quad9'"), true);

  assert.equal(mainSrc.includes("lower.startsWith('sec-ch-ua')"), true);
  assert.equal(mainSrc.includes("zaslon-ephemeral-tor-"), true);
  assert.equal(mainSrc.includes("--zaslon-tor="), true);
  assert.equal(mainSrc.includes("r.container === '🧅 Tor Zırhlı'"), true);
  assert.equal(mainSrc.includes("DOH_DIRECT_PARTITION"), true);
});

test('DohManager deduplicates concurrent lookups and clears cache on provider change', async () => {
  let fetchCalls = 0;
  const mgr = new DohManager({
    fetchFn: async (_url, opts) => {
      fetchCalls++;
      await new Promise(r => setTimeout(r, 20));
      const ip = mgr.provider === 'mullvad' ? '198.51.100.77' : '203.0.113.55';
      const packet = buildMockDnsAnswerPacket(Buffer.from(opts.body), [{ type: 1, ip, ttl: 120 }]);
      return { ok: true, arrayBuffer: async () => packet };
    }
  });
  mgr.applyConfig({ enabled: true, provider: 'quad9', strictMode: true });

  const [ip1, ip2, ip3] = await Promise.all([
    mgr.resolveHostViaDoH('www.google.com'),
    mgr.resolveHostViaDoH('www.google.com'),
    mgr.resolveHostViaDoH('WWW.GOOGLE.COM')
  ]);
  assert.equal(ip1, '203.0.113.55');
  assert.equal(ip2, '203.0.113.55');
  assert.equal(ip3, '203.0.113.55');
  assert.equal(fetchCalls, 1);

  mgr.applyConfig({ enabled: true, provider: 'mullvad', strictMode: true });
  const ipAfterSwitch = await mgr.resolveHostViaDoH('www.google.com');
  assert.equal(ipAfterSwitch, '198.51.100.77');
  assert.equal(fetchCalls, 2);
});

test('DpiManager exposes port/proxyAddress and splits SNI even after large post-quantum key_share', async () => {
  const host = Buffer.from('www.google.com', 'ascii');
  // Synthetic TLS ClientHello: key_share (0x0033) of 1200 bytes BEFORE SNI (0x0000)
  const keyShareExt = Buffer.concat([
    Buffer.from([0x00, 0x33, 0x04, 0xb0]), // type 0x0033, len 1200
    Buffer.alloc(1200, 0xaa)
  ]);
  const sniEntry = Buffer.concat([
    Buffer.from([0x00]),
    Buffer.from([(host.length >> 8) & 0xff, host.length & 0xff]),
    host
  ]);
  const sniList = Buffer.concat([
    Buffer.from([(sniEntry.length >> 8) & 0xff, sniEntry.length & 0xff]),
    sniEntry
  ]);
  const sniExt = Buffer.concat([
    Buffer.from([0x00, 0x00, (sniList.length >> 8) & 0xff, sniList.length & 0xff]),
    sniList
  ]);
  const allExts = Buffer.concat([keyShareExt, sniExt]);
  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]), // legacy_version
    Buffer.alloc(32, 0x11), // random
    Buffer.from([0x20]), // session_id_len = 32
    Buffer.alloc(32, 0x22), // session_id
    Buffer.from([0x00, 0x02, 0x13, 0x01]), // cipher_suites_len = 2
    Buffer.from([0x01, 0x00]), // compression_methods_len = 1
    Buffer.from([(allExts.length >> 8) & 0xff, allExts.length & 0xff]),
    allExts
  ]);
  const hs = Buffer.concat([
    Buffer.from([0x01, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff]),
    body
  ]);
  const tlsRecord = Buffer.concat([
    Buffer.from([0x16, 0x03, 0x01, (hs.length >> 8) & 0xff, hs.length & 0xff]),
    hs
  ]);

  const chunks = buildFragmentedTlsChunks(tlsRecord, 'sni-frag');
  assert.equal(chunks.length, 3);
  // First 2 records should not contain the full unbroken 'www.google.com' string, and final split must cut inside SNI
  const combinedTextPerChunk = chunks.map(c => c.subarray(5).toString('latin1'));
  assert.equal(combinedTextPerChunk.some(s => s.includes('www.google.com')), false);
  assert.equal(combinedTextPerChunk.join('').includes('www.google.com'), true);

  const dohMgr = new DohManager({
    fetchFn: async (_url, opts) => ({
      ok: true,
      arrayBuffer: async () => buildMockDnsAnswerPacket(Buffer.from(opts.body), [{ type: 1, ip: '127.0.0.1', ttl: 60 }])
    })
  });
  const dpi = new DpiManager({ dohManager: dohMgr });
  await dpi.start({ mode: 'builtin', splitProfile: 'sni-frag' });
  try {
    assert.ok(dpi.port > 0);
    assert.equal(dpi.proxyAddress, `127.0.0.1:${dpi.port}`);
  } finally {
    await dpi.stop(false);
  }
});

test('Faz 3 & 9.1/9.4 regression: [native code] toString/name masking, WeakSet AudioBuffer, OffscreenCanvas, WebRTC setConfiguration, iframe hook & Closed Shadow DOM', () => {
  const vm = require('node:vm');
  const preloadSrc = fs.readFileSync(path.join(__dirname, '..', 'page-preload.js'), 'utf8');
  assert.equal(preloadSrc.includes('Apple M2'), false);
  assert.equal(preloadSrc.includes('__zasNoised'), false);
  assert.equal(preloadSrc.includes("attachShadow({ mode: 'closed' })"), true);
  assert.equal(preloadSrc.includes('webFrame.insertCSS'), true);

  const fnMatches = preloadSrc.match(/function\s+(buildMainWorldShieldScript|buildYouTubeAdblockMainWorldScript)\s*\(/g);
  assert.ok(fnMatches && fnMatches.length === 2);

  const helpersMatch = preloadSrc.match(/function buildMainWorldShieldScript[\s\S]*?^function buildYouTubeAdblockMainWorldScript[\s\S]*?^\}/m);
  assert.ok(helpersMatch);

  const buildMain = vm.runInNewContext(`(() => { ${helpersMatch[0].split('function buildYouTubeAdblockMainWorldScript')[0]}\nreturn buildMainWorldShieldScript; })()`);
  const buildYt = vm.runInNewContext(`(() => { ${'function buildYouTubeAdblockMainWorldScript' + helpersMatch[0].split('function buildYouTubeAdblockMainWorldScript')[1]}\nreturn buildYouTubeAdblockMainWorldScript; })()`);

  // 1. Test standard mode (normal tab): WebRTC setConfiguration lock, OffscreenCanvas, AudioBuffer WeakSet, iframe propagation, [native code]
  const normalScript = buildMain('salt-1', 'standard', false, true);

  function NavCtor() {}
  const fakeNav = Object.create(NavCtor.prototype);
  function AudioBuf() {
    this._buf = new Float32Array(128);
  }
  AudioBuf.prototype.getChannelData = function () {
    return this._buf;
  };
  function FakePeerConnection(cfg) {
    this.cfg = cfg;
  }
  FakePeerConnection.prototype.setConfiguration = function (cfg) {
    this.cfg = cfg;
  };
  function FakeOffscreen2D() {}
  FakeOffscreen2D.prototype.getImageData = () => ({ data: new Uint8ClampedArray(64).fill(100) });
  FakeOffscreen2D.prototype.measureText = () => ({ width: 50 });

  function FakeIFrame() {
    this._cw = {
      Object,
      Promise,
      DOMException,
      Date,
      Intl,
      Blob,
      URL,
      Navigator: function () {},
      navigator: {},
      Performance: function () {},
      performance: { now: () => 12.34 },
      Screen: function () {},
      screen: { width: 2560, height: 1440, availWidth: 2560, availHeight: 1400, colorDepth: 24, pixelDepth: 24 },
      devicePixelRatio: 2
    };
    this._cw.navigator = Object.create(this._cw.Navigator.prototype);
    this._cw.window = this._cw;
  }
  Object.defineProperty(FakeIFrame.prototype, 'contentWindow', {
    configurable: true,
    get() {
      return this._cw;
    }
  });
  Object.defineProperty(FakeIFrame.prototype, 'contentDocument', {
    configurable: true,
    get() {
      return { defaultView: this._cw };
    }
  });
  function FakeNode() {}
  FakeNode.prototype.appendChild = function (n) {
    return n;
  };
  FakeNode.prototype.replaceChild = function (n) {
    return n;
  };
  function FakeWebGL() {}
  FakeWebGL.prototype.getParameter = () => 'raw';

  const sandbox = {
    Navigator: NavCtor,
    navigator: fakeNav,
    AudioBuffer: AudioBuf,
    OffscreenCanvasRenderingContext2D: FakeOffscreen2D,
    WebGLRenderingContext: FakeWebGL,
    WebGL2RenderingContext: FakeWebGL,
    RTCPeerConnection: FakePeerConnection,
    webkitRTCPeerConnection: FakePeerConnection,
    HTMLIFrameElement: FakeIFrame,
    Node: FakeNode,
    Element: function () {},
    Document: function () {},
    Screen: function () {},
    screen: { width: 2560, height: 1440, availWidth: 2560, availHeight: 1400, colorDepth: 24, pixelDepth: 24 },
    devicePixelRatio: 2,
    Performance: function () {},
    performance: { now: () => 10.123 },
    location: { hostname: 'creepjs.example', href: 'https://creepjs.example/' },
    Object,
    Promise,
    DOMException,
    Date,
    Intl,
    Blob,
    URL,
    WeakSet,
    WeakMap,
    Uint8ClampedArray,
    Float32Array,
    Math
  };
  sandbox.Element.prototype = { append: n => n, prepend: n => n };
  sandbox.Document.prototype = { write: () => {} };
  sandbox.Performance.prototype = { now: () => 10.123 };
  sandbox.window = sandbox;

  vm.createContext(sandbox);
  vm.runInContext(normalScript, sandbox);

  // Check [native code] + .name on overridden getters & methods
  const hwDesc = Object.getOwnPropertyDescriptor(NavCtor.prototype, 'hardwareConcurrency');
  assert.equal(hwDesc.get.name, 'get hardwareConcurrency');
  const vmFnToString = vm.runInContext('Function.prototype.toString', sandbox);
  assert.match(vmFnToString.call(hwDesc.get), /\[native code\]/);
  assert.match(vmFnToString.call(vmFnToString), /\[native code\]/);
  assert.match(vmFnToString.call(AudioBuf.prototype.getChannelData), /\[native code\]/);

  // AudioBuffer leaves zero own properties (__zasNoised gone)
  const audioBuf = new AudioBuf();
  audioBuf.getChannelData(0);
  assert.equal(Object.getOwnPropertyNames(audioBuf).includes('__zasNoised'), false);
  assert.deepEqual(Object.getOwnPropertyNames(audioBuf), ['_buf']);

  // WebGL never returns Apple M2
  assert.equal(new FakeWebGL().getParameter(37446).includes('Apple M2'), false);

  // OffscreenCanvas noise
  const offImg = new FakeOffscreen2D().getImageData(0, 0, 4, 4);
  assert.ok(offImg.data.some(v => v !== 100) || offImg.data.length === 64);

  // Screen masked when letterbox=true
  assert.equal(sandbox.screen.width, 1920);
  assert.equal(sandbox.screen.height, 1080);
  assert.equal(sandbox.devicePixelRatio, 1);

  // WebRTC constructor and setConfiguration force iceServers: []
  const pc = new sandbox.RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
  assert.equal(pc.cfg.iceServers.length, 0);
  pc.setConfiguration({ iceServers: [{ urls: 'turn:evil.example' }] });
  assert.equal(pc.cfg.iceServers.length, 0);

  // Iframe contentWindow gets patched automatically
  const ifr = new FakeIFrame();
  const cw = ifr.contentWindow;
  assert.equal(cw.navigator.hardwareConcurrency, 8);
  assert.equal(cw.screen.width, 1920);

  // YouTube adblock script does NOT touch non-YouTube Response.prototype.json or window.ytInitialPlayerResponse
  const origRespJson = () => 'untouched';
  sandbox.Response = { prototype: { json: origRespJson } };
  vm.runInContext(buildYt(), sandbox);
  assert.equal(sandbox.Response.prototype.json, origRespJson);
  assert.equal('ytInitialPlayerResponse' in sandbox, false);
});

test('TorManager & DpiManager proxies handle split TCP headers, IPv6 CONNECT, and coalesced start()', async () => {
  const net = require('net');
  const { DpiManager } = require('../src/network/dpi-manager');
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zaslon-split-gw-'));
  let torMgr = null;
  let dpiMgr = null;
  let mockSocks = null;
  let mockOrigin = null;

  try {
    // 1. Coalescing check when binary missing: concurrent starts coalesce cleanly to one result
    torMgr = new TorManager({ userDataPath: tmpDir, allowExternalTor: false });
    const [r1, r2] = await Promise.all([torMgr.start(), torMgr.start()]);
    assert.equal(r1.connected, false);
    assert.equal(r1.lastError, 'TOR_BINARY_MISSING');
    assert.equal(r2.lastError, 'TOR_BINARY_MISSING');

    // 2. Split-header Tor gateway test (IPv6 CONNECT + plain HTTP Connection: close)
    const socksSeen = [];
    mockOrigin = net.createServer(sock => {
      sock.once('data', reqBuf => {
        const reqStr = reqBuf.toString('latin1');
        assert.match(reqStr, /Connection:\s*close/i);
        assert.equal(/Proxy-Connection:/i.test(reqStr), false);
        sock.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok');
      });
    });
    await new Promise(r => mockOrigin.listen(0, '127.0.0.1', r));
    const originPort = mockOrigin.address().port;

    mockSocks = net.createServer(sock => {
      sock.once('data', () => {
        sock.write(Buffer.from([0x05, 0x02]));
        sock.once('data', () => {
          sock.write(Buffer.from([0x01, 0x00]));
          sock.once('data', cmd => {
            const addrLen = cmd[4];
            const host = cmd.subarray(5, 5 + addrLen).toString('utf8');
            const port = cmd.readUInt16BE(5 + addrLen);
            socksSeen.push({ host, port });
            sock.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80]));
            if (port === originPort) {
              const up = net.connect({ host: '127.0.0.1', port: originPort }, () => {
                sock.pipe(up);
                up.pipe(sock);
              });
              up.on('error', () => sock.destroy());
            } else {
              sock.once('data', payload => sock.write(payload));
            }
          });
        });
      });
    });
    await new Promise(r => mockSocks.listen(0, '127.0.0.1', r));

    torMgr.socksPort = mockSocks.address().port;
    torMgr.state = 'connected';
    const gwPort = await torMgr.ensureIsolationGateway();

    // Split plain HTTP request across 2 TCP chunks
    const httpResp = await new Promise((resolve, reject) => {
      const c = net.connect({ host: '127.0.0.1', port: gwPort }, () => {
        c.write(`GET http://127.0.0.1:${originPort}/hello HTTP/1.1\r\nHost: 127.0.0.1:${originPort}`);
        setTimeout(() => {
          c.write('\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\n\r\n');
        }, 25);
      });
      let data = '';
      c.on('data', d => { data += d.toString('latin1'); });
      c.on('end', () => resolve(data));
      c.on('error', reject);
      setTimeout(() => reject(new Error('Tor split HTTP timeout')), 3000);
    });
    assert.ok(httpResp.endsWith('ok'));

    // Split IPv6 CONNECT request across 2 TCP chunks
    const ipv6TunnelRes = await new Promise((resolve, reject) => {
      const c = net.connect({ host: '127.0.0.1', port: gwPort }, () => {
        c.write('CONNECT [::1]:443 HTTP/1.1\r\n');
        setTimeout(() => c.write('Host: [::1]:443\r\n\r\n'), 25);
      });
      c.once('data', chunk => {
        c.destroy();
        resolve(chunk.toString('latin1'));
      });
      c.on('error', reject);
      setTimeout(() => reject(new Error('Tor split IPv6 CONNECT timeout')), 3000);
    });
    assert.match(ipv6TunnelRes, /200 Connection Established/);
    assert.ok(socksSeen.some(s => s.host === '::1' && s.port === 443));

    // 3. DPI split-header proxy check
    dpiMgr = new DpiManager({ userDataPath: tmpDir });
    const dpiSt = await dpiMgr.start({ mode: 'builtin', splitProfile: 'sni-frag' });
    assert.equal(dpiSt.enabled, true);
    const dpiPort = dpiMgr.port;
    const dpiRes = await new Promise((resolve, reject) => {
      const c = net.connect({ host: '127.0.0.1', port: dpiPort }, () => {
        c.write(`CONNECT 127.0.0.1:${originPort}`);
        setTimeout(() => c.write(' HTTP/1.1\r\n\r\n'), 25);
      });
      c.once('data', chunk => {
        c.destroy();
        resolve(chunk.toString('latin1'));
      });
      c.on('error', reject);
      setTimeout(() => reject(new Error('DPI split CONNECT timeout')), 3000);
    });
    assert.match(dpiRes, /200 Connection Established/);
  } finally {
    if (dpiMgr) await dpiMgr.stop().catch(() => {});
    if (torMgr) await torMgr.stop(false).catch(() => {});
    if (mockSocks) await new Promise(r => mockSocks.close(r));
    if (mockOrigin) await new Promise(r => mockOrigin.close(r));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('page-preload.js dismisses long Turkish consent buttons, hides CMP overlays, clicks shadow DOM reject, and unlocks body scroll', () => {
  const preloadPath = path.join(__dirname, '..', 'page-preload.js');
  const origLoad = Module._load;
  const origArgv = process.argv.slice();
  const origWindow = global.window;
  const origDocument = global.document;
  const origGetComputedStyle = global.getComputedStyle;
  const origSetTimeout = global.setTimeout;
  const origSetInterval = global.setInterval;

  let domReadyCb = null;
  let trClickCount = 0;
  let ucClickCount = 0;

  const makeStyleMap = (init = {}) => {
    const map = { ...init };
    return {
      setProperty(k, v) { map[k] = v; },
      getPropertyValue(k) { return map[k] || ''; },
      get display() { return map.display || ''; },
      get overflow() { return map.overflow || ''; }
    };
  };

  const trBtn = {
    innerText: 'Sadece   Zorunlu Çerezlere İzin Ver',
    getAttribute: () => null,
    click: () => { trClickCount++; }
  };
  const trModal = {
    nodeType: 1,
    tagName: 'DIV',
    id: 'turkish-consent',
    className: 'cookie-consent-modal',
    dataset: {},
    style: makeStyleMap({ display: 'block', position: 'fixed' }),
    innerText: 'Bu site çerez kullanıyor',
    getAttribute: () => null,
    querySelectorAll: () => [trBtn]
  };
  const ucDenyBtn = {
    getAttribute: () => 'uc-deny-all-button',
    click: () => { ucClickCount++; }
  };
  const ucShadowRoot = {
    host: { id: 'usercentrics-root', className: '', tagName: 'DIV' },
    appended: [],
    appendChild(n) { this.appended.push(n); },
    querySelector: () => null,
    querySelectorAll: sel => (String(sel).includes('uc-deny-all-button') ? [ucDenyBtn] : [])
  };
  const ucHost = {
    nodeType: 1,
    tagName: 'DIV',
    id: 'usercentrics-root',
    className: '',
    shadowRoot: ucShadowRoot,
    style: makeStyleMap({ display: 'block', position: 'fixed' }),
    getAttribute: () => null
  };

  const fakeBody = {
    style: makeStyleMap({ overflow: 'hidden' })
  };
  const fakeDocEl = {
    style: makeStyleMap({ overflow: 'hidden' })
  };

  Module._load = function (request) {
    if (request === 'electron') {
      return {
        ipcRenderer: { send: () => {}, on: () => {} },
        webFrame: {
          executeJavaScript: () => Promise.resolve(),
          insertCSS: () => Promise.resolve('css-key-1')
        }
      };
    }
    return origLoad.apply(this, arguments);
  };

  try {
    delete require.cache[require.resolve(preloadPath)];
    global.window = {
      addEventListener: (ev, cb) => {
        if (ev === 'DOMContentLoaded') domReadyCb = cb;
      }
    };
    global.location = { hostname: 'example.com', href: 'https://example.com/' };
    global.document = {
      body: fakeBody,
      documentElement: fakeDocEl,
      createElement: tag => ({ tagName: tag.toUpperCase(), setAttribute() {}, textContent: '' }),
      addEventListener: () => {},
      querySelector: sel => (String(sel).includes('usercentrics-root') ? ucHost : null),
      querySelectorAll: sel => {
        const s = String(sel);
        if (s === '*') return [trModal, ucHost];
        if (s.includes('cookie-consent') || s.includes('çerez') || s.includes('[id*="cookie"')) return [trModal];
        return [];
      }
    };
    global.getComputedStyle = el => ({
      overflow: el.style.overflow || 'visible',
      display: el.style.display || 'block',
      position: 'fixed'
    });
    global.setTimeout = () => 0;
    global.setInterval = () => 0;
    process.argv = ['electron', '--zaslon-popups=1', '--zaslon-fp=0', '--zaslon-sb=0'];

    require(preloadPath);
    assert.ok(typeof domReadyCb === 'function');
    domReadyCb();

    assert.equal(trClickCount, 1);
    assert.equal(ucClickCount, 1);
    assert.equal(trModal.style.display, 'none');
    assert.equal(ucShadowRoot.appended.length, 1);
    assert.equal(fakeBody.style.overflow, 'auto');
    assert.equal(fakeDocEl.style.overflow, 'auto');
  } finally {
    Module._load = origLoad;
    process.argv = origArgv;
    global.window = origWindow;
    global.document = origDocument;
    global.getComputedStyle = origGetComputedStyle;
    global.setTimeout = origSetTimeout;
    global.setInterval = origSetInterval;
    delete global.location;
    delete require.cache[require.resolve(preloadPath)];
  }
});
