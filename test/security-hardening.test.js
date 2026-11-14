const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.join(__dirname, '..');
const REPO_ROOT = path.join(ROOT, '..');

function extractFunctionSource(code, fnName) {
  const marker = `function ${fnName}(`;
  const start = code.indexOf(marker);
  assert.ok(start >= 0, `${fnName} bulunamadı`);
  const braceStart = code.indexOf('{', start);
  let depth = 0;
  for (let i = braceStart; i < code.length; i++) {
    if (code[i] === '{') depth++;
    else if (code[i] === '}') {
      depth--;
      if (depth === 0) return code.slice(start, i + 1);
    }
  }
  throw new Error(`${fnName} bloğu kapanmadı`);
}

function httpRequest(port, reqPath, opts = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: reqPath,
        method: opts.method || 'GET',
        headers: opts.headers || {}
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
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

test('chromium-hardening synchronizes dynamic Chrome major UA and disables extra hardware/sensor features', () => {
  const {
    applyChromiumHardeningFlags,
    getUniformChromeMajor,
    getUniformBrowserUserAgent
  } = require('../src/privacy/chromium-hardening');

  const major = getUniformChromeMajor();
  assert.match(major, /^\d+$/);
  const ua = getUniformBrowserUserAgent();
  assert.ok(ua.includes(`Chrome/${major}.0.0.0`), `Expected UA to include Chrome/${major}.0.0.0, got: ${ua}`);

  const recorded = [];
  applyChromiumHardeningFlags({
    commandLine: {
      appendSwitch: (k, v) => recorded.push([k, v])
    }
  });
  const byKey = new Map(recorded);
  assert.ok(byKey.has('disable-speech-synthesis-api'));
  assert.ok(byKey.has('disable-notifications'));
  const disabledFeatures = String(byKey.get('disable-features') || '').split(',');
  for (const feat of ['WebBluetooth', 'WebUSB', 'WebSerial', 'WebHID', 'IdleDetection', 'ComputePressure', 'PrivateStateTokens']) {
    assert.ok(disabledFeatures.includes(feat), `Missing disabled feature: ${feat}`);
  }
});

test('TorManager enforces hardened spawn flags, advances epoch on stop, and creates isolated HTTP proxy URLs', async () => {
  const torSrc = fs.readFileSync(path.join(ROOT, 'src', 'network', 'tor-manager.js'), 'utf8');
  for (const flag of ["'--SafeSocks'", "'--ClientOnly'", "'--AvoidDiskWrites'"]) {
    assert.ok(torSrc.includes(flag), `TorManager must spawn tor with ${flag}`);
  }

  const { TorManager } = require('../src/network/tor-manager');
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zaslon-tor-sec-'));
  try {
    const tor = new TorManager({ userDataPath: tmpDir, autoManage: false });
    const startEpoch = tor.circuitEpoch;
    tor.state = 'connected';
    tor.socksPort = 19950;
    const proxyUrl = await tor.getIsolatedHttpProxyUrl('sub.example.com');
    assert.match(proxyUrl, /^http:\/\/127\.0\.0\.1:\d+$/);
    await tor.stop(false);
    assert.equal(tor.circuitEpoch, startEpoch + 1);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('page-preload.js hardens userAgentData, UTC Date strings, all Intl locales, WebGL readPixels, AnalyserNode, screen geometry, and hardware APIs', async () => {
  const preloadCode = fs.readFileSync(path.join(ROOT, 'page-preload.js'), 'utf8');
  const buildFnCode = extractFunctionSource(preloadCode, 'buildMainWorldShieldScript');
  const buildMain = new Function(`${buildFnCode}; return buildMainWorldShieldScript;`)();
  const scriptA = buildMain('salt-sec-1', 'safest', true, true, '144');
  const scriptB = buildMain('salt-sec-2', 'safest', true, true, '144');

  function makeEnv(hostname, injectedScript) {
    function FakeIntlDateTimeFormat(locales, options) {
      this._loc = Array.isArray(locales) ? (locales[0] || 'tr-TR') : (locales || 'tr-TR');
      this._tz = (options && options.timeZone) || 'Europe/Istanbul';
    }
    FakeIntlDateTimeFormat.prototype.resolvedOptions = function () {
      return { locale: this._loc, timeZone: this._tz };
    };
    FakeIntlDateTimeFormat.prototype.format = function (d) {
      return `FMT(${this._loc}|${this._tz}|${d.toISOString()})`;
    };
    FakeIntlDateTimeFormat.supportedLocalesOf = () => ['en-US'];

    function FakeIntlNumberFormat(locales) {
      this._loc = Array.isArray(locales) ? (locales[0] || 'tr-TR') : (locales || 'tr-TR');
    }
    FakeIntlNumberFormat.prototype.resolvedOptions = function () {
      return { locale: this._loc };
    };
    FakeIntlNumberFormat.supportedLocalesOf = () => ['en-US'];

    function FakeWebGL() {}
    FakeWebGL.prototype.getParameter = p => `RAW_${p}`;
    FakeWebGL.prototype.readPixels = (_x, _y, _w, _h, _fmt, _type, buf) => {
      buf.fill(100);
    };

    function FakeAnalyser() {}
    FakeAnalyser.prototype.getFloatFrequencyData = arr => {
      arr.fill(-40.0);
    };
    FakeAnalyser.prototype.getByteFrequencyData = arr => {
      arr.fill(120);
    };

    function FakeNavigator() {}
    Object.defineProperties(FakeNavigator.prototype, {
      hardwareConcurrency: { get: () => 16, configurable: true },
      deviceMemory: { get: () => 32, configurable: true },
      webdriver: { get: () => true, configurable: true },
      language: { get: () => 'tr-TR', configurable: true },
      languages: { get: () => ['tr-TR', 'tr'], configurable: true },
      platform: { get: () => 'Linux x86_64', configurable: true },
      userAgent: { get: () => 'Electron/45.3.0', configurable: true },
      appVersion: { get: () => 'Electron/45.3.0', configurable: true },
      vendor: { get: () => 'Electron', configurable: true },
      connection: { get: () => ({ effectiveType: '4g', rtt: 50 }), configurable: true },
      bluetooth: { get: () => ({}), configurable: true },
      usb: { get: () => ({}), configurable: true },
      gpu: { get: () => ({}), configurable: true },
      getGamepads: { value: () => [{ id: 'Xbox' }], configurable: true },
      mediaDevices: {
        get: () => ({
          enumerateDevices: async () => [{ deviceId: 'mic-1', kind: 'audioinput' }],
          getUserMedia: async () => ({}),
          getDisplayMedia: async () => ({})
        }),
        configurable: true
      },
      keyboard: {
        get: () => ({
          getLayoutMap: async () => new Map([['KeyQ', 'q']])
        }),
        configurable: true
      }
    });
    const nav = new FakeNavigator();

    const sandbox = {
      Object,
      Array,
      String,
      Number,
      Boolean,
      Math,
      JSON,
      Map,
      Set,
      WeakMap,
      WeakSet,
      Promise,
      Date,
      RegExp,
      URL,
      Blob,
      Uint8Array,
      Float32Array,
      DOMException: class DOMException extends Error {
        constructor(msg, name) {
          super(msg);
          this.name = name;
        }
      },
      location: { hostname, href: `https://${hostname}/` },
      navigator: nav,
      screen: { width: 2560, height: 1440, availWidth: 2560, availHeight: 1400, availLeft: 100, availTop: 40, colorDepth: 30, pixelDepth: 30 },
      Screen: function Screen() {},
      innerWidth: 1200,
      innerHeight: 800,
      outerWidth: 1280,
      outerHeight: 880,
      screenX: 120,
      screenY: 90,
      screenLeft: 120,
      screenTop: 90,
      devicePixelRatio: 2,
      matchMedia: q => ({ media: q, matches: /dark|reduce/.test(q) }),
      speechSynthesis: { getVoices: () => [{ name: 'Microsoft Tolga - Turkish' }] },
      Intl: {
        DateTimeFormat: FakeIntlDateTimeFormat,
        NumberFormat: FakeIntlNumberFormat,
        RelativeTimeFormat: FakeIntlNumberFormat,
        ListFormat: FakeIntlNumberFormat,
        PluralRules: FakeIntlNumberFormat,
        Collator: FakeIntlNumberFormat
      },
      WebGLRenderingContext: FakeWebGL,
      AnalyserNode: FakeAnalyser
    };
    sandbox.window = sandbox;
    sandbox.self = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(injectedScript, sandbox);
    return sandbox;
  }

  const envA = makeEnv('site-a.example', scriptA);
  const envB = makeEnv('site-b.example', scriptB);
  const scriptStd = buildMain('salt-sec-std', 'standard', false, false, '144');
  const envStd = makeEnv('site-std.example', scriptStd);

  // Synced UA in standard & strictMode; userAgentData stripped in strictMode to eliminate sec-ch-ua HTTP/JS mismatch
  assert.ok(envA.navigator.userAgent.includes('Chrome/144.0.0.0'));
  assert.ok(!envA.navigator.userAgent.includes('Electron'));
  assert.equal(envA.navigator.userAgentData, undefined);
  assert.equal(envA.navigator.doNotTrack, null);
  assert.equal(envStd.navigator.userAgentData.platform, 'Windows');
  const hev = await envStd.navigator.userAgentData.getHighEntropyValues(['uaFullVersion', 'platformVersion', 'bitness']);
  assert.equal(hev.uaFullVersion, '144.0.0.0');
  assert.equal(hev.bitness, '64');

  // UTC timezone + generic Date.prototype strings
  const sampleDate = new envA.Date('2026-06-15T12:34:56Z');
  assert.equal(sampleDate.getTimezoneOffset(), 0);
  assert.ok(sampleDate.toTimeString().includes('GMT+0000 (Coordinated Universal Time)'));
  assert.ok(sampleDate.toString().includes('Mon Jun 15 2026 12:34:56 GMT+0000'));
  assert.ok(sampleDate.toLocaleString().includes('en-US|UTC|'));

  // All Intl constructors normalize implicit OS locale to en-US while keeping explicit locales
  assert.equal(new envA.Intl.DateTimeFormat().resolvedOptions().locale, 'en-US');
  assert.equal(new envA.Intl.DateTimeFormat().resolvedOptions().timeZone, 'UTC');
  assert.equal(new envA.Intl.NumberFormat().resolvedOptions().locale, 'en-US');
  assert.equal(new envA.Intl.NumberFormat('de-DE').resolvedOptions().locale, 'de-DE');

  // Screen & window geometry
  assert.equal(envA.screen.availLeft, 0);
  assert.equal(envA.screen.availTop, 0);
  assert.equal(envA.screenX, 0);
  assert.equal(envA.screenY, 0);
  assert.equal(envA.outerWidth, 1200);
  assert.equal(envA.outerHeight, 800);

  // MatchMedia & hardware APIs
  assert.equal(envA.matchMedia('(prefers-color-scheme: dark)').matches, false);
  assert.equal(envA.matchMedia('(prefers-color-scheme: light)').matches, true);
  assert.equal(envA.matchMedia('(prefers-reduced-motion: reduce)').matches, false);
  assert.deepEqual(Array.from(envA.navigator.getGamepads()), []);
  assert.deepEqual(Array.from(envA.speechSynthesis.getVoices()), []);
  assert.equal(envA.navigator.bluetooth, undefined);
  assert.equal(envA.navigator.gpu, undefined);
  assert.deepEqual(Array.from(await envA.navigator.mediaDevices.enumerateDevices()), []);
  await assert.rejects(() => envA.navigator.mediaDevices.getUserMedia({ audio: true }), /Permission denied/);
  assert.equal((await envA.navigator.keyboard.getLayoutMap()).size, 0);

  // WebGL GL_VENDOR/GL_RENDERER + deterministic readPixels perturbation
  const glA = new envA.WebGLRenderingContext();
  const glB = new envB.WebGLRenderingContext();
  assert.equal(glA.getParameter(7936), 'WebKit');
  assert.equal(glA.getParameter(7937), 'WebKit WebGL');
  const pxA1 = new envA.Uint8Array(64);
  const pxA2 = new envA.Uint8Array(64);
  const pxB = new envB.Uint8Array(64);
  glA.readPixels(0, 0, 4, 4, 0, 0, pxA1);
  glA.readPixels(0, 0, 4, 4, 0, 0, pxA2);
  glB.readPixels(0, 0, 4, 4, 0, 0, pxB);
  assert.deepEqual(Array.from(pxA1), Array.from(pxA2));
  assert.notDeepEqual(Array.from(pxA1), Array.from(pxB));

  // AnalyserNode deterministic domain noise
  const anA = new envA.AnalyserNode();
  const anB = new envB.AnalyserNode();
  const fA1 = new envA.Float32Array(64);
  const fA2 = new envA.Float32Array(64);
  const fB = new envB.Float32Array(64);
  anA.getFloatFrequencyData(fA1);
  anA.getFloatFrequencyData(fA2);
  anB.getFloatFrequencyData(fB);
  assert.deepEqual(Array.from(fA1), Array.from(fA2));
  assert.notDeepEqual(Array.from(fA1), Array.from(fB));
});

test('LanSyncManager uses generic deviceName, blocks pairToken-only API auth, and blocks replay nonces', async () => {
  const { LanSyncManager } = require('../src/storage/lan-sync');
  const lan = new LanSyncManager();
  assert.notEqual(lan.deviceName, os.hostname());

  await lan.start(0);
  assert.equal(lan.running, true);
  try {
    // pairToken in query / header / body MUST NOT authenticate /api/ping or /api/sync/pull
    const tokenPing = await httpRequest(lan.httpPort, `/api/ping?t=${lan.pairToken}`, {
      headers: { 'X-Zaslon-Token': lan.pairToken }
    });
    assert.equal(tokenPing.status, 401);

    const tokenPull = await httpRequest(lan.httpPort, `/api/sync/pull?t=${lan.pairToken}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Zaslon-Token': lan.pairToken },
      body: JSON.stringify({ token: lan.pairToken })
    });
    assert.equal(tokenPull.status, 401);

    // Replay of identical X-Zaslon-Auth header is rejected
    const authHdr = lan._buildPinAuthHeader(lan.pin, 'GET', '/api/ping');
    const first = await httpRequest(lan.httpPort, '/api/ping', { headers: { 'X-Zaslon-Auth': authHdr } });
    assert.equal(first.status, 200);
    const replay = await httpRequest(lan.httpPort, '/api/ping', { headers: { 'X-Zaslon-Auth': authHdr } });
    assert.equal(replay.status, 401);

    // Unauthenticated /api/sync/push fails before body processing
    const unauthPush = await httpRequest(lan.httpPort, '/api/sync/push', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ envelope: { encrypted: true } })
    });
    assert.equal(unauthPush.status, 401);
  } finally {
    lan.stop();
  }
});

test('main.js, ui.html, and zaslon-android files maintain hardened fail-closed, CSP, favicon, and multi-tab Tor guards', () => {
  const mainSrc = fs.readFileSync(path.join(ROOT, 'main.js'), 'utf8');
  const uiSrc = fs.readFileSync(path.join(ROOT, 'ui.html'), 'utf8');
  assert.ok(mainSrc.includes('FAIL_CLOSED_TOR_PROXY'));
  assert.ok(mainSrc.includes('ALLOWED_NAV_PROTOCOLS'));
  assert.ok(mainSrc.includes("script-src 'none'; object-src 'none'; base-uri 'none'"));
  assert.ok(mainSrc.includes('EPHEMERAL_CONTAINERS.has(normCont)'));
  assert.ok(mainSrc.includes('--zaslon-chrome-major='));
  assert.ok(mainSrc.includes('torManager.getIsolatedHttpProxyUrl('));
  assert.ok(uiSrc.includes('const ephOnly=S.tabs.some'));

  const bgPath = path.join(REPO_ROOT, 'zaslon-android', 'app', 'src', 'main', 'assets', 'extensions', 'zaslon-shield', 'background.js');
  if (fs.existsSync(bgPath)) {
    const bgSrc = fs.readFileSync(bgPath, 'utf8');
    // Syntax check background.js cleanly
    new vm.Script(bgSrc);
    assert.ok(bgSrc.includes('nonTorTabIds'));
    assert.ok(bgSrc.includes('torServiceRequestUrls'));
    assert.ok(bgSrc.includes('nonTorServiceRequestUrls'));
    assert.ok(bgSrc.includes('extractRootDomain'));
    assert.ok(bgSrc.includes('circuitEpoch'));
  }

  const geckoYamlPath = path.join(REPO_ROOT, 'zaslon-android', 'app', 'src', 'main', 'assets', 'geckoview-config.yaml');
  if (fs.existsSync(geckoYamlPath)) {
    const geckoYaml = fs.readFileSync(geckoYamlPath, 'utf8');
    assert.ok(geckoYaml.includes('media.peerconnection.enabled: false'));
    assert.ok(geckoYaml.includes('network.proxy.socks_remote_dns: true'));
    assert.ok(geckoYaml.includes('privacy.resistFingerprinting.letterboxing: true'));
    assert.ok(geckoYaml.includes('privacy.spoof_english: 2'));
  }

  const lanKtPath = path.join(REPO_ROOT, 'zaslon-android', 'app', 'src', 'main', 'java', 'com', 'zaslon', 'browser', 'storage', 'LanSyncClient.kt');
  if (fs.existsSync(lanKtPath)) {
    const lanKt = fs.readFileSync(lanKtPath, 'utf8');
    assert.equal(lanKt.includes('Build.MODEL'), false);
  }
});

test('Beyond-Tor anonymity parity: JIT-less Safer/Safest, Tor padding & bridges, HTTPS-Only (.onion-safe), Onion-Location, Module Workers & Android TRR Tor fix', () => {
  const { applyChromiumHardeningFlags } = require('../src/privacy/chromium-hardening');
  const jitRecorded = [];
  applyChromiumHardeningFlags(
    { commandLine: { appendSwitch: (k, v) => jitRecorded.push([k, v]) } },
    { securityLevel: 'safer' }
  );
  const jitMap = new Map(jitRecorded);
  assert.equal(jitMap.get('js-flags'), '--jitless');
  assert.ok(String(jitMap.get('enable-features')).includes('SplitCacheByNetworkIsolationKey'));
  assert.ok(String(jitMap.get('disable-features')).includes('FontAccess'));

  // TorManager full ConnectionPadding + sanitized Bridge args
  const { TorManager, sanitizeBridgeLine } = require('../src/network/tor-manager');
  assert.equal(sanitizeBridgeLine("bridge obfs4 192.0.2.1:443 ABC\r\n--EvilArg 1"), 'obfs4 192.0.2.1:443 ABC');
  const torTmp = fs.mkdtempSync(path.join(os.tmpdir(), 'zaslon-tor-pad-'));
  try {
    const tor = new TorManager({
      userDataPath: torTmp,
      bridges: ['Bridge obfs4 198.51.100.10:443 FINGERPRINT cert=xyz iat-mode=0']
    });
    const args = tor.buildTorSpawnArgs(path.join(torTmp, 'tor-data'), '');
    assert.ok(args.includes('--ConnectionPadding'));
    assert.equal(args[args.indexOf('--ConnectionPadding') + 1], '1');
    assert.ok(args.includes('--ReducedConnectionPadding'));
    assert.equal(args[args.indexOf('--ReducedConnectionPadding') + 1], '0');
    assert.ok(args.includes('--UseBridges'));
    assert.ok(args.includes('--Bridge'));
    assert.equal(args[args.indexOf('--Bridge') + 1], 'obfs4 198.51.100.10:443 FINGERPRINT cert=xyz iat-mode=0');
  } finally {
    fs.rmSync(torTmp, { recursive: true, force: true });
  }

  // main.js HTTPS-Only exempts .onion & RFC1918, validates Onion-Location, wipes cross-site Tor storage, and drops DNT header
  const mainSrc = fs.readFileSync(path.join(ROOT, 'main.js'), 'utf8');
  assert.ok(mainSrc.includes('isPublicClearnetHttpUpgradeEligible'));
  assert.ok(mainSrc.includes('extractValidOnionLocationHeader'));
  assert.ok(mainSrc.includes("storages: ['cookies', 'localstorage', 'indexdb', 'websql', 'serviceworkers', 'cachestorage', 'filesystem']"));
  assert.equal(mainSrc.includes("h['DNT'] = '1'"), false);

  const extractFn = name => new Function(`${extractFunctionSource(mainSrc, name)}; return ${name};`)();
  const isHttpUpgradable = extractFn('isPublicClearnetHttpUpgradeEligible');
  assert.equal(isHttpUpgradable('http://example.com/news'), true);
  assert.equal(isHttpUpgradable('http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/'), false);
  assert.equal(isHttpUpgradable('http://127.0.0.1:8080/'), false);
  assert.equal(isHttpUpgradable('http://192.168.1.1/'), false);

  const parseOnionLoc = extractFn('extractValidOnionLocationHeader');
  const validOnion = 'http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/index.html';
  assert.equal(parseOnionLoc({ 'Onion-Location': [validOnion] }), validOnion);
  assert.equal(parseOnionLoc({ 'Onion-Location': ['https://evil.example.com/'] }), '');

  // page-preload.js safer disables WebAssembly, patches module/data Workers, DOMRect, and WebGL caps
  const preloadCode = fs.readFileSync(path.join(ROOT, 'page-preload.js'), 'utf8');
  const buildMain = new Function(`${extractFunctionSource(preloadCode, 'buildMainWorldShieldScript')}; return buildMainWorldShieldScript;`)();
  const saferScript = buildMain('salt-safer', 'safer', true, true, '144');
  const workersSpawned = [];
  const saferSandbox = {
    Object, Array, String, Number, Boolean, Math, JSON, Map, Set, WeakMap, WeakSet, Promise, Date, RegExp, URL, Uint8Array, Float32Array, Int32Array,
    DOMException,
    Blob: class { constructor(parts) { this.parts = parts; } },
    atob: s => Buffer.from(s, 'base64').toString('binary'),
    location: { hostname: 'test.onion', href: 'http://test.onion/', origin: 'http://test.onion' },
    navigator: {},
    WebAssembly: { compile: () => {} },
    Worker: function (u, o) { workersSpawned.push({ u, o }); },
    Element: { prototype: { getBoundingClientRect: () => ({ left: 10.1234, top: 20.6789, width: 100.333, height: 30.888, right: 110.456, bottom: 51.567 }) } },
    Range: { prototype: { getBoundingClientRect: () => ({ left: 1.24, top: 2.76, width: 3.12, height: 4.88, right: 4.36, bottom: 7.64 }) } },
    matchMedia: q => ({ media: q, matches: /p3|coarse/i.test(q) }),
    WebGLRenderingContext: function () {},
    AudioContext: function () {},
    AudioDestinationNode: function () {}
  };
  saferSandbox.WebGLRenderingContext.prototype.getParameter = p => (p === 3379 ? 32768 : 0);
  saferSandbox.WebGLRenderingContext.prototype.getSupportedExtensions = () => ['EXT_unique_gpu_secret'];
  saferSandbox.URL.createObjectURL = b => `blob:${b.parts.join('')}`;
  saferSandbox.window = saferSandbox;
  saferSandbox.self = saferSandbox;
  vm.createContext(saferSandbox);
  vm.runInContext(saferScript, saferSandbox);

  assert.equal(saferSandbox.WebAssembly, undefined);
  new saferSandbox.Worker('/mod.mjs', { type: 'module' });
  assert.ok(workersSpawned[0].u.includes("import(\"http://test.onion/mod.mjs\")"));
  new saferSandbox.Worker('data:application/javascript,console.log(1)');
  assert.ok(workersSpawned[1].u.includes('console.log(1)'));
  assert.equal(saferSandbox.Element.prototype.getBoundingClientRect().width, 100.5);
  assert.equal(new saferSandbox.WebGLRenderingContext().getParameter(3379), 16384);
  assert.equal(new saferSandbox.WebGLRenderingContext().getSupportedExtensions().includes('EXT_unique_gpu_secret'), false);
  assert.equal(saferSandbox.matchMedia('(color-gamut: p3)').matches, false);
  assert.equal(saferSandbox.matchMedia('(any-pointer: coarse)').matches, false);
  assert.equal(new saferSandbox.AudioContext().sampleRate, 44100);
  assert.equal(new saferSandbox.AudioDestinationNode().maxChannelCount, 2);

  // Android geckoview-config.yaml + HardenedGeckoEngine.kt fixes
  const geckoYamlPath = path.join(REPO_ROOT, 'zaslon-android', 'app', 'src', 'main', 'assets', 'geckoview-config.yaml');
  if (fs.existsSync(geckoYamlPath)) {
    const geckoYaml = fs.readFileSync(geckoYamlPath, 'utf8');
    assert.ok(geckoYaml.includes('privacy.donottrackheader.enabled: false'));
    assert.ok(geckoYaml.includes('network.http.referer.XOriginPolicy: 1'));
    assert.ok(geckoYaml.includes('network.trr.excluded-domains: "onion"'));
    assert.ok(geckoYaml.includes('network.dns.blockDotOnion: false'));
  }

  const geckoKtPath = path.join(REPO_ROOT, 'zaslon-android', 'app', 'src', 'main', 'java', 'com', 'zaslon', 'browser', 'engine', 'HardenedGeckoEngine.kt');
  if (fs.existsSync(geckoKtPath)) {
    const geckoKt = fs.readFileSync(geckoKtPath, 'utf8');
    assert.ok(geckoKt.includes('val trrMode = if (useStaticProxy) 0 else 3'));
    assert.ok(geckoKt.includes('javascript.options.ion'));
    assert.ok(geckoKt.includes('javascript.options.wasm'));
  }
});

test('Daily vs Strict anonymity upgrades: zero DOM markers, [native code] YT hooks, 60Hz rAF, font/WebGL blocks, strict Worker parity, ETag/telemetry stripping, and encrypted shield rules', async () => {
  const { applyChromiumHardeningFlags } = require('../src/privacy/chromium-hardening');
  const { EncryptedVault } = require('../src/storage/encrypted-vault');
  const { AdblockAndInspectorEngine } = require('../src/privacy/adblock-engine');

  // 1. Chromium flags enforce sRGB profile and disable Privacy Sandbox / FencedFrames
  const switches = [];
  applyChromiumHardeningFlags({ commandLine: { appendSwitch: (k, v) => switches.push([k, v]) } });
  const swMap = new Map(switches);
  assert.equal(swMap.get('force-color-profile'), 'srgb');
  const disabled = String(swMap.get('disable-features') || '').split(',');
  assert.ok(disabled.includes('PrivacySandboxAdsAPIs'));
  assert.ok(disabled.includes('FencedFrames'));

  // 2. page-preload.js leaks zero zaslon DOM markers & masks YouTube adblock functions as [native code]
  const preloadSrc = fs.readFileSync(path.join(ROOT, 'page-preload.js'), 'utf8');
  assert.equal(preloadSrc.includes('data-zaslon-cookie-shield'), false);
  assert.equal(preloadSrc.includes('zaslonConsentHidden'), false);

  const buildMain = new Function(`${extractFunctionSource(preloadSrc, 'buildMainWorldShieldScript')}; return buildMainWorldShieldScript;`)();
  const buildYt = new Function(`${extractFunctionSource(preloadSrc, 'buildYouTubeAdblockMainWorldScript')}; return buildYouTubeAdblockMainWorldScript;`)();

  function FakeResp() {}
  FakeResp.prototype.json = async () => ({ videoDetails: { id: 'ok' }, adPlacements: ['ad'], playerAds: ['p'] });
  const ytSb = {
    location: { hostname: 'www.youtube.com' },
    ytInitialPlayerResponse: { streamingData: {}, adPlacements: [1], playerAds: [2] },
    Response: FakeResp,
    Object, Function, WeakMap
  };
  ytSb.window = ytSb;
  vm.createContext(ytSb);
  vm.runInContext(buildYt(), ytSb);
  assert.equal('adPlacements' in ytSb.ytInitialPlayerResponse, false);
  assert.match(ytSb.Function.prototype.toString.call(ytSb.Response.prototype.json), /\[native code\]/);
  const jsonOut = await new ytSb.Response().json();
  assert.equal('adPlacements' in jsonOut, false);
  assert.equal('playerAds' in jsonOut, false);

  // 3. Normal (standard) mode keeps YouTube/WASM/rAF intact yet strips hardware trackers
  function StdNav() {}
  Object.defineProperties(StdNav.prototype, {
    connection: { get: () => ({ rtt: 50 }), configurable: true },
    bluetooth: { get: () => ({}), configurable: true },
    usb: { get: () => ({}), configurable: true },
    hid: { get: () => ({}), configurable: true },
    serial: { get: () => ({}), configurable: true },
    getBattery: { value: async () => ({ level: 0.5 }), configurable: true },
    getGamepads: { value: () => [{ id: 'Pad' }], configurable: true },
    language: { get: () => 'tr-TR', configurable: true }
  });
  const stdSb = {
    Object, Promise, DOMException, Date, Intl, URL, Blob, WeakSet, WeakMap, Math,
    location: { hostname: 'www.youtube.com', href: 'https://www.youtube.com/watch?v=1' },
    Navigator: StdNav,
    navigator: Object.create(StdNav.prototype),
    WebAssembly: { compile: () => {} },
    requestAnimationFrame: cb => cb(123.4567)
  };
  stdSb.window = stdSb;
  vm.createContext(stdSb);
  vm.runInContext(buildMain('salt-std', 'standard', false, false, '144', 'tor'), stdSb);
  assert.equal(stdSb.navigator.connection, undefined);
  assert.equal(stdSb.navigator.bluetooth, undefined);
  assert.equal(stdSb.navigator.usb, undefined);
  assert.equal(stdSb.navigator.hid, undefined);
  assert.equal(stdSb.navigator.serial, undefined);
  assert.equal(stdSb.navigator.getBattery, undefined);
  assert.deepEqual(Array.from(stdSb.navigator.getGamepads()), []);
  assert.equal(typeof stdSb.WebAssembly.compile, 'function');
  assert.equal(stdSb.navigator.language, 'tr-TR');
  let stdRafTs = 0;
  stdSb.requestAnimationFrame(ts => { stdRafTs = ts; });
  assert.equal(stdRafTs, 123.4567);

  // 4. Strict (Tor / safest) mode: 60Hz rAF, null WEBGL_debug_renderer_info, FontFaceSet allowlist, AudioWorklet off, Worker parity + nested Worker
  const spawnedBlobs = [];
  function StrictNav() {}
  Object.defineProperties(StrictNav.prototype, {
    storage: { value: { estimate: async () => ({ quota: 999, usage: 10 }) }, configurable: true }
  });
  function FakeFontFaceSet() {}
  FakeFontFaceSet.prototype.check = () => true;
  FakeFontFaceSet.prototype.forEach = () => {};
  const fakeFontList = Object.create(FakeFontFaceSet.prototype);
  function FakeStrictWebGL() {}
  FakeStrictWebGL.prototype.getExtension = n => ({ ext: n });
  FakeStrictWebGL.prototype.getParameter = () => 0;

  let injectedIframePatched = false;
  function FakeElem() {}
  let innerHtmlStore = '';
  Object.defineProperty(FakeElem.prototype, 'innerHTML', {
    configurable: true,
    enumerable: true,
    get() { return innerHtmlStore; },
    set(v) { innerHtmlStore = v; }
  });
  FakeElem.prototype.insertAdjacentHTML = function () {};
  FakeElem.prototype.querySelectorAll = () => [{
    contentWindow: {
      Object, Promise, DOMException, Date, Intl, URL, Blob,
      Navigator: function () {},
      navigator: {},
      setAudioFlag() { injectedIframePatched = true; }
    }
  }];

  const strictSb = {
    Object, Array, String, Number, Boolean, Math, JSON, Map, Set, WeakMap, WeakSet, Promise, Date, RegExp, URL, Symbol,
    Uint8Array, Uint8ClampedArray, Float32Array, Int32Array, DOMException,
    Blob: class { constructor(parts) { this.parts = parts; } },
    atob: s => Buffer.from(s, 'base64').toString('binary'),
    location: { hostname: 'tor-audit.onion', href: 'http://tor-audit.onion/', origin: 'http://tor-audit.onion' },
    Navigator: StrictNav,
    navigator: Object.create(StrictNav.prototype),
    requestAnimationFrame: cb => cb(105.9),
    WebGLRenderingContext: FakeStrictWebGL,
    FontFaceSet: FakeFontFaceSet,
    document: { fonts: fakeFontList },
    Element: FakeElem,
    AudioWorklet: function () {},
    AudioWorkletNode: function () {},
    Worker: function (u, o) { spawnedBlobs.push({ u, o }); }
  };
  strictSb.URL.createObjectURL = b => b.parts.join('');
  strictSb.document.fonts = fakeFontList;
  strictSb.window = strictSb;
  strictSb.self = strictSb;
  vm.createContext(strictSb);
  vm.runInContext(buildMain('salt-strict', 'safest', true, true, '144', 'tor'), strictSb);

  let strictRafTs = 0;
  strictSb.requestAnimationFrame(ts => { strictRafTs = ts; });
  assert.equal(strictRafTs, Math.floor(105.9 / (1000 / 60)) * (1000 / 60));
  assert.equal(new strictSb.WebGLRenderingContext().getExtension('WEBGL_debug_renderer_info'), null);
  assert.notEqual(new strictSb.WebGLRenderingContext().getExtension('OES_texture_float'), null);
  assert.equal(strictSb.document.fonts.check('12px "Segoe UI"'), false);
  assert.equal(strictSb.document.fonts.check('12px Arial'), true);
  assert.equal(strictSb.document.fonts.size, 0);
  assert.equal(strictSb.AudioWorklet, undefined);
  assert.equal(strictSb.AudioWorkletNode, undefined);

  // Trigger innerHTML iframe propagation
  const hostEl = new strictSb.Element();
  hostEl.innerHTML = '<iframe></iframe>';
  const childWin = hostEl.querySelectorAll('iframe')[0].contentWindow;
  assert.equal(childWin.navigator.userAgent, 'Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0');

  // Execute captured workerPrelude inside a real strict-mode Worker sandbox including nested Worker spawn
  new strictSb.Worker('/outer-worker.js');
  assert.equal(spawnedBlobs.length, 1);
  const workerCode = spawnedBlobs[0].u;
  const nestedWorkers = [];
  function WorkerNav() {}
  const workerNav = Object.create(WorkerNav.prototype);
  workerNav.storage = { estimate: async () => ({ quota: 1, usage: 0 }) };
  function WorkerOffscreen2D() {}
  WorkerOffscreen2D.prototype.getImageData = () => ({ data: new Uint8ClampedArray(64).fill(120) });
  const workerSb = {
    Object, Array, Math, JSON, Map, Set, Promise, Date, Intl, RegExp, URL, Uint8ClampedArray,
    Blob: class { constructor(parts) { this.parts = parts; } },
    navigator: workerNav,
    location: { href: 'http://tor-audit.onion/outer-worker.js' },
    OffscreenCanvasRenderingContext2D: WorkerOffscreen2D,
    Performance: function () {},
    performance: { now: () => 5.5 },
    Worker: function (u) { nestedWorkers.push(u); },
    importScripts: () => {}
  };
  workerSb.URL.createObjectURL = b => b.parts.join('');
  workerSb.Performance.prototype = { now: () => 5.5 };
  workerSb.self = workerSb;
  vm.createContext(workerSb);
  vm.runInContext(`"use strict";\n${workerCode}`, workerSb);

  const wEst = await workerSb.navigator.storage.estimate();
  assert.equal(wEst.quota, 2147483648); // Matches main window exactly!
  assert.equal(workerSb.navigator.gpu, undefined);
  assert.ok(new workerSb.Date('2026-06-15T12:00:00Z').toString().includes('GMT+0000'));
  const wPx = new workerSb.OffscreenCanvasRenderingContext2D().getImageData(0, 0, 4, 4);
  assert.ok(wPx.data.some(v => v !== 120));
  // Nested worker spawned inside strict worker wraps cleanly without arguments.callee error
  new workerSb.Worker('/inner-worker.js');
  assert.equal(nestedWorkers.length, 1);
  assert.ok(nestedWorkers[0].includes('importScripts("http://tor-audit.onion/inner-worker.js")'));

  // 5. AdblockAndInspectorEngine stores shield rules encrypted inside EncryptedVault (zero plaintext file) and shreds on panicWipe
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zaslon-shield-vault-'));
  try {
    const vault = new EncryptedVault({ userDataPath: tmpDir });
    const ab1 = new AdblockAndInspectorEngine({ userDataPath: tmpDir, vault });
    ab1.setCustomDomainRule('secret-tracker.example', 'block');
    assert.equal(fs.existsSync(path.join(tmpDir, 'zaslon-shield-rules.json')), false);

    const ab2 = new AdblockAndInspectorEngine({ userDataPath: tmpDir, vault });
    assert.equal(ab2.customDomainRules['secret-tracker.example'], 'block');

    vault.panicWipe(false);
    ab2.clearCustomRules();
    const ab3 = new AdblockAndInspectorEngine({ userDataPath: tmpDir, vault });
    assert.equal(ab3.customDomainRules['secret-tracker.example'], undefined);
    try { vault.close?.(); } catch {}
    try { vault.db?.close?.(); } catch {}
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }

  // 6. main.js strips 3rd-party ETag/If-None-Match/NEL/Report-To/prefetch Link headers, cancels ping/cspReport, and awaits Tor pre-sync on history navigation
  const mainSrc = fs.readFileSync(path.join(ROOT, 'main.js'), 'utf8');
  assert.ok(mainSrc.includes("details.resourceType === 'ping' || details.resourceType === 'cspReport'"));
  assert.ok(mainSrc.includes("lower === 'if-none-match' || lower === 'if-modified-since'"));
  assert.ok(mainSrc.includes("low === 'set-cookie' || low === 'etag'"));
  assert.ok(mainSrc.includes("low === 'nel' || low === 'report-to' || low === 'reporting-endpoints'"));
  assert.ok(mainSrc.includes('prepareTorSessionForHistoryOffset'));
});
