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

  // Synced UA & userAgentData
  assert.ok(envA.navigator.userAgent.includes('Chrome/144.0.0.0'));
  assert.ok(!envA.navigator.userAgent.includes('Electron'));
  assert.equal(envA.navigator.userAgentData.platform, 'Windows');
  const hev = await envA.navigator.userAgentData.getHighEntropyValues(['uaFullVersion', 'platformVersion', 'bitness']);
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

  const bgSrc = fs.readFileSync(
    path.join(REPO_ROOT, 'zaslon-android', 'app', 'src', 'main', 'assets', 'extensions', 'zaslon-shield', 'background.js'),
    'utf8'
  );
  // Syntax check background.js cleanly
  new vm.Script(bgSrc);
  assert.ok(bgSrc.includes('nonTorTabIds'));
  assert.ok(bgSrc.includes('torServiceRequestUrls'));
  assert.ok(bgSrc.includes('nonTorServiceRequestUrls'));
  assert.ok(bgSrc.includes('extractRootDomain'));
  assert.ok(bgSrc.includes('circuitEpoch'));

  const geckoYaml = fs.readFileSync(
    path.join(REPO_ROOT, 'zaslon-android', 'app', 'src', 'main', 'assets', 'geckoview-config.yaml'),
    'utf8'
  );
  assert.ok(geckoYaml.includes('media.peerconnection.enabled: false'));
  assert.ok(geckoYaml.includes('network.proxy.socks_remote_dns: true'));
  assert.ok(geckoYaml.includes('privacy.resistFingerprinting.letterboxing: true'));
  assert.ok(geckoYaml.includes('privacy.spoof_english: 2'));

  const lanKt = fs.readFileSync(
    path.join(REPO_ROOT, 'zaslon-android', 'app', 'src', 'main', 'java', 'com', 'zaslon', 'browser', 'storage', 'LanSyncClient.kt'),
    'utf8'
  );
  assert.equal(lanKt.includes('Build.MODEL'), false);
});
