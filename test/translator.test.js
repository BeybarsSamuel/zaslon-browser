const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { TranslatorService } = require('../src/tools/translator');
const {
  LocalTranslatorEngine,
  isLoopbackUrl,
  detectSourceLangOffline
} = require('../src/tools/local-translator');

test('isLoopbackUrl accepts loopback and blocks non-loopback / non-http URLs', () => {
  assert.equal(isLoopbackUrl('http://127.0.0.1:5000').ok, true);
  assert.equal(isLoopbackUrl('http://localhost:11434/').url, 'http://localhost:11434');
  assert.equal(isLoopbackUrl('http://[::1]:8080').ok, true);

  assert.equal(isLoopbackUrl('https://evil.com:5000').ok, false);
  assert.equal(isLoopbackUrl('http://192.168.1.50:5000').ok, false);
  assert.equal(isLoopbackUrl('file:///etc/passwd').ok, false);
  assert.equal(isLoopbackUrl('').ok, false);
});

test('detectSourceLangOffline identifies Turkish, Russian Cyrillic, and Latin English', () => {
  assert.equal(detectSourceLangOffline('Merhaba dünya güvenlik şifresi'), 'tr');
  assert.equal(detectSourceLangOffline('Привет мир'), 'ru');
  assert.equal(detectSourceLangOffline('Privacy is a human right'), 'en');
});

test('TranslatorService local_only makes ZERO network calls and returns needsLocalModel if missing', async () => {
  const fetchCalls = [];
  const spyFetch = async url => {
    fetchCalls.push(url);
    throw new Error('Network should never be called in local_only mode');
  };

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zaslon-tr-test-'));
  try {
    const svc = new TranslatorService({
      modelsDir: tmpDir,
      fetchFn: spyFetch
    });

    // Matched dictionary words work 100% offline
    const dictHit = await svc.translateText(
      { q: 'privacy browser security', source: 'en', target: 'tr' },
      { engine: 'local_only', isTorTab: false }
    );
    assert.equal(dictHit.ok, true);
    assert.equal(dictHit.privacyLevel, 'offline');
    assert.equal(dictHit.routedVia, 'offline');
    assert.match(dictHit.translatedText.toLowerCase(), /gizlilik/);
    assert.equal(fetchCalls.length, 0);

    // Unmatched sentence cleanly asks for local model with ZERO network calls
    const miss = await svc.translateText(
      { q: 'Quantum entanglement telemetry anomaly', source: 'en', target: 'tr' },
      { engine: 'local_only', isTorTab: true }
    );
    assert.equal(miss.ok, false);
    assert.equal(miss.needsLocalModel, true);
    assert.equal(miss.privacyLevel, 'offline');
    assert.equal(fetchCalls.length, 0);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('TranslatorService default auto_private NEVER silently calls Google in normal or Tor tabs', async () => {
  const fetchCalls = [];
  const mockFetch = async (url, init) => {
    fetchCalls.push({ url, init });
    if (url.includes('/api/v1/')) {
      return {
        ok: true,
        async json() {
          return { translation: 'Merhaba dünya', info: { detectedSource: 'en' } };
        }
      };
    }
    return { ok: false, status: 500, async json() { return {}; } };
  };

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zaslon-tr-test-'));
  try {
    const svc = new TranslatorService({ modelsDir: tmpDir, fetchFn: mockFetch });
    const res = await svc.translateText(
      { q: 'Hello world', source: 'auto', target: 'tr' },
      { engine: 'auto_private', isTorTab: false, routing: 'tab' }
    );
    assert.equal(res.ok, true);
    assert.equal(res.translatedText, 'Merhaba dünya');
    assert.equal(res.engineUsed, 'lingva');
    assert.equal(res.privacyLevel, 'clearnet-anonymous');
    assert.ok(fetchCalls.length >= 1);
    assert.equal(
      fetchCalls.some(c => c.url.includes('translate.googleapis.com')),
      false
    );
    assert.equal(fetchCalls[0].init.credentials, 'omit');
    assert.equal(fetchCalls[0].init.referrerPolicy, 'no-referrer');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('TranslatorService locks Google GTX on Tor tab & offline route, allows explicit opt-in on normal tab', async () => {
  const fetchCalls = [];
  const mockFetch = async url => {
    fetchCalls.push(url);
    if (url.includes('translate.googleapis.com')) {
      return {
        ok: true,
        async json() {
          return [[['Günlük doküman çevirisi', 'Daily document translation']], null, 'en'];
        }
      };
    }
    if (url.includes('/api/v1/')) {
      return {
        ok: true,
        async json() {
          return { translation: 'Tor güvenli çeviri', info: { detectedSource: 'en' } };
        }
      };
    }
    return { ok: false, status: 500, async json() { return {}; } };
  };

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zaslon-tr-test-'));
  try {
    const svc = new TranslatorService({ modelsDir: tmpDir, fetchFn: mockFetch });

    // 1. Tor tab explicitly requesting google_gtx -> blockedByTorLock, 0 fetches
    const torBlocked = await svc.translateText(
      { q: 'Secret Tor text', source: 'en', target: 'tr' },
      { engine: 'google_gtx', isTorTab: true, routing: 'tab' }
    );
    assert.equal(torBlocked.ok, false);
    assert.equal(torBlocked.blockedByTorLock, true);
    assert.equal(fetchCalls.length, 0);

    // 2. Offline routing forcing google_gtx -> resolveEffectivePolicy coerces away from Google, 0 fetches
    const offlineBlocked = await svc.translateText(
      { q: 'Quantum telemetry payload', source: 'en', target: 'tr' },
      { engine: 'google_gtx', isTorTab: false, routing: 'offline' }
    );
    assert.equal(offlineBlocked.ok, false);
    assert.equal(offlineBlocked.routedVia, 'offline');
    assert.equal(fetchCalls.length, 0);

    // 3. Tor tab requesting auto_fast -> silently downgrades to auto_private, never calls Google
    const torDowngrade = await svc.translateText(
      { q: 'Tor safe fast test', source: 'en', target: 'tr' },
      { engine: 'auto_fast', isTorTab: true, routing: 'tab' }
    );
    assert.equal(torDowngrade.ok, true);
    assert.equal(torDowngrade.privacyLevel, 'tor');
    assert.equal(
      fetchCalls.some(u => u.includes('translate.googleapis.com')),
      false
    );

    // 4. Normal tab explicitly selecting google_gtx -> works and labels clearnet-google
    const normalOptIn = await svc.translateText(
      { q: 'Daily document translation', source: 'en', target: 'tr' },
      { engine: 'google_gtx', isTorTab: false, routing: 'direct' }
    );
    assert.equal(normalOptIn.ok, true);
    assert.equal(normalOptIn.engineUsed, 'google_gtx');
    assert.equal(normalOptIn.privacyLevel, 'clearnet-google');
    assert.equal(normalOptIn.translatedText, 'Günlük doküman çevirisi');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('TranslatorService Tor disconnected fails closed for network engines without clearnet leak', async () => {
  let called = 0;
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zaslon-tr-tordown-'));
  try {
    const svc = new TranslatorService({
      modelsDir: tmpDir,
      fetchFn: async () => {
        called++;
        throw new Error('Must not leak to clearnet when Tor is disconnected');
      }
    });

    const res = await svc.translateText(
      { q: 'Hello Tor', source: 'en', target: 'tr' },
      {
        engine: 'auto_private',
        isTorTab: true,
        routing: 'tab',
        torNotReadyError: 'Tor bağlantısı hazır değil'
      }
    );
    assert.equal(res.ok, false);
    assert.equal(res.blockedByTorLock, true);
    assert.equal(called, 0);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('LocalTranslatorEngine + TranslatorService real loopback HTTP LibreTranslate & Ollama batch without delimiter corruption', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zaslon-tr-srv-'));
  const srv = http.createServer((req, res) => {
    let body = '';
    req.on('data', c => (body += c));
    req.on('end', () => {
      res.setHeader('Content-Type', 'application/json');
      const parsed = JSON.parse(body || '{}');
      if (req.url === '/translate') {
        res.end(JSON.stringify({ translatedText: `LT:${parsed.q}` }));
      } else if (req.url === '/api/generate') {
        const last = String(parsed.prompt || '').split('\n\n').pop();
        res.end(JSON.stringify({ response: `OL:${last}` }));
      } else {
        res.statusCode = 404;
        res.end('{}');
      }
    });
  });

  await new Promise(resolve => srv.listen(0, '127.0.0.1', resolve));
  const addr = srv.address();
  const baseUrl = `http://127.0.0.1:${addr.port}`;

  try {
    const svc = new TranslatorService({
      localEngine: new LocalTranslatorEngine({
        modelsDir: tmpDir
      })
    });

    const ltBatch = await svc.translateBatch(
      { texts: ['First block', 'Second block'], source: 'en', target: 'tr' },
      {
        engine: 'local_server',
        localConfig: { type: 'libretranslate', url: baseUrl }
      }
    );
    assert.equal(ltBatch.ok, true);
    assert.deepEqual(ltBatch.translations, ['LT:First block', 'LT:Second block']);
    assert.equal(ltBatch.privacyLevel, 'offline');

    const olBatch = await svc.translateBatch(
      { texts: ['Alpha', 'Beta'], source: 'en', target: 'tr' },
      {
        engine: 'local_server',
        localConfig: { type: 'ollama', url: baseUrl, model: 'qwen2.5:3b' }
      }
    );
    assert.equal(olBatch.ok, true);
    assert.deepEqual(olBatch.translations, ['OL:Alpha', 'OL:Beta']);

    // Reject remote HTTP server in local_server mode
    const remoteReject = await svc.translateText(
      { q: 'Blocked', source: 'en', target: 'tr' },
      {
        engine: 'local_server',
        localConfig: { type: 'libretranslate', url: 'https://remote.example.com' }
      }
    );
    assert.equal(remoteReject.ok, false);
    assert.match(remoteReject.error, /127\.0\.0\.1|localhost/);
  } finally {
    srv.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('TranslatorService batch delegates array directly to localEngine.translateWithNmt when available', async () => {
  let batchCalls = 0;
  const mockLocalEngine = {
    async translateWithNmt(input) {
      batchCalls++;
      assert.equal(Array.isArray(input), true);
      return {
        ok: true,
        translations: input.map(s => `NMT(${s})`),
        provider: 'Yerel NMT (WASM · en→tr)',
        engineUsed: 'local_nmt',
        privacyLevel: 'offline'
      };
    }
  };

  const svc = new TranslatorService({ localEngine: mockLocalEngine });
  const out = await svc.translateBatch(
    { texts: ['One', 'Two', 'Three'], source: 'en', target: 'tr' },
    { engine: 'auto_private', isTorTab: true }
  );
  assert.equal(batchCalls, 1);
  assert.equal(out.ok, true);
  assert.equal(out.engineUsed, 'local_nmt');
  assert.equal(out.privacyLevel, 'offline');
  assert.deepEqual(out.translations, ['NMT(One)', 'NMT(Two)', 'NMT(Three)']);
});
