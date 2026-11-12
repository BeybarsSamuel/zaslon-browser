const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const {
  TELEMETRY_HOSTS,
  applyChromiumHardeningFlags,
  isTelemetryHost
} = require('../src/privacy/chromium-hardening');
const { AdblockAndInspectorEngine } = require('../src/privacy/adblock-engine');
const { SponsorBlockService, getVideoIdHashPrefix } = require('../src/media/sponsorblock');
const { RssService } = require('../src/tools/rss-service');
const { TorManager } = require('../src/network/tor-manager');
const { YtDlpManager } = require('../src/media/ytdlp-manager');

test('chromium-hardening fixes leading space typos and enables disable-quic & spellcheck hardening', () => {
  assert.equal(TELEMETRY_HOSTS.has('woolyss.com'), true);
  assert.equal(TELEMETRY_HOSTS.has('redirector.gvt1.com'), true);
  assert.equal(isTelemetryHost('redirector.gvt1.com'), true);
  assert.equal(isTelemetryHost('edgedl.me.gvt1.com'), true);
  assert.equal(isTelemetryHost('tools.google.com'), true);

  const appended = [];
  applyChromiumHardeningFlags({
    commandLine: {
      appendSwitch: (k, v) => appended.push([k, v])
    }
  });
  const keys = appended.map(([k]) => k);
  assert.equal(keys.includes('disable-quic'), true);
  assert.equal(keys.includes('disable-spell-checking'), true);
  assert.equal(keys.includes('disable-metrics-reporting'), true);
  const feat = appended.find(([k]) => k === 'disable-features');
  assert.ok(feat && feat[1].includes('SpellcheckDictionaryDownload'));
});

test('adblock-engine loads bundled snapshot offline and blocks gumgum, ws/wss, and mainFrame', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zaslon-ab-'));
  try {
    const snapPath = path.join(__dirname, '..', 'resources', 'adblock-snapshot.bin');
    assert.equal(fs.existsSync(snapPath), true);

    const engine = new AdblockAndInspectorEngine({
      userDataPath: tmpDir,
      resourcesPath: path.join(__dirname, '..', 'resources')
    });
    engine.registerWebContents(10, 'tab-1');

    const prefs = { tele: true, adblock: true, securityLevel: 'standard' };
    const subGum = engine.evaluateRequest(
      { url: 'https://g2.gumgum.com/javascripts/ggv2.js', resourceType: 'script', webContentsId: 10, referrer: 'https://example.com/' },
      prefs
    );
    assert.equal(subGum.cancel, true);

    const wsBlocked = engine.evaluateRequest(
      { url: 'wss://doubleclick.net/live', resourceType: 'webSocket', webContentsId: 10, referrer: 'https://example.com/' },
      prefs
    );
    assert.equal(wsBlocked.cancel, true);

    const mainBlocked = engine.evaluateRequest(
      { url: 'https://popads.net/pop.html', resourceType: 'mainFrame', webContentsId: 10, referrer: '' },
      prefs
    );
    assert.equal(mainBlocked.cancel, true);

    engine.setCustomDomainRule('blocked.example', 'block');
    const customMain = engine.evaluateRequest(
      { url: 'https://blocked.example/index.html', resourceType: 'mainFrame', webContentsId: 10, referrer: '' },
      prefs
    );
    assert.equal(customMain.cancel, true);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('SponsorBlock uses 4-char SHA-256 k-anonymity without ZaslonBrowser UA and fails closed when Tor offline', async () => {
  const seen = [];
  const videoId = 'dQw4w9WgXcQ';
  const expectedPrefix = getVideoIdHashPrefix(videoId);
  assert.equal(expectedPrefix.length, 4);

  const sb = new SponsorBlockService({
    fetchFn: async (url, opts) => {
      seen.push({ url, opts });
      return {
        ok: true,
        status: 200,
        json: async () => [
          {
            videoID: 'OTHERVIDEO1',
            hash: expectedPrefix + 'aaaa',
            segments: [{ segment: [1, 9], UUID: 'wrong-1', category: 'sponsor' }]
          },
          {
            videoID: videoId,
            hash: expectedPrefix + 'bbbb',
            segments: [{ segment: [10, 25], UUID: 'right-1', category: 'sponsor' }]
          }
        ]
      };
    }
  });

  // Fail closed when Tor required but not connected
  const blockedSegs = await sb.getSegmentsForVideo(videoId, { torRequired: true, torConnected: false });
  assert.deepEqual(blockedSegs, []);
  assert.equal(seen.length, 0);

  const segs = await sb.getSegmentsForVideo(`https://www.youtube.com/watch?v=${videoId}`);
  assert.equal(seen.length, 1);
  assert.ok(seen[0].url.includes(`/api/skipSegments/${expectedPrefix}?`));
  assert.equal(seen[0].url.includes(videoId), false);
  assert.equal(seen[0].opts.credentials, 'omit');
  assert.equal(seen[0].opts.referrerPolicy, 'no-referrer');
  assert.equal(/ZaslonBrowser/i.test(seen[0].opts.headers['User-Agent']), false);
  assert.equal(segs.length, 1);
  assert.equal(segs[0].uuid, 'right-1');
});

test('RssService removes ZaslonRSS UA, enforces omit credentials, and fails closed if Tor required offline', async () => {
  const calls = [];
  const rss = new RssService({
    fetchFn: async (url, opts) => {
      calls.push({ url, opts });
      return {
        ok: true,
        status: 200,
        text: async () => '<rss><channel><title>Test</title><item><title>Hi</title><link>https://example.com/1</link></item></channel></rss>'
      };
    }
  });

  const closed = await rss.fetchSingleFeed('https://example.com/feed.xml', { torRequired: true, torConnected: false });
  assert.equal(closed.ok, false);
  assert.equal(calls.length, 0);

  const res = await rss.fetchSingleFeed('https://example.com/feed.xml');
  assert.equal(res.ok, true);
  assert.ok(calls.length >= 1);
  for (const c of calls) {
    assert.equal(/ZaslonRSS/i.test(c.opts.headers['User-Agent']), false);
    assert.equal(c.opts.credentials, 'omit');
  }
});

test('TorManager and YtDlpManager enforce SHA-256 binary integrity and Tor fail-closed', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zaslon-bin-'));
  try {
    const tor = new TorManager({
      userDataPath: tmpDir,
      fetchFn: async () => ({
        ok: true,
        arrayBuffer: async () => Buffer.alloc(1_100_000, 0x41)
      })
    });
    const torRes = await tor.installTorBinary();
    assert.equal(torRes.state, 'error');
    assert.match(torRes.lastError, /SHA-256 mismatch/);
    assert.equal(fs.existsSync(path.join(tmpDir, 'bin', 'tor', 'tor-expert-bundle.tar.gz')), false);

    const payload = Buffer.from('fake-yt-dlp-binary');
    const goodHash = crypto.createHash('sha256').update(payload).digest('hex');
    const badHash = '0'.repeat(64);
    const binName = process.platform === 'win32' ? 'yt-dlp.exe' : 'yt-dlp';
    const seenHeaders = [];

    const ytdlpBad = new YtDlpManager({
      userDataPath: tmpDir,
      fetchFn: async (url, opts) => {
        seenHeaders.push(opts?.headers || {});
        if (url.endsWith('SHA2-256SUMS')) {
          return { ok: true, status: 200, text: async () => `${badHash}  ${binName}\n` };
        }
        return { ok: true, status: 200, arrayBuffer: async () => payload };
      }
    });
    const failInstall = await ytdlpBad.installYtDlpBinary();
    assert.equal(failInstall.ok, false);
    assert.match(failInstall.error, /SHA-256 mismatch/);
    assert.equal(fs.existsSync(path.join(tmpDir, 'bin', binName)), false);
    assert.equal(seenHeaders.some(h => /ZaslonBrowser/i.test(h['User-Agent'] || '')), false);

    const ytdlpGood = new YtDlpManager({
      userDataPath: tmpDir,
      fetchFn: async url => {
        if (url.endsWith('SHA2-256SUMS')) {
          return { ok: true, status: 200, text: async () => `${goodHash}  ${binName}\n` };
        }
        return { ok: true, status: 200, arrayBuffer: async () => payload };
      }
    });
    const okInstall = await ytdlpGood.installYtDlpBinary();
    assert.equal(okInstall.hasYtDlp, true);
    assert.equal(fs.existsSync(path.join(tmpDir, 'bin', binName)), true);

    const torBlockedDl = await ytdlpGood.startDownload({
      url: 'https://example.com/video.mp4',
      torBlocked: true,
      torBlockedReason: 'Tor required'
    });
    assert.equal(torBlockedDl.ok, false);
    assert.equal(torBlockedDl.error, 'Tor required');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('ui.html eliminates Google and external DuckDuckGo favicon requests', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'ui.html'), 'utf8');
  assert.equal(/s2\/favicons/i.test(html), false);
  assert.equal(/icons\.duckduckgo\.com/i.test(html), false);
});

test('Faz 2, 4 & 9.1 regression: chromium-hardening DNS bootstrap, ephemeral UA isolation, Tor redirects, panicBurn & userscripts', () => {
  const appended = [];
  applyChromiumHardeningFlags({
    commandLine: {
      appendSwitch: (k, v) => appended.push([k, v])
    }
  });
  const map = Object.fromEntries(appended);
  assert.equal('dns-prefetch-disable' in map, true);
  assert.equal('enforce-webrtc-ip-permission-check' in map, true);
  assert.equal(map['webrtc-ip-handling-policy'], 'disable_non_proxied_udp');
  assert.ok(map['host-resolver-rules'].includes('MAP dns.quad9.net 9.9.9.9'));
  assert.ok(map['host-resolver-rules'].includes('MAP cloudflare-dns.com 1.1.1.1'));

  const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'main.js'), 'utf8');
  // Every ephemeral/DoH/translator session is hardened with UNIFORM_BROWSER_UA & sec-ch-ua stripping
  assert.equal(mainSrc.includes("session.fromPartition('zaslon-ephemeral-translator')"), true); // inside wipeAllSessionsAndStorage only
  const translatorInstallBlock = mainSrc.slice(
    mainSrc.indexOf("ipcMain.handle('translatorInstallModel'"),
    mainSrc.indexOf("ipcMain.handle('translatorDeleteModel'")
  );
  assert.equal(translatorInstallBlock.includes('getHardenedEphemeralSession('), true);
  assert.equal(translatorInstallBlock.includes('ensureSessionReady('), true);
  assert.equal(mainSrc.includes("lower === 'x-client-data'"), true);

  // Tor navigation & redirect dynamic firstPartyHost isolation + panicBurn extraSessions before views.clear()
  assert.equal(mainSrc.includes("wc.on('will-navigate'"), true);
  assert.equal(mainSrc.includes("wc.on('will-redirect'"), true);
  assert.equal(mainSrc.includes('extraSessionsToWipe'), true);
  assert.equal(mainSrc.includes('wipeAllSessionsAndStorage({ extraSessions: extraSessionsToWipe })'), true);

  // TorManager no longer auto-pings check.torproject.org on start()
  const torMgrSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'network', 'tor-manager.js'), 'utf8');
  const startSection = torMgrSrc.slice(torMgrSrc.indexOf('async start('), torMgrSrc.indexOf('async verifyTorExitIp('));
  assert.equal(startSection.includes('verifyTorExitIp'), false);

  // UserScriptManager defaults builtin-copy-unlock off and leaves zero DOM/localStorage signatures
  const { UserScriptManager } = require('../src/tools/userscript-manager');
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zaslon-us-'));
  try {
    const us = new UserScriptManager({ userDataPath: tmpDir });
    const copyUnlock = us.scripts.find(s => s.id === 'builtin-copy-unlock');
    assert.equal(copyUnlock.enabled, false);
    const bundle = us.buildInjectionBundleForUrl('https://www.youtube.com/watch?v=123');
    assert.equal(bundle.includes('data-zaslon-userscript'), false);
    assert.equal(bundle.includes('__zas_gm_'), false);
    assert.equal(bundle.includes('localStorage'), false);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
