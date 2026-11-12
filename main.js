const {
  app,
  BrowserWindow,
  WebContentsView,
  ipcMain,
  session,
  Menu,
  shell,
  clipboard,
  net,
  nativeTheme,
  nativeImage,
  safeStorage
} = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const http = require('http');
const tls = require('tls');
const crypto = require('crypto');
const { spawn } = require('child_process');

const {
  applyChromiumHardeningFlags,
  hardenWebContents,
  computeLetterboxBounds,
  getUniformChromeMajor,
  getUniformBrowserUserAgent
} = require('./src/privacy/chromium-hardening');
const { cleanTrackingUrl } = require('./src/privacy/url-cleaner');
const { AdblockAndInspectorEngine } = require('./src/privacy/adblock-engine');
const { performMetaSearch } = require('./src/search/meta-search');
const { DohManager } = require('./src/network/doh-manager');
const { DpiManager } = require('./src/network/dpi-manager');
const { TorManager, extractRootDomain } = require('./src/network/tor-manager');
const { StreamSniffer } = require('./src/media/stream-sniffer');
const { SponsorBlockService } = require('./src/media/sponsorblock');
const { YtDlpManager } = require('./src/media/ytdlp-manager');
const { TranslatorService } = require('./src/tools/translator');
const { saveSingleFileArchive } = require('./src/tools/singlefile');
const {
  captureVisibleViewport,
  captureCroppedRegion,
  captureFullPageScrolling
} = require('./src/tools/screenshot-full');
const { RssService } = require('./src/tools/rss-service');
const { UserScriptManager } = require('./src/tools/userscript-manager');
const { EncryptedVault } = require('./src/storage/encrypted-vault');
const { LanSyncManager } = require('./src/storage/lan-sync');
const { GitHubUpdater } = require('./src/storage/github-updater');
const { t, setLang, getLang, normalizeLang } = require('./src/i18n/translations');

// 1. Zırh: Motor daha başlamadan tüm Google/Chromium arka plan servislerini ve WebRTC sızıntısını kapat
try {
  app.name = 'Zaslon Browser';
  app.setName('Zaslon Browser');
  if (process.platform === 'win32') {
    app.setAppUserModelId('com.zaslon.browser');
  }
} catch {}
applyChromiumHardeningFlags(app);

if (!app.requestSingleInstanceLock()) {
  app.quit();
  process.exit(0);
}
nativeTheme.themeSource = 'dark';

/* ---------- Gizlilik ayarları ve durum ---------- */
const prefs = {
  adblock: true,
  tele: true,
  fp: true,
  popups: true,
  block3pCookies: true,
  letterbox: false,
  clearOnExit: false,
  clearTabOnClose: false,
  securityLevel: 'standard', // 'standard' | 'safer' | 'safest'
  dohEnabled: true,
  dohProvider: 'quad9',
  dohCustomUrl: '',
  dohStrict: true,
  allowExternalTor: false,
  clearTorDataOnExit: false,
  dpi: false,
  dpiMode: 'builtin', // 'builtin' | 'spoofdpi' | 'goodbyedpi'
  dpiSplitProfile: 'sni-frag',
  sponsorBlock: true,
  userscriptsEnabled: true,
  darkReader: false,
  darkReaderSmart: true,
  darkReaderBrightness: 100,
  darkReaderContrast: 96,
  darkReaderSepia: 8,
  darkReaderGrayscale: 0,
  darkReaderDisabledHosts: [],
  darkReaderEnabledHosts: [],
  rgxEnabled: false,
  rgxPreset: 'std',
  rgxVideos: true,
  rgxImages: false,
  rgxHud: true,
  rgxSplit: false,
  rgxSharpness: 55,
  rgxSaturation: 112,
  rgxContrast: 106,
  rgxBrightness: 100,
  rgxDisabledHosts: [],
  trEngine: 'auto_private',
  trRouting: 'tab',
  trLocalServerType: 'libretranslate',
  trLocalServerUrl: '',
  trLocalServerModel: 'qwen2.5:3b',
  trLingvaUrl: 'https://translate.plausibility.cloud',
  metaSearchRouting: 'tab',
  metaSearchRequireTor: false,
  metaSearchRegional: false,
  metaSearchLoadImages: false,
  metaSearchProviders: {
    duckduckgo: true,
    brave: true,
    wikipedia: true,
    instant: true,
    searxng: true,
    yahoo: false
  },
  lang: 'tr'
};

let sessionSalt = crypto.randomBytes(12).toString('hex');
let win = null;
let blockedDelta = 0;
let trackedDelta = 0;
let adblockEngine = null;
let dohManager = null;
let dpiManager = null;
let torManager = null;
let streamSniffer = null;
let sponsorBlockService = null;
let ytDlpManager = null;
let translatorService = null;
let rssService = null;
let userScriptManager = null;
let encryptedVault = null;
let lanSyncManager = null;
let githubUpdater = null;

const send = (c, d) => {
  if (win && !win.isDestroyed()) win.webContents.send(c, d);
};

setInterval(() => {
  if (blockedDelta && win) {
    send('blocked', blockedDelta);
    blockedDelta = 0;
  }
  if (trackedDelta && win) {
    send('tracked', trackedDelta);
    trackedDelta = 0;
  }
}, 800);

/* ---------- Oturumlar (Konteyner başına izole) ---------- */
const prepared = new Set();
const partitionToContainer = new Map();
const sessionProxyPromises = new Map();
const EPHEMERAL_CONTAINERS = new Set(['Anonim', 'Geçici', '🧅 Tor Zırhlı']);
const SERVICE_EPHEMERAL_PARTITION = 'zaslon-ephemeral-services';
const DOH_DIRECT_PARTITION = 'zaslon-ephemeral-doh';
const appliedSessionProxyKeys = new WeakMap();
let defaultSessionHardened = false;

function isAllowedDefaultSessionUrl(urlStr) {
  if (!urlStr) return false;
  if (
    urlStr.startsWith('file://') ||
    urlStr.startsWith('devtools://') ||
    urlStr.startsWith('data:') ||
    urlStr.startsWith('blob:') ||
    urlStr.startsWith('zaslon://')
  ) {
    return true;
  }
  return /^http:\/\/(127\.0\.0\.1|localhost|\[::1\])(?::\d+)?(?:\/|$)/i.test(urlStr);
}

function hardenDefaultSession() {
  if (defaultSessionHardened) return;
  defaultSessionHardened = true;
  const def = session.defaultSession;
  if (!def) return;
  try {
    def.setSpellCheckerEnabled?.(false);
    def.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
    def.webRequest.onBeforeRequest((details, cb) => {
      if (isAllowedDefaultSessionUrl(details.url || '')) {
        return cb({});
      }
      return cb({ cancel: true });
    });
  } catch {}
}

const UNIFORM_CHROME_MAJOR = getUniformChromeMajor();
const UNIFORM_BROWSER_UA = getUniformBrowserUserAgent();
try {
  if (app) app.userAgentFallback = UNIFORM_BROWSER_UA;
} catch {}
const FAIL_CLOSED_TOR_PROXY = {
  mode: 'fixed_servers',
  proxyRules: 'http=127.0.0.1:9;https=127.0.0.1:9;ftp=127.0.0.1:9',
  proxyBypassRules: '<-loopback>'
};
const ALLOWED_NAV_PROTOCOLS = new Set(['http:', 'https:', 'data:', 'blob:', 'about:', 'zaslon:']);
function isAllowedNavProtocol(rawUrl) {
  try {
    const p = new URL(String(rawUrl || '')).protocol.toLowerCase();
    return ALLOWED_NAV_PROTOCOLS.has(p);
  } catch {
    return false;
  }
}
const partitionFirstParty = new Map();

function normalizeContainerName(container) {
  if (!container) return 'Kişisel';
  if (container === 'İş') return 'Banka/İş';
  if (container === 'Anonim') return 'Geçici';
  return container;
}

function getPartitionName(container, tabId = '') {
  const norm = normalizeContainerName(container);
  if (norm === '🧅 Tor Zırhlı' && tabId) {
    return 'zaslon-ephemeral-tor-' + Buffer.from(String(tabId)).toString('hex');
  }
  if (EPHEMERAL_CONTAINERS.has(norm) || EPHEMERAL_CONTAINERS.has(container)) {
    return 'zaslon-ephemeral-' + Buffer.from(norm).toString('hex');
  }
  return 'persist:zaslon-' + Buffer.from(norm).toString('hex');
}

function setSessionProxyWithTracking(part, ses, containerName, firstPartyHost = '') {
  if (firstPartyHost) partitionFirstParty.set(part, firstPartyHost);
  const effectiveFp = firstPartyHost || partitionFirstParty.get(part) || '';
  const p = applyProxyToSession(ses, containerName, effectiveFp).catch(() => {});
  sessionProxyPromises.set(part, p);
  return p;
}

async function applyProxyToSession(ses, containerName, firstPartyHost = '') {
  if (!ses) return;
  const norm = normalizeContainerName(containerName);
  try {
    let targetRules = { mode: 'direct' };
    if (norm === '🧅 Tor Zırhlı') {
      if (torManager) {
        if (firstPartyHost) {
          await torManager.ensureFirstPartyGateway(firstPartyHost);
        } else {
          await torManager.ensureIsolationGateway();
        }
        const torRules = torManager.getTorSessionProxyRules(firstPartyHost);
        targetRules = torRules || FAIL_CLOSED_TOR_PROXY;
      } else {
        targetRules = FAIL_CLOSED_TOR_PROXY;
      }
    } else if (dpiManager && dpiManager.enabled) {
      const dpiRules = dpiManager.getProxyRulesForSession();
      if (dpiRules) {
        targetRules = dpiRules;
      }
    }

    const ruleKey = JSON.stringify(targetRules);
    if (appliedSessionProxyKeys.get(ses) === ruleKey) {
      return;
    }
    await ses.setProxy(targetRules);
    appliedSessionProxyKeys.set(ses, ruleKey);
    await ses.closeAllConnections();
  } catch {}
}

async function applyNetworkProxiesToAllSessions() {
  for (const part of prepared) {
    const cName = partitionToContainer.get(part) || 'Kişisel';
    const fpHost = partitionFirstParty.get(part) || '';
    const ses = session.fromPartition(part);
    await setSessionProxyWithTracking(part, ses, cName, fpHost);
  }
  await getHardenedEphemeralSession(SERVICE_EPHEMERAL_PARTITION, 'Geçici');
  await getHardenedEphemeralSession('zaslon-ephemeral-metasearch', 'Kişisel');
  await getHardenedEphemeralSession('zaslon-ephemeral-translator', 'Kişisel');
}

async function ensureSessionReady(container, tabId = '', firstPartyHost = '') {
  const norm = normalizeContainerName(container);
  const part = getPartitionName(norm, tabId);
  const ses = getSession(norm, tabId);
  const inflight = sessionProxyPromises.get(part);
  if (inflight) {
    await inflight.catch(() => {});
  }
  if (norm === '🧅 Tor Zırhlı') {
    await setSessionProxyWithTracking(part, ses, norm, firstPartyHost);
  }
  return ses;
}

async function ensureTorStartedOrInstalled(opts = {}) {
  if (!torManager) return null;
  if (typeof opts.allowExternalTor === 'boolean') {
    torManager.allowExternalTor = opts.allowExternalTor;
  } else {
    torManager.allowExternalTor = !!prefs.allowExternalTor;
  }
  const st = await torManager.start(opts);
  if (st && !st.connected && st.lastError === 'TOR_BINARY_MISSING') {
    const inst = await torManager.installTorBinary();
    await applyNetworkProxiesToAllSessions();
    return inst;
  }
  if (st && st.connected) {
    await applyNetworkProxiesToAllSessions();
  }
  return st;
}

function getSession(container, tabId = '') {
  const norm = normalizeContainerName(container);
  const part = getPartitionName(norm, tabId);
  const ses = session.fromPartition(part);
  partitionToContainer.set(part, norm);

  if (norm === '🧅 Tor Zırhlı' && torManager && torManager.state === 'stopped') {
    ensureTorStartedOrInstalled().catch(() => {});
  }

  if (prepared.has(part)) return ses;
  prepared.add(part);
  try {
    const pagePreloadPath = path.join(__dirname, 'page-preload.js');
    if (typeof ses.registerPreloadScript === 'function') {
      ses.registerPreloadScript({
        id: 'zaslon-page-shield',
        type: 'frame',
        filePath: pagePreloadPath
      });
    } else if (typeof ses.setPreloads === 'function') {
      ses.setPreloads([pagePreloadPath]);
    }
  } catch {}
  try {
    ses.setSpellCheckerEnabled?.(false);
  } catch {}
  setSessionProxyWithTracking(part, ses, norm);

  // Standart ve tek tip UA havuzu (Electron/Zaslon/OS sürüm izini temizle)
  if (prefs.fp || norm === '🧅 Tor Zırhlı') {
    ses.setUserAgent(UNIFORM_BROWSER_UA);
  } else {
    const cleanUA = ses
      .getUserAgent()
      .replace(/\s?(Electron|zaslon-browser)\/[\d.]+/gi, '');
    ses.setUserAgent(cleanUA);
  }

  // Ağ Seviyesi Kalkan: Telemetri Duvarı + ClearURLs + @ghostery/adblocker-electron + WebSocket + Canlı İstek Denetçisi
  ses.webRequest.onBeforeRequest((details, cb) => {
    try {
      const urlStr = details.url || '';
      const isHttp = urlStr.startsWith('http://') || urlStr.startsWith('https://');
      const isWs = urlStr.startsWith('ws://') || urlStr.startsWith('wss://');
      if (!isHttp && !isWs) {
        return cb({});
      }

      // 1) Ana çerçeve geçişlerinde takip parametrelerini (utm_*, fbclid, gclid, si vb.) temizle
      if (isHttp && prefs.tele && details.resourceType === 'mainFrame') {
        const cleaned = cleanTrackingUrl(urlStr);
        if (cleaned.removedCount > 0) {
          trackedDelta += cleaned.removedCount;
          if (adblockEngine) {
            const tabId = adblockEngine.wcToTabId.get(details.webContentsId);
            adblockEngine.recordStrippedParams(tabId, cleaned.removedCount);
          }
          return cb({ redirectURL: cleaned.url });
        }
      }

      // 2) AdBlock + Telemetri Duvarı + Güvenlik Seviyesi + Canlı İstek Denetçisi değerlendirmesi
      if (adblockEngine) {
        const decision = adblockEngine.evaluateRequest(details, prefs);
        if (decision.cancel) {
          return cb({ cancel: true });
        }
      }
    } catch {}
    cb({});
  });

function getThirdPartyCookieContext(details) {
  if (!details || details.resourceType === 'mainFrame') return null;
  const targetUrl = details.url || '';
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) return null;
  const tabId = adblockEngine ? adblockEngine.wcToTabId.get(details.webContentsId) : null;
  const rec = tabId ? views.get(tabId) : null;
  let topUrl = '';
  try {
    if (rec && rec.view && !rec.view.webContents.isDestroyed()) {
      topUrl = rec.view.webContents.getURL() || '';
    }
  } catch {}
  if (!topUrl || topUrl.startsWith('data:')) {
    topUrl = details.initiator || details.referrer || '';
  }
  if (!topUrl || (!topUrl.startsWith('http://') && !topUrl.startsWith('https://'))) return null;
  try {
    const topHost = new URL(topUrl).hostname;
    const targetHost = new URL(targetUrl).hostname;
    const topRoot = extractRootDomain(topHost);
    const targetRoot = extractRootDomain(targetHost);
    if (!topRoot || !targetRoot || topRoot === targetRoot) return null;
    if (adblockEngine && adblockEngine.isSiteWhitelisted(topUrl)) return null;
    return { tabId, topRoot, targetRoot };
  } catch {
    return null;
  }
}

  // Gizlilik Başlıkları, Client-Hints (sec-ch-ua*) Soyma, 3. Parti Çerez Engelleme ve Referer Kırpma
  ses.webRequest.onBeforeSendHeaders((details, cb) => {
    const h = { ...(details.requestHeaders || {}) };
    const isTorSes = norm === '🧅 Tor Zırhlı';
    const isThirdParty = (prefs.block3pCookies || isTorSes) ? getThirdPartyCookieContext(details) : null;
    if (isThirdParty) {
      for (const hdrKey of Object.keys(h)) {
        if (hdrKey.toLowerCase() === 'cookie') {
          delete h[hdrKey];
        }
      }
    }
    if (prefs.fp || isTorSes) {
      h['Sec-GPC'] = '1';
      h['DNT'] = '1';
      let existingReferer = '';
      for (const hdrKey of Object.keys(h)) {
        const lower = hdrKey.toLowerCase();
        if (lower.startsWith('sec-ch-ua')) {
          delete h[hdrKey];
        } else if (isTorSes && (lower === 'user-agent' || lower === 'accept-language')) {
          delete h[hdrKey];
        } else if (lower === 'referer') {
          existingReferer = h[hdrKey];
          delete h[hdrKey];
        }
      }
      if (isTorSes) {
        h['User-Agent'] = UNIFORM_BROWSER_UA;
        h['Accept-Language'] = 'en-US,en;q=0.5';
      }
      if (existingReferer) {
        try {
          const r = new URL(existingReferer);
          const u = new URL(details.url);
          h['Referer'] = r.origin !== u.origin ? r.origin + '/' : existingReferer;
        } catch {
          h['Referer'] = existingReferer;
        }
      }
    }
    cb({ requestHeaders: h });
  });

  // Faz 4: Ağdaki .mp4, .m3u8 (HLS), .mpd (DASH), .webm, .mp3, .m4a medya akışlarını yakala & 3. parti Set-Cookie soy
  ses.webRequest.onHeadersReceived((details, cb) => {
    try {
      if (streamSniffer) {
        streamSniffer.inspectHeadersReceived(details);
      }
      const isTorSes = norm === '🧅 Tor Zırhlı';
      const stripCookies = (prefs.block3pCookies || isTorSes) && getThirdPartyCookieContext(details);
      const enforceSafestCsp =
        prefs.securityLevel === 'safest' &&
        (details.resourceType === 'mainFrame' || details.resourceType === 'subFrame') &&
        /^https?:\/\//i.test(details.url || '');
      if ((stripCookies || enforceSafestCsp) && details.responseHeaders) {
        const rh = { ...details.responseHeaders };
        let modified = false;
        if (stripCookies) {
          for (const hdrKey of Object.keys(rh)) {
            if (hdrKey.toLowerCase() === 'set-cookie') {
              delete rh[hdrKey];
              modified = true;
            }
          }
        }
        if (enforceSafestCsp) {
          let existingCspKey = null;
          for (const hdrKey of Object.keys(rh)) {
            if (hdrKey.toLowerCase() === 'content-security-policy') {
              existingCspKey = hdrKey;
              break;
            }
          }
          const prev = existingCspKey && Array.isArray(rh[existingCspKey]) ? rh[existingCspKey] : existingCspKey ? [String(rh[existingCspKey])] : [];
          rh[existingCspKey || 'Content-Security-Policy'] = [
            ...prev,
            "script-src 'none'; object-src 'none'; base-uri 'none'"
          ];
          modified = true;
        }
        if (modified) {
          return cb({ responseHeaders: rh });
        }
      }
    } catch {}
    cb({});
  });

  // İzin İstekleri: Bildirim, konum, mikrofon/kamera tuzaklarını varsayılan olarak reddet
  ses.setPermissionRequestHandler((_wc, perm, cb) => {
    const allowed = ['fullscreen', 'clipboard-sanitized-write', 'pointerLock'].includes(perm);
    cb(allowed);
  });

  // İndirme Yöneticisi
  ses.on('will-download', (_e, item) => {
    const dir = app.getPath('downloads');
    let name = item.getFilename();
    let full = path.join(dir, name);
    let n = 1;
    const ext = path.extname(name);
    const base = path.basename(name, ext);
    while (fs.existsSync(full)) full = path.join(dir, `${base} (${n++})${ext}`);
    item.setSavePath(full);
    const id = Date.now() + Math.random();
    const upd = state =>
      send('dl', {
        id,
        name: path.basename(full),
        received: item.getReceivedBytes(),
        total: item.getTotalBytes(),
        state,
        path: full
      });
    item.on('updated', () => upd('progress'));
    item.once('done', (_ev, st) => upd(st === 'completed' ? 'done' : 'failed'));
    upd('progress');
  });

  return ses;
}

async function getHardenedEphemeralSession(partitionName, containerName = 'Geçici', firstPartyHost = '') {
  const norm = normalizeContainerName(containerName);
  const ses = session.fromPartition(partitionName);
  partitionToContainer.set(partitionName, norm);
  if (!prepared.has(partitionName)) {
    prepared.add(partitionName);
    try {
      ses.setSpellCheckerEnabled?.(false);
      ses.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
      ses.setPermissionCheckHandler?.(() => false);
      ses.setUserAgent(UNIFORM_BROWSER_UA);
      ses.webRequest.onBeforeSendHeaders((details, cb) => {
        const h = { ...(details.requestHeaders || {}) };
        for (const hdrKey of Object.keys(h)) {
          const lower = hdrKey.toLowerCase();
          if (
            lower.startsWith('sec-ch-ua') ||
            lower === 'x-client-data' ||
            lower === 'user-agent' ||
            lower === 'accept-language' ||
            lower === 'referer' ||
            lower === 'origin' ||
            lower === 'dnt' ||
            lower === 'x-requested-with'
          ) {
            delete h[hdrKey];
          }
        }
        h['User-Agent'] = UNIFORM_BROWSER_UA;
        h['Accept-Language'] = 'en-US,en;q=0.5';
        h['Sec-GPC'] = '1';
        cb({ requestHeaders: h });
      });
    } catch {}
  }
  await setSessionProxyWithTracking(partitionName, ses, norm, firstPartyHost);
  return ses;
}

/* ---------- Sekme Görünümleri (WebContentsView) ---------- */
const views = new Map(); // id -> { view, container, dark, darkKey, zoom, cosmeticKey }
let active = null;
let lastBounds = { x: 0, y: 100, width: 800, height: 600 };
let fsView = false;

let DARKREADER_BUNDLE_CODE = '';
try {
  const drFile = path.join(__dirname, 'node_modules', 'darkreader', 'darkreader.js');
  if (fs.existsSync(drFile)) {
    DARKREADER_BUNDLE_CODE = fs.readFileSync(drFile, 'utf8');
  }
} catch {}

function shouldApplyDarkReader(rec) {
  if (typeof rec.dark === 'boolean') return rec.dark;
  const wc = rec.view?.webContents;
  if (!wc) return !!prefs.darkReader;
  try {
    const u = wc.getURL();
    if (!u || !u.startsWith('http')) return false;
    const h = new URL(u).hostname.replace(/^www\./, '').toLowerCase();
    const disabled = Array.isArray(prefs.darkReaderDisabledHosts) ? prefs.darkReaderDisabledHosts : [];
    const enabled = Array.isArray(prefs.darkReaderEnabledHosts) ? prefs.darkReaderEnabledHosts : [];
    if (disabled.includes(h)) return false;
    if (enabled.includes(h)) return true;
  } catch {}
  return !!prefs.darkReader;
}

async function applyDark(rec) {
  const wc = rec.view.webContents;
  if (!wc || wc.isDestroyed()) return;
  const url = wc.getURL() || '';
  if (!url.startsWith('http://') && !url.startsWith('https://')) return;

  if (rec.darkKey) {
    try {
      await wc.removeInsertedCSS(rec.darkKey);
    } catch {}
    rec.darkKey = null;
  }

  const activeDark = prefs.securityLevel !== 'safest' && shouldApplyDarkReader(rec);
  if (!activeDark) {
    if (prefs.securityLevel === 'safest') return;
    try {
      await wc.executeJavaScript(
        `(() => {
          document.documentElement.classList.remove('__zaslon_dr_invert', '__zaslon_dr_tone');
          if (window.DarkReader && typeof window.DarkReader.disable === 'function') {
            window.DarkReader.disable();
          }
        })()`,
        true
      );
    } catch {}
    return;
  }

  const cfg = rec.darkCfg || {};
  const brightness = Math.max(60, Math.min(130, Number(cfg.brightness ?? prefs.darkReaderBrightness ?? 100)));
  const contrast = Math.max(65, Math.min(135, Number(cfg.contrast ?? prefs.darkReaderContrast ?? 96)));
  const sepia = Math.max(0, Math.min(70, Number(cfg.sepia ?? prefs.darkReaderSepia ?? 8)));
  const grayscale = Math.max(0, Math.min(100, Number(cfg.grayscale ?? prefs.darkReaderGrayscale ?? 0)));
  const smart = cfg.smart ?? (prefs.darkReaderSmart !== false);
  const forcedOnHost = (() => {
    try {
      const h = new URL(url).hostname.replace(/^www\./, '').toLowerCase();
      return typeof rec.dark === 'boolean' || (prefs.darkReaderEnabledHosts || []).includes(h);
    } catch {
      return false;
    }
  })();

  try {
    // Harici CSS dosyalarını CORS/CSP engeline takılmadan Electron oturumuyla önceden çek
    let prefetchedCss = {};
    try {
      const sheetUrls = await wc.executeJavaScript(
        `(() => [...document.querySelectorAll('link[rel~="stylesheet"][href]')].map(l => l.href).filter(u => /^https?:\\/\\//i.test(u)).slice(0, 24))()`,
        true
      );
      if (Array.isArray(sheetUrls) && sheetUrls.length > 0 && wc.session && typeof wc.session.fetch === 'function') {
        const isTorTab = normalizeContainerName(rec.container) === '🧅 Tor Zırhlı';
        if (!isTorTab || (torManager && torManager.state === 'connected')) {
          const results = await Promise.allSettled(
            sheetUrls.map(async u => {
              const ctrl = new AbortController();
              const tmr = setTimeout(() => ctrl.abort(), 2500);
              try {
                const res = await wc.session.fetch(u, {
                  credentials: 'omit',
                  referrerPolicy: 'no-referrer',
                  signal: ctrl.signal
                });
                if (!res.ok) return null;
                const txt = await res.text();
                if (txt.length > 524288) return null;
                return [u, txt];
              } catch {
                return null;
              } finally {
                clearTimeout(tmr);
              }
            })
          );
          for (const r of results) {
            if (r.status === 'fulfilled' && Array.isArray(r.value)) {
              prefetchedCss[r.value[0]] = r.value[1];
            }
          }
        }
      }
    } catch {}

    // Resmi Dark Reader (darkreader.js) kütüphanesini henüz yüklenmemişse enjekte et
    if (DARKREADER_BUNDLE_CODE) {
      const hasDr = await wc.executeJavaScript(`Boolean(window.DarkReader && window.DarkReader.enable)`, true);
      if (!hasDr) {
        await wc.executeJavaScript(DARKREADER_BUNDLE_CODE, true);
      }
      await wc.executeJavaScript(
        `(() => {
          const cached = ${JSON.stringify(prefetchedCss)};
          if (window.DarkReader && typeof window.DarkReader.setFetchMethod === 'function') {
            window.DarkReader.setFetchMethod(u => {
              const hit = cached && Object.prototype.hasOwnProperty.call(cached, u) ? cached[u] : null;
              if (typeof hit === 'string') {
                return Promise.resolve(new Response(hit, { status: 200, headers: { 'content-type': 'text/css' } }));
              }
              return window.fetch(u, { credentials: 'omit', referrerPolicy: 'no-referrer' }).catch(() => new Response('', { status: 200 }));
            });
          }
        })()`,
        true
      );
    }

    await wc.executeJavaScript(
      `(() => {
        document.documentElement.classList.remove('__zaslon_dr_invert', '__zaslon_dr_tone');
        if (!window.DarkReader || typeof window.DarkReader.enable !== 'function') return;

        // Akıllı Koyu Site Algılama: Site zaten doğal koyu temadaysa (örn: YouTube Dark, GitHub Dark) bozma
        if (${JSON.stringify(smart)} && !${JSON.stringify(forcedOnHost)}) {
          const parseLum = col => {
            if (!col || col === 'transparent' || col === 'rgba(0, 0, 0, 0)') return null;
            const m = col.match(/rgba?\\((\\d+),\\s*(\\d+),\\s*(\\d+)/i);
            if (!m) return null;
            const [r, g, b] = [Number(m[1]), Number(m[2]), Number(m[3])];
            return (0.299 * r + 0.587 * g + 0.114 * b) / 255;
          };
          const root = document.documentElement;
          const body = document.body;
          if (!window.DarkReader.isEnabled()) {
            const rBg = parseLum(getComputedStyle(root).backgroundColor);
            const bBg = body ? parseLum(getComputedStyle(body).backgroundColor) : null;
            const lum = bBg !== null ? bBg : rBg;
            const schemeDark = getComputedStyle(root).colorScheme === 'dark';
            if ((lum !== null && lum < 0.24) || (schemeDark && lum !== null && lum < 0.35)) {
              return;
            }
          }
        }

        window.DarkReader.enable({
          brightness: ${brightness},
          contrast: ${contrast},
          sepia: ${sepia},
          grayscale: ${grayscale}
        });
      })()`,
      true
    );
  } catch {}
}

function isAdblockEffectiveForUrl(urlStr) {
  if (!prefs.adblock) return false;
  if (!adblockEngine || !urlStr || !urlStr.startsWith('http')) return !!prefs.adblock;
  try {
    const h = new URL(urlStr).hostname.replace(/^www\./, '').toLowerCase();
    return !adblockEngine.isSiteWhitelisted(h);
  } catch {
    return !!prefs.adblock;
  }
}

async function applyCosmeticAdblock(rec) {
  const wc = rec.view.webContents;
  if (!wc || wc.isDestroyed()) return;
  try {
    const url = wc.getURL();
    if (!url.startsWith('http')) return;
    const effective = isAdblockEffectiveForUrl(url);
    wc.send('zaslon-page-config', {
      adblock: effective,
      popups: prefs.popups,
      sponsorBlock: prefs.sponsorBlock,
      securityLevel: prefs.securityLevel,
      lang: prefs.lang,
      rgxEnabled: !!prefs.rgxEnabled,
      rgxPreset: prefs.rgxPreset || 'std',
      rgxVideos: prefs.rgxVideos !== false,
      rgxImages: !!prefs.rgxImages,
      rgxHud: prefs.rgxHud !== false,
      rgxSplit: !!prefs.rgxSplit,
      rgxSharpness: Number(prefs.rgxSharpness ?? 55),
      rgxSaturation: Number(prefs.rgxSaturation ?? 112),
      rgxContrast: Number(prefs.rgxContrast ?? 106),
      rgxBrightness: Number(prefs.rgxBrightness ?? 100),
      rgxDisabledHosts: Array.isArray(prefs.rgxDisabledHosts) ? prefs.rgxDisabledHosts : []
    });
    if (!effective || !adblockEngine) return;
    const css = adblockEngine.getCosmeticCssForPage();
    if (css) await wc.insertCSS(css);
  } catch {}
}

const errPage = (url, desc, container) => {
  const norm = normalizeContainerName(container);
  const isTor = norm === '🧅 Tor Zırhlı';
  const torNotReady = isTor && (!torManager || torManager.state !== 'connected');
  const title = torNotReady ? t('err.torTitle') : t('err.pageTitle');
  const helperNote = torNotReady
    ? t('err.torHelper', { status: torManager ? torManager.bootstrapSummary : t('tor.off') })
    : t('err.pageHelper');
  const escHtml = s => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
  const actionButtons = torNotReady
    ? `<div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:18px"><a href="zaslon://tor-action?action=install-and-start&target=${encodeURIComponent(
        url
      )}" style="display:inline-flex;align-items:center;gap:6px;padding:10px 16px;border-radius:10px;background:#10b981;color:#04241a;font:700 13px 'Segoe UI',sans-serif;text-decoration:none">${escHtml(
        t('err.torInstallBtn')
      )}</a><a href="zaslon://tor-action?action=retry&target=${encodeURIComponent(
        url
      )}" style="display:inline-flex;align-items:center;gap:6px;padding:10px 16px;border-radius:10px;background:#1e293b;color:#e2e8f0;font:600 13px 'Segoe UI',sans-serif;text-decoration:none;border:1px solid #334155">${escHtml(
        t('err.torRetryBtn')
      )}</a></div>`
    : '';

  return (
    'data:text/html;charset=utf-8,' +
    encodeURIComponent(
      `<html lang="${getLang()}"><meta charset=utf-8><title>${escHtml(title)}</title><body style="margin:0;height:100vh;display:grid;place-items:center;background:#08101f;color:#e6ecfa;font:15px 'Segoe UI',sans-serif"><div style="max-width:540px;padding:24px;background:#0d182e;border-radius:16px;box-shadow:0 10px 30px #0006"><h1 style="font:700 24px Bahnschrift,sans-serif;margin:0 0 10px">${escHtml(title)}</h1><p style="color:#8394b8;line-height:1.6;margin:0 0 8px;word-break:break-all">${escHtml(url)}</p><p style="color:${torNotReady ? '#34d399' : '#fb7185'};margin:0 0 14px;font-weight:600">${escHtml(desc)}</p><p style="color:#93a9d3;line-height:1.6;margin:0">${escHtml(helperNote)}</p>${actionButtons}</div></html>`
    )
  );
};

function sendNavUpdate(id, wc) {
  const url = wc.getURL();
  if (!url || url.startsWith('data:')) return;
  let canBack = false;
  let canFwd = false;
  try {
    canBack = wc.navigationHistory ? wc.navigationHistory.canGoBack() : wc.canGoBack();
    canFwd = wc.navigationHistory ? wc.navigationHistory.canGoForward() : wc.canGoForward();
  } catch {}
  send('nav', {
    id,
    url,
    title: wc.getTitle(),
    canBack,
    canFwd
  });
}

function createView(id, container) {
  const isTorContainer = normalizeContainerName(container) === '🧅 Tor Zırhlı';
  const ses = getSession(container, id);
  const useSessionFramePreload = typeof ses.registerPreloadScript === 'function';
  const view = new WebContentsView({
    webPreferences: {
      session: ses,
      ...(useSessionFramePreload ? {} : { preload: path.join(__dirname, 'page-preload.js') }),
      additionalArguments: [
        `--zaslon-salt=${sessionSalt}-${Buffer.from(container || 'default').toString('hex')}`,
        `--zaslon-tor=${isTorContainer ? '1' : '0'}`,
        `--zaslon-fp=${prefs.fp ? '1' : '0'}`,
        `--zaslon-adblock=${prefs.adblock ? '1' : '0'}`,
        `--zaslon-popups=${prefs.popups ? '1' : '0'}`,
        `--zaslon-sb=${prefs.sponsorBlock ? '1' : '0'}`,
        `--zaslon-sec=${prefs.securityLevel || 'standard'}`,
        `--zaslon-chrome-major=${UNIFORM_CHROME_MAJOR}`,
        `--zaslon-letterbox=${prefs.letterbox ? '1' : '0'}`,
        `--zaslon-lang=${getLang()}`,
        `--zaslon-rgx=${prefs.rgxEnabled ? '1' : '0'}`,
        `--zaslon-rgx-preset=${prefs.rgxPreset || 'std'}`,
        `--zaslon-rgx-vid=${prefs.rgxVideos !== false ? '1' : '0'}`,
        `--zaslon-rgx-img=${prefs.rgxImages ? '1' : '0'}`,
        `--zaslon-rgx-hud=${prefs.rgxHud !== false ? '1' : '0'}`,
        `--zaslon-rgx-sharp=${Number(prefs.rgxSharpness ?? 55)}`,
        `--zaslon-rgx-sat=${Number(prefs.rgxSaturation ?? 112)}`,
        `--zaslon-rgx-con=${Number(prefs.rgxContrast ?? 106)}`,
        `--zaslon-rgx-bri=${Number(prefs.rgxBrightness ?? 100)}`
      ],
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      nodeIntegrationInSubFrames: true,
      spellcheck: false,
      javascript: prefs.securityLevel !== 'safest'
    }
  });

  const rec = { view, container, dark: null, darkCfg: null, darkKey: null, zoom: 1, speed: 1, navSeq: 0, pendingTorUrl: '', lastFailedUrl: '' };
  views.set(id, rec);
  win.contentView.addChildView(view);
  view.setVisible(false);

  const wc = view.webContents;
  hardenWebContents(wc, prefs.securityLevel);
  if (adblockEngine) {
    adblockEngine.registerWebContents(wc.id, id);
  }
  if (streamSniffer) {
    streamSniffer.registerWebContents(wc.id, id);
  }

  wc.setWindowOpenHandler(({ url, disposition }) => {
    if (/^https?:/.test(url)) {
      const openInBg = disposition === 'background-tab';
      send('new-tab', { url, bg: openInBg });
    }
    return { action: 'deny' };
  });

  // Tor sekmesinde link tıklaması veya yönlendirme ile farklı bir kök etki alanına geçildiğinde
  // bağlantı kurulmadan önce Tor devresini (First-Party Gateway) yenile.
  const ensureTorCircuitForUrl = async targetUrl => {
    if (!targetUrl || !/^https?:\/\//i.test(targetUrl)) return false;
    if (normalizeContainerName(rec.container) !== '🧅 Tor Zırhlı') return false;
    let nextHost = '';
    try {
      nextHost = new URL(targetUrl).hostname;
    } catch {
      return false;
    }
    if (!nextHost) return false;
    const prevRoot = rec.firstPartyHost ? extractRootDomain(rec.firstPartyHost) : '';
    const nextRoot = extractRootDomain(nextHost);
    if (nextRoot === prevRoot) return false;
    rec.firstPartyHost = nextHost;
    await ensureSessionReady(rec.container, id, nextHost).catch(() => {});
    return true;
  };

  wc.on('will-navigate', (e, url) => {
    if (!url) return;
    if (url.startsWith('zaslon://tor-action')) {
      e.preventDefault();
      try {
        const parsed = new URL(url);
        const action = parsed.searchParams.get('action') || 'install-and-start';
        const target = parsed.searchParams.get('target') || rec.pendingTorUrl || '';
        if (target && /^https?:\/\//i.test(target)) rec.pendingTorUrl = target;
        if (action === 'retry' && torManager && torManager.state === 'connected' && rec.pendingTorUrl) {
          const retryUrl = rec.pendingTorUrl;
          rec.pendingTorUrl = '';
          ensureSessionReady(rec.container, id, new URL(retryUrl).hostname)
            .catch(() => {})
            .finally(() => {
              if (!wc.isDestroyed()) wc.loadURL(retryUrl).catch(() => {});
            });
          return;
        }
        ensureTorStartedOrInstalled()
          .then(st => {
            if (!wc.isDestroyed() && (!st || !st.connected)) {
              const showUrl = rec.pendingTorUrl || target || '';
              const msg = st?.lastError && st.lastError !== 'TOR_BINARY_MISSING' ? st.lastError : torManager?.bootstrapSummary || t('tor.off');
              wc.loadURL(errPage(showUrl, msg, rec.container)).catch(() => {});
            }
          })
          .catch(() => {});
        const showUrl = rec.pendingTorUrl || target || '';
        if (showUrl && (!torManager || torManager.state !== 'connected')) {
          wc.loadURL(errPage(showUrl, torManager ? torManager.bootstrapSummary : t('tor.off'), rec.container)).catch(() => {});
        }
      } catch {}
      return;
    }
    if (!isAllowedNavProtocol(url)) {
      e.preventDefault();
      return;
    }
    if (url.startsWith('data:') || normalizeContainerName(rec.container) !== '🧅 Tor Zırhlı') return;
    if (!/^https?:\/\//i.test(url)) return;
    if (!torManager || torManager.state !== 'connected') {
      e.preventDefault();
      rec.pendingTorUrl = url;
      ensureTorStartedOrInstalled().catch(() => {});
      const holdMsg = torManager ? torManager.bootstrapSummary : t('tor.disabledKillSwitch');
      wc.loadURL(errPage(url, holdMsg, rec.container)).catch(() => {});
      return;
    }
    let nextHost = '';
    try {
      nextHost = new URL(url).hostname;
    } catch {
      return;
    }
    const prevRoot = rec.firstPartyHost ? extractRootDomain(rec.firstPartyHost) : '';
    const nextRoot = extractRootDomain(nextHost);
    if (nextHost && nextRoot !== prevRoot) {
      e.preventDefault();
      rec.firstPartyHost = nextHost;
      ensureSessionReady(rec.container, id, nextHost)
        .catch(() => {})
        .finally(() => {
          if (!wc.isDestroyed()) {
            wc.loadURL(url).catch(() => {});
          }
        });
    }
  });

  wc.on('will-redirect', (e, url, _isInPlace, isMainFrame) => {
    if (!isMainFrame || !url) return;
    if (!isAllowedNavProtocol(url)) {
      e.preventDefault();
      return;
    }
    if (url.startsWith('data:') || normalizeContainerName(rec.container) !== '🧅 Tor Zırhlı') return;
    if (!/^https?:\/\//i.test(url)) return;
    if (!torManager || torManager.state !== 'connected') {
      e.preventDefault();
      rec.pendingTorUrl = url;
      const holdMsg = torManager ? torManager.bootstrapSummary : t('tor.disabledKillSwitch');
      wc.loadURL(errPage(url, holdMsg, rec.container)).catch(() => {});
      return;
    }
    let nextHost = '';
    try {
      nextHost = new URL(url).hostname;
    } catch {
      return;
    }
    const prevRoot = rec.firstPartyHost ? extractRootDomain(rec.firstPartyHost) : '';
    const nextRoot = extractRootDomain(nextHost);
    if (nextHost && nextRoot !== prevRoot) {
      e.preventDefault();
      rec.firstPartyHost = nextHost;
      ensureSessionReady(rec.container, id, nextHost)
        .catch(() => {})
        .finally(() => {
          if (!wc.isDestroyed()) {
            wc.loadURL(url).catch(() => {});
          }
        });
    }
  });

  wc.on('did-start-navigation', (_e, url, isInPlace, isMainFrame) => {
    if (!isMainFrame || !url || url.startsWith('data:')) return;
    ensureTorCircuitForUrl(url);
    if (!isInPlace && streamSniffer) {
      streamSniffer.clearTabStreams(id);
    }
    if (streamSniffer) {
      streamSniffer.inspectPageNavigation(id, url, wc.getTitle());
    }
  });

  wc.on('did-start-loading', () => send('loading', { id, on: true }));
  wc.on('did-stop-loading', () => {
    send('loading', { id, on: false });
    sendNavUpdate(id, wc);
    if (streamSniffer) {
      streamSniffer.inspectPageNavigation(id, wc.getURL(), wc.getTitle());
    }
  });

  const onNav = url => {
    if (url.startsWith('data:')) return;
    sendNavUpdate(id, wc);
    applyDark(rec);
    if (streamSniffer) {
      streamSniffer.inspectPageNavigation(id, url, wc.getTitle());
    }
  };

  wc.on('did-navigate', (_e, url) => {
    onNav(url);
  });
  wc.on('did-navigate-in-page', (_e, url, isMain) => {
    if (isMain) onNav(url);
  });
  const buildPageConfigPayload = () => ({
    adblock: isAdblockEffectiveForUrl(wc.getURL()),
    popups: prefs.popups,
    sponsorBlock: prefs.sponsorBlock,
    securityLevel: prefs.securityLevel,
    lang: prefs.lang,
    rgxEnabled: !!prefs.rgxEnabled,
    rgxPreset: prefs.rgxPreset || 'std',
    rgxVideos: prefs.rgxVideos !== false,
    rgxImages: !!prefs.rgxImages,
    rgxHud: prefs.rgxHud !== false,
    rgxSplit: !!prefs.rgxSplit,
    rgxSharpness: Number(prefs.rgxSharpness ?? 55),
    rgxSaturation: Number(prefs.rgxSaturation ?? 112),
    rgxContrast: Number(prefs.rgxContrast ?? 106),
    rgxBrightness: Number(prefs.rgxBrightness ?? 100),
    rgxDisabledHosts: Array.isArray(prefs.rgxDisabledHosts) ? prefs.rgxDisabledHosts : []
  });

  wc.on('did-frame-finish-load', (_e, isMainFrame, frameProcessId, frameRoutingId) => {
    if (isMainFrame) return;
    try {
      const targetFrame =
        wc.mainFrame && Array.isArray(wc.mainFrame.framesInSubtree)
          ? wc.mainFrame.framesInSubtree.find(
              f => f.processId === frameProcessId && f.routingId === frameRoutingId
            )
          : null;
      if (targetFrame && !targetFrame.isDestroyed()) {
        targetFrame.send('zaslon-page-config', buildPageConfigPayload());
      }
    } catch {}
  });

  wc.on('dom-ready', () => {
    applyDark(rec);
    applyCosmeticAdblock(rec);
    if (rec.zoom !== 1) wc.setZoomFactor(rec.zoom);
    try {
      const cfg = buildPageConfigPayload();
      if (wc.mainFrame && Array.isArray(wc.mainFrame.framesInSubtree)) {
        for (const f of wc.mainFrame.framesInSubtree) {
          try {
            if (f && !f.isDestroyed()) f.send('zaslon-page-config', cfg);
          } catch {}
        }
      }
    } catch {}
    if (streamSniffer) {
      streamSniffer.inspectPageNavigation(id, wc.getURL(), wc.getTitle());
    }
    // Faz 4: Eşleşen UserScript betiklerini sayfaya enjekte et
    if (prefs.userscriptsEnabled && userScriptManager && prefs.securityLevel !== 'safest') {
      const bundle = userScriptManager.buildInjectionBundleForUrl(wc.getURL());
      if (bundle) {
        wc.executeJavaScript(bundle, true).catch(() => {});
      }
    }
  });
  wc.on('page-title-updated', (_e, title) => {
    send('title', { id, title });
    if (streamSniffer) {
      streamSniffer.inspectPageNavigation(id, wc.getURL(), title);
    }
  });
  wc.on('page-favicon-updated', async (_e, icons) => {
    const rawIcon = icons && icons[0];
    const pageUrl = wc.getURL();
    if (!rawIcon || !pageUrl || (!pageUrl.startsWith('http://') && !pageUrl.startsWith('https://'))) return;
    const normCont = normalizeContainerName(rec.container);
    if (EPHEMERAL_CONTAINERS.has(normCont) || normCont === '🧅 Tor Zırhlı') {
      return;
    }
    try {
      if (rawIcon.startsWith('data:image/')) {
        if (rawIcon.length <= 350000 && !rawIcon.startsWith('data:image/svg+xml')) {
          send('fav', { url: pageUrl, icon: rawIcon });
        }
        return;
      }
      if (!/^https?:\/\//i.test(rawIcon)) return;
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 4000);
      try {
        const res = await wc.session.fetch(rawIcon, {
          method: 'GET',
          credentials: 'omit',
          referrerPolicy: 'no-referrer',
          signal: ctrl.signal
        });
        if (!res.ok) return;
        const ctype = String(res.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
        if (!ctype.startsWith('image/') || ctype === 'image/svg+xml') return;
        const buf = Buffer.from(await res.arrayBuffer());
        if (!buf.length || buf.length > 262144) return;
        const dataUrl = `data:${ctype};base64,${buf.toString('base64')}`;
        if (!wc.isDestroyed()) send('fav', { url: pageUrl, icon: dataUrl });
      } finally {
        clearTimeout(timer);
      }
    } catch {}
  });
  wc.on('did-fail-load', (_e, code, desc, url, isMain) => {
    if (isMain && code !== -3 && code !== -27) {
      if (url && !url.startsWith('data:')) rec.lastFailedUrl = url;
      wc.loadURL(errPage(url, desc, container));
    }
  });
  wc.on('found-in-page', (_e, r) =>
    send('found', { matches: r.matches, active: r.activeMatchOrdinal })
  );
  wc.on('enter-html-full-screen', () => {
    fsView = true;
    win.setFullScreen(true);
    setTimeout(() => placeActive(), 150);
  });
  wc.on('leave-html-full-screen', () => {
    fsView = false;
    win.setFullScreen(false);
    setTimeout(() => send('resync'), 150);
  });

  wc.on('before-input-event', (e, input) => {
    if (input.type !== 'keyDown') return;
    const k = input.key;
    if (k === 'F12') {
      wc.toggleDevTools();
      e.preventDefault();
      return;
    }
    if (k === 'F5') {
      send('cmd', 'reload');
      e.preventDefault();
      return;
    }
    if (input.alt && k === 'ArrowLeft') {
      send('cmd', 'back');
      e.preventDefault();
      return;
    }
    if (input.alt && k === 'ArrowRight') {
      send('cmd', 'fwd');
      e.preventDefault();
      return;
    }
    // Alt+X: Tek tıkla Panik / Her Şeyi Yak kısayolu
    if (input.alt && k.toLowerCase() === 'x') {
      e.preventDefault();
      send('panic-trigger');
      return;
    }
    // Alt+G: Zaslon RGX (Video & Görsel Keskinleştirme) Hızlı Aç/Kapat kısayolu
    if (input.alt && !input.control && k.toLowerCase() === 'g') {
      e.preventDefault();
      send('cmd', 'rgx-toggle');
      return;
    }
    if (
      input.control &&
      !input.alt &&
      ['t', 'w', 'l', 'k', 'd', 'b', 'f', 'r', 'Tab', ',', '+', '=', '-', '0'].includes(
        k.length === 1 ? k.toLowerCase() : k
      )
    ) {
      e.preventDefault();
      if (['l', 'k', 'f'].includes(k.toLowerCase())) win.webContents.focus();
      send('shortcut', { key: k, shift: input.shift });
    }
  });

  wc.on('context-menu', (_e, p) => {
    const tMenu = [];
    if (p.linkURL) {
      tMenu.push(
        { label: t('ctx.openNewTab'), click: () => send('new-tab', { url: p.linkURL }) },
        { label: t('ctx.openBg'), click: () => send('new-tab', { url: p.linkURL, bg: true }) },
        { label: t('ctx.copyLink'), click: () => clipboard.writeText(p.linkURL) },
        { type: 'separator' }
      );
    }
    if (p.mediaType === 'image') {
      tMenu.push(
        { label: t('ctx.copyImage'), click: () => wc.copyImageAt(p.x, p.y) },
        { label: t('ctx.copyImageUrl'), click: () => clipboard.writeText(p.srcURL) },
        { label: t('ctx.saveImage'), click: () => wc.downloadURL(p.srcURL) },
        { type: 'separator' }
      );
    }
    if (p.isEditable) {
      tMenu.push(
        { label: t('ctx.cut'), role: 'cut' },
        { label: t('ctx.copy'), role: 'copy' },
        { label: t('ctx.paste'), role: 'paste' },
        { type: 'separator' }
      );
    } else if (p.selectionText) {
      tMenu.push(
        { label: t('ctx.copy'), role: 'copy' },
        {
          label: t('ctx.searchFor', { text: p.selectionText.slice(0, 24) }),
          click: () => send('search', p.selectionText)
        },
        {
          label: t('ctx.translateSel', { text: p.selectionText.slice(0, 22) }),
          click: () => send('translate-selection', p.selectionText)
        },
        { type: 'separator' }
      );
    }
    tMenu.push(
      { label: t('ctx.back'), click: () => send('cmd', 'back') },
      { label: t('ctx.fwd'), click: () => send('cmd', 'fwd') },
      { label: t('ctx.reload'), click: () => send('cmd', 'reload') },
      { type: 'separator' },
      { label: t('ctx.translatePage'), click: () => send('cmd', 'translate-page') },
      { label: t('ctx.saveSingleFile'), click: () => send('cmd', 'singlefile') },
      { type: 'separator' },
      { label: t('ctx.inspect'), click: () => wc.inspectElement(p.x, p.y) }
    );
    Menu.buildFromTemplate(tMenu).popup({ window: win });
  });

  return rec;
}

function placeActive() {
  const rec = views.get(active);
  if (!rec) return;
  let b;
  if (fsView) {
    const [w, h] = win.getContentSize();
    b = { x: 0, y: 0, width: w, height: h };
  } else {
    const useLetterbox =
      prefs.letterbox ||
      prefs.securityLevel === 'safest' ||
      normalizeContainerName(rec.container) === '🧅 Tor Zırhlı';
    b = computeLetterboxBounds(lastBounds, useLetterbox);
  }
  rec.view.setBounds(b);
  rec.view.setVisible(true);
}

function hideAll() {
  views.forEach(r => r.view.setVisible(false));
}

/* ---------- IPC Kanalları ---------- */
ipcMain.on('nav', async (_e, id, url, container) => {
  let rec = views.get(id);
  if (!rec) rec = createView(id, container);
  const seq = (rec.navSeq = (rec.navSeq || 0) + 1);
  const targetContainer = rec.container || container;
  const norm = normalizeContainerName(targetContainer);
  let fpHost = '';
  if (/^https?:\/\//i.test(url)) {
    try {
      fpHost = new URL(url).hostname;
    } catch {}
  }
  rec.firstPartyHost = fpHost;

  try {
    await ensureSessionReady(targetContainer, id, fpHost);
  } catch {}
  if (seq !== rec.navSeq || !rec.view || rec.view.webContents.isDestroyed()) return;

  if (norm === '🧅 Tor Zırhlı' && /^https?:\/\//i.test(url) && (!torManager || torManager.state !== 'connected')) {
    rec.pendingTorUrl = url;
    if (torManager && (torManager.state === 'stopped' || torManager.state === 'error')) {
      ensureTorStartedOrInstalled().catch(() => {});
    }
    const holdMsg = torManager ? torManager.bootstrapSummary : t('tor.disabledKillSwitch');
    rec.view.webContents.loadURL(errPage(url, holdMsg, targetContainer)).catch(() => {});
    return;
  }

  rec.pendingTorUrl = '';
  rec.lastFailedUrl = '';
  rec.view.webContents.loadURL(url).catch(() => {});
});

// Gerçek BFCache Geri / İleri / Yenile Navigasyonu
ipcMain.on('goBack', (_e, id) => {
  const rec = views.get(id);
  if (!rec) return;
  const wc = rec.view.webContents;
  const canBack = wc.navigationHistory ? wc.navigationHistory.canGoBack() : wc.canGoBack();
  if (canBack) wc.goBack();
});

ipcMain.on('goForward', (_e, id) => {
  const rec = views.get(id);
  if (!rec) return;
  const wc = rec.view.webContents;
  const canFwd = wc.navigationHistory ? wc.navigationHistory.canGoForward() : wc.canGoForward();
  if (canFwd) wc.goForward();
});

ipcMain.on('reloadTab', (_e, id) => {
  const rec = views.get(id);
  if (!rec || !rec.view || rec.view.webContents.isDestroyed()) return;
  const wc = rec.view.webContents;
  const currentUrl = wc.getURL() || '';
  if (currentUrl.startsWith('data:text/html')) {
    const retryUrl = rec.pendingTorUrl || rec.lastFailedUrl;
    if (retryUrl && /^https?:\/\//i.test(retryUrl)) {
      if (normalizeContainerName(rec.container) === '🧅 Tor Zırhlı' && (!torManager || torManager.state !== 'connected')) {
        rec.pendingTorUrl = retryUrl;
        if (torManager && (torManager.state === 'stopped' || torManager.state === 'error')) {
          ensureTorStartedOrInstalled().catch(() => {});
        }
        const holdMsg = torManager ? torManager.bootstrapSummary : t('tor.disabledKillSwitch');
        wc.loadURL(errPage(retryUrl, holdMsg, rec.container)).catch(() => {});
        return;
      }
      rec.lastFailedUrl = '';
      wc.loadURL(retryUrl).catch(() => {});
      return;
    }
  }
  wc.reload();
});

ipcMain.on('mouse-nav', (_e, dir) => {
  if (dir === 'back') send('cmd', 'back');
  else if (dir === 'fwd') send('cmd', 'fwd');
});

ipcMain.on('open-bg-tab', (_e, url) => {
  if (url && /^https?:\/\//i.test(url)) {
    send('new-tab', { url, bg: true });
  }
});

ipcMain.on('yt-ad-skipped', e => {
  blockedDelta += 1;
  if (adblockEngine && e && e.sender) {
    const tabId = adblockEngine.wcToTabId.get(e.sender.id);
    if (tabId) {
      const rep = adblockEngine.tabReports.get(tabId);
      if (rep) {
        rep.blockedCount = (rep.blockedCount || 0) + 1;
        if (tabId === active) {
          send('inspector', adblockEngine.getTabInspectorReport(tabId));
        }
      }
    }
  }
});

ipcMain.on('show', (_e, id, b) => {
  lastBounds = b;
  if (active !== id) {
    hideAll();
    active = id;
  }
  placeActive();
});

ipcMain.on('hide', () => hideAll());

ipcMain.on('close', async (_e, id) => {
  const rec = views.get(id);
  if (!rec) return;
  const closedContainer = normalizeContainerName(rec.container);
  let closedOrigin = '';
  try {
    const u = rec.view.webContents.getURL();
    if (u && /^https?:\/\//i.test(u)) {
      closedOrigin = new URL(u).origin;
    }
  } catch {}

  if (adblockEngine) adblockEngine.unregisterTab(id);
  if (streamSniffer) streamSniffer.unregisterTab(id);
  win.contentView.removeChildView(rec.view);
  rec.view.webContents.close();
  views.delete(id);
  if (active === id) active = null;

  // 1) Geçici (RAM-Only) veya Tor konteyneri temizliği (her Tor sekmesi bağımsız bölüme sahip)
  if (closedContainer === '🧅 Tor Zırhlı') {
    try {
      const part = getPartitionName(closedContainer, id);
      const ses = session.fromPartition(part);
      await ses.clearStorageData();
      await ses.clearCache();
      await ses.clearHostResolverCache();
      await ses.clearAuthCache();
      prepared.delete(part);
      partitionFirstParty.delete(part);
      partitionToContainer.delete(part);
      sessionProxyPromises.delete(part);
    } catch {}
    return;
  }

  const remainingInContainer = [...views.values()].filter(
    v => normalizeContainerName(v.container) === closedContainer
  );
  if (EPHEMERAL_CONTAINERS.has(closedContainer) && remainingInContainer.length === 0) {
    try {
      const ses = session.fromPartition(getPartitionName(closedContainer));
      await ses.clearStorageData();
      await ses.clearCache();
      await ses.clearHostResolverCache();
      await ses.clearAuthCache();
    } catch {}
    return;
  }

  // 2) "Sekme Kapandığında Site Çerezlerini Sil" (clearTabOnClose) aktifse ve o origin başka sekmede açık değilse temizle
  if (prefs.clearTabOnClose && closedOrigin) {
    const stillOpenSameOrigin = remainingInContainer.some(v => {
      try {
        return new URL(v.view.webContents.getURL()).origin === closedOrigin;
      } catch {
        return false;
      }
    });
    if (!stillOpenSameOrigin) {
      try {
        const ses = session.fromPartition(getPartitionName(closedContainer));
        await ses.clearStorageData({
          origin: closedOrigin,
          storages: [
            'cookies',
            'filesystem',
            'indexdb',
            'localstorage',
            'shadercache',
            'websql',
            'serviceworkers',
            'cachestorage'
          ]
        });
      } catch {}
    }
  }
});

ipcMain.on('zoom', (_e, id, f) => {
  const r = views.get(id);
  if (!r) return;
  r.zoom = f;
  r.view.webContents.setZoomFactor(f);
});

ipcMain.on('dark', (_e, id, onOrCfg) => {
  const r = views.get(id);
  if (!r) return;
  if (onOrCfg && typeof onOrCfg === 'object') {
    r.dark = typeof onOrCfg.enabled === 'boolean' ? onOrCfg.enabled : null;
    r.darkCfg = onOrCfg;
  } else {
    r.dark = typeof onOrCfg === 'boolean' ? onOrCfg : null;
  }
  applyDark(r);
});

ipcMain.on('rgx', (_e, id, cfg) => {
  if (cfg && typeof cfg === 'object') {
    if (typeof cfg.rgxEnabled === 'boolean') prefs.rgxEnabled = cfg.rgxEnabled;
    if (typeof cfg.rgxPreset === 'string') prefs.rgxPreset = cfg.rgxPreset;
    if (typeof cfg.rgxVideos === 'boolean') prefs.rgxVideos = cfg.rgxVideos;
    if (typeof cfg.rgxImages === 'boolean') prefs.rgxImages = cfg.rgxImages;
    if (typeof cfg.rgxHud === 'boolean') prefs.rgxHud = cfg.rgxHud;
    if (typeof cfg.rgxSplit === 'boolean') prefs.rgxSplit = cfg.rgxSplit;
    if (typeof cfg.rgxSharpness === 'number') prefs.rgxSharpness = cfg.rgxSharpness;
    if (typeof cfg.rgxSaturation === 'number') prefs.rgxSaturation = cfg.rgxSaturation;
    if (typeof cfg.rgxContrast === 'number') prefs.rgxContrast = cfg.rgxContrast;
    if (typeof cfg.rgxBrightness === 'number') prefs.rgxBrightness = cfg.rgxBrightness;
    if (Array.isArray(cfg.rgxDisabledHosts)) prefs.rgxDisabledHosts = cfg.rgxDisabledHosts;
  }
  const targetRec = id ? views.get(id) : views.get(active);
  if (targetRec && targetRec.view && !targetRec.view.webContents.isDestroyed()) {
    targetRec.view.webContents.send('zaslon-rgx-config', {
      rgxEnabled: !!prefs.rgxEnabled,
      rgxPreset: prefs.rgxPreset || 'std',
      rgxVideos: prefs.rgxVideos !== false,
      rgxImages: !!prefs.rgxImages,
      rgxHud: prefs.rgxHud !== false,
      rgxSplit: !!prefs.rgxSplit,
      rgxSharpness: Number(prefs.rgxSharpness ?? 55),
      rgxSaturation: Number(prefs.rgxSaturation ?? 112),
      rgxContrast: Number(prefs.rgxContrast ?? 106),
      rgxBrightness: Number(prefs.rgxBrightness ?? 100),
      rgxDisabledHosts: Array.isArray(prefs.rgxDisabledHosts) ? prefs.rgxDisabledHosts : [],
      flash: Boolean(cfg && cfg.flash)
    });
  }
});

ipcMain.on('rgx-inline-toggle', (_e, data) => {
  if (!data || typeof data !== 'object') return;
  if (typeof data.enabled === 'boolean') prefs.rgxEnabled = data.enabled;
  if (typeof data.preset === 'string') prefs.rgxPreset = data.preset;
  if (typeof data.sharpness === 'number') prefs.rgxSharpness = data.sharpness;
  if (typeof data.saturation === 'number') prefs.rgxSaturation = data.saturation;
  if (typeof data.contrast === 'number') prefs.rgxContrast = data.contrast;
  if (typeof data.brightness === 'number') prefs.rgxBrightness = data.brightness;
  if (typeof data.split === 'boolean') prefs.rgxSplit = data.split;
  send('rgx-status', {
    rgxEnabled: prefs.rgxEnabled,
    rgxPreset: prefs.rgxPreset,
    rgxSharpness: prefs.rgxSharpness,
    rgxSaturation: prefs.rgxSaturation,
    rgxContrast: prefs.rgxContrast,
    rgxBrightness: prefs.rgxBrightness,
    rgxSplit: prefs.rgxSplit
  });
});

ipcMain.on('find', (_e, id, text, opts) => {
  const r = views.get(id);
  if (r && text) r.view.webContents.findInPage(text, opts || {});
});

ipcMain.on('stopFind', (_e, id) => {
  const r = views.get(id);
  if (r) r.view.webContents.stopFindInPage('clearSelection');
});

ipcMain.on('devtools', (_e, id) => {
  const r = views.get(id);
  if (r) r.view.webContents.openDevTools({ mode: 'detach' });
});

ipcMain.on('focusPage', (_e, id) => {
  const r = views.get(id);
  if (r) r.view.webContents.focus();
});

ipcMain.on('prefs', async (_e, p) => {
  const prevDpi = prefs.dpi;
  const prevDpiMode = prefs.dpiMode;
  const prevDpiSplit = prefs.dpiSplitProfile;
  const prevLang = prefs.lang || 'tr';
  Object.assign(prefs, p);
  prefs.lang = normalizeLang(prefs.lang);
  if (prefs.lang !== prevLang || prefs.lang !== getLang()) {
    setLang(prefs.lang);
    if (dohManager) send('doh-status', dohManager.getStatus());
    if (dpiManager) dpiManager.emitStatus();
    if (torManager) torManager.emitStatus();
    if (encryptedVault) send('vault-status', encryptedVault.getStatus());
    if (lanSyncManager) lanSyncManager._emitStatus();
    if (streamSniffer) {
      for (const r of views.values()) streamSniffer.emitTabUpdate(r.id);
    }
    if (adblockEngine) {
      for (const r of views.values()) send('inspector', adblockEngine.getTabInspectorReport(r.id));
    }
  }

  // 1) Şifreli DNS (DoH) yapılandırmasını güncelle
  if (dohManager) {
    const dohStatus = dohManager.applyConfig({
      enabled: prefs.dohEnabled,
      provider: prefs.dohProvider,
      customUrl: prefs.dohCustomUrl,
      strictMode: prefs.dohStrict
    });
    send('doh-status', dohStatus);
  }

  // 2) DPI Aşıcı durumu değiştiyse başlat/durdur ve oturumlara uygula
  if (
    dpiManager &&
    (prefs.dpi !== prevDpi ||
      (prefs.dpi && (prefs.dpiMode !== prevDpiMode || prefs.dpiSplitProfile !== prevDpiSplit)))
  ) {
    if (prefs.dpi) {
      await dpiManager.start({ mode: prefs.dpiMode, splitProfile: prefs.dpiSplitProfile });
    } else {
      await dpiManager.stop();
    }
    await applyNetworkProxiesToAllSessions();
  }

  if (sponsorBlockService && typeof prefs.sponsorBlock === 'boolean') {
    sponsorBlockService.enabled = prefs.sponsorBlock;
  }
  if (torManager) {
    if (typeof prefs.allowExternalTor === 'boolean') torManager.allowExternalTor = prefs.allowExternalTor;
    if (typeof prefs.clearTorDataOnExit === 'boolean') torManager.clearTorDataOnExit = prefs.clearTorDataOnExit;
  }

  views.forEach(r => {
    const wc = r.view.webContents;
    hardenWebContents(wc, prefs.securityLevel);
    applyDark(r);
    const pageCfg = {
      adblock: isAdblockEffectiveForUrl(wc.getURL()),
      popups: prefs.popups,
      sponsorBlock: prefs.sponsorBlock,
      securityLevel: prefs.securityLevel,
      lang: prefs.lang,
      rgxEnabled: !!prefs.rgxEnabled,
      rgxPreset: prefs.rgxPreset || 'std',
      rgxVideos: prefs.rgxVideos !== false,
      rgxImages: !!prefs.rgxImages,
      rgxHud: prefs.rgxHud !== false,
      rgxSplit: !!prefs.rgxSplit,
      rgxSharpness: Number(prefs.rgxSharpness ?? 55),
      rgxSaturation: Number(prefs.rgxSaturation ?? 112),
      rgxContrast: Number(prefs.rgxContrast ?? 106),
      rgxBrightness: Number(prefs.rgxBrightness ?? 100),
      rgxDisabledHosts: Array.isArray(prefs.rgxDisabledHosts) ? prefs.rgxDisabledHosts : []
    };
    wc.send('zaslon-page-config', pageCfg);
    try {
      if (wc.mainFrame && Array.isArray(wc.mainFrame.framesInSubtree)) {
        for (const f of wc.mainFrame.framesInSubtree) {
          if (f && f !== wc.mainFrame && !f.isDestroyed()) {
            f.send('zaslon-page-config', pageCfg);
          }
        }
      }
    } catch {}
  });
  placeActive();
});

ipcMain.on('theme', (_e, bg, fg) => {
  try {
    win.setBackgroundColor(bg);
    if (process.platform === 'win32') {
      win.setTitleBarOverlay({ color: bg, symbolColor: fg, height: 42 });
    }
  } catch {}
});

ipcMain.on('showItem', (_e, p) => {
  try {
    const raw = String(p || '').trim();
    if (!raw || raw.startsWith('\\\\') || raw.startsWith('//') || raw.includes('\0')) return;
    const resolved = path.resolve(raw);
    const allowedRoots = [app.getPath('downloads'), app.getPath('userData')].map(r => path.resolve(r));
    const isInsideRoot = allowedRoots.some(root => {
      const rel = path.relative(root, resolved);
      return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
    });
    if (isInsideRoot && fs.existsSync(resolved)) {
      shell.showItemInFolder(resolved);
    }
  } catch {}
});
ipcMain.on('external', (_e, u) => {
  try {
    const parsed = new URL(String(u || '').trim());
    const host = (parsed.hostname || '').toLowerCase();
    if (host === 'onion' || host.endsWith('.onion')) return;
    if ((parsed.protocol === 'https:' || parsed.protocol === 'http:') && !parsed.username && !parsed.password) {
      shell.openExternal(parsed.href);
    }
  } catch {}
});

/* ---------- Faz 3: Erişim Özgürlüğü (DoH, SpoofDPI/GoodbyeDPI, Tor Devre İzolasyonu) IPC ---------- */
ipcMain.handle('getNetworkStatus', () => {
  return {
    doh: dohManager ? dohManager.getStatus() : null,
    dpi: dpiManager ? dpiManager.getStatus() : null,
    tor: torManager ? torManager.getStatus() : null
  };
});

ipcMain.handle('configureDoh', (_e, cfg) => {
  if (!dohManager) return null;
  if (cfg) {
    if (typeof cfg.enabled === 'boolean') prefs.dohEnabled = cfg.enabled;
    if (cfg.provider) prefs.dohProvider = cfg.provider;
    if (typeof cfg.customUrl === 'string') prefs.dohCustomUrl = cfg.customUrl;
    if (typeof cfg.strictMode === 'boolean') prefs.dohStrict = cfg.strictMode;
  }
  const status = dohManager.applyConfig({
    enabled: prefs.dohEnabled,
    provider: prefs.dohProvider,
    customUrl: prefs.dohCustomUrl,
    strictMode: prefs.dohStrict
  });
  send('doh-status', status);
  return status;
});

ipcMain.handle('testDoh', async () => {
  if (!dohManager) return { ok: false, error: t('err.dohNotReady') };
  const res = await dohManager.testConnection();
  send('doh-status', dohManager.getStatus());
  return res;
});

ipcMain.handle('toggleDpi', async (_e, opts) => {
  if (!dpiManager) return null;
  if (opts && opts.mode) prefs.dpiMode = opts.mode;
  if (opts && opts.splitProfile) prefs.dpiSplitProfile = opts.splitProfile;
  const shouldEnable = opts && typeof opts.enabled === 'boolean' ? opts.enabled : !dpiManager.enabled;
  prefs.dpi = shouldEnable;

  let status;
  if (shouldEnable) {
    status = await dpiManager.start({ mode: prefs.dpiMode, splitProfile: prefs.dpiSplitProfile });
  } else {
    status = await dpiManager.stop();
  }
  await applyNetworkProxiesToAllSessions();
  return status;
});

ipcMain.handle('configureDpi', async (_e, opts) => {
  if (!dpiManager) return null;
  if (opts && opts.mode) prefs.dpiMode = opts.mode;
  if (opts && opts.splitProfile) prefs.dpiSplitProfile = opts.splitProfile;
  if (dpiManager.enabled) {
    await dpiManager.start({ mode: prefs.dpiMode, splitProfile: prefs.dpiSplitProfile });
    await applyNetworkProxiesToAllSessions();
  }
  return dpiManager.getStatus();
});

ipcMain.handle('testDpi', async () => {
  if (!dpiManager) return { ok: false, error: t('err.dpiNotReady') };
  const wasEnabled = dpiManager.enabled;
  try {
    if (!wasEnabled) {
      await dpiManager.start({ mode: prefs.dpiMode || 'builtin', splitProfile: prefs.dpiSplitProfile || 'sni-frag' });
      prefs.dpi = true;
      await applyNetworkProxiesToAllSessions();
    }
    const port = dpiManager.port;
    if (!port) {
      return { ok: false, error: t('err.dpiPortFail') };
    }
    const beforeFrag = dpiManager.stats.fragmentedHandshakes || 0;
    const t0 = Date.now();
    const traceInfo = await new Promise((resolve, reject) => {
      const req = http.request({
        host: '127.0.0.1',
        port,
        method: 'CONNECT',
        path: 'www.cloudflare.com:443',
        timeout: 8000
      });
      req.on('connect', (_res, socket) => {
        const tlsSock = tls.connect(
          { socket, servername: 'www.cloudflare.com', timeout: 8000 },
          () => {
            tlsSock.write('GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n');
          }
        );
        let raw = '';
        tlsSock.on('data', d => { raw += d.toString(); });
        tlsSock.on('end', () => resolve(raw));
        tlsSock.on('error', reject);
      });
      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy(new Error(t('err.timeout')));
      });
      req.end();
    });
    const latencyMs = Date.now() - t0;
    const afterFrag = dpiManager.stats.fragmentedHandshakes || 0;
    const ipMatch = traceInfo.match(/ip=([^\r\n]+)/);
    const coloMatch = traceInfo.match(/colo=([^\r\n]+)/);
    const tlsMatch = traceInfo.match(/tls=([^\r\n]+)/);
    const status = dpiManager.getStatus();
    send('dpi-status', status);
    return {
      ok: true,
      latencyMs,
      fragmentedDelta: Math.max(1, afterFrag - beforeFrag),
      totalFragmented: afterFrag,
      dohResolved: dpiManager.stats.dohResolved || 0,
      proxyAddress: dpiManager.proxyAddress,
      splitProfile: dpiManager.splitProfile,
      ip: ipMatch ? ipMatch[1].trim() : '',
      colo: coloMatch ? coloMatch[1].trim() : '',
      tlsVersion: tlsMatch ? tlsMatch[1].trim() : 'TLSv1.3',
      status
    };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

ipcMain.handle('startTor', async (_e, opts) => {
  if (!torManager) return null;
  return await ensureTorStartedOrInstalled(opts || { allowExternalTor: !!prefs.allowExternalTor });
});

ipcMain.handle('stopTor', async () => {
  if (!torManager) return null;
  return await torManager.stop(!!prefs.clearTorDataOnExit);
});

ipcMain.handle('newTorIdentity', async () => {
  if (!torManager) return null;
  // 1) Tor devrelerini CookieAuthentication ile yenile
  const status = await torManager.newIdentity();
  // 2) Tüm açık "🧅 Tor Zırhlı" sekme oturumlarını sıfırla ve First-Party devrelerini yenile
  try {
    const torPartitions = new Set([getPartitionName('🧅 Tor Zırhlı')]);
    for (const [tabId, r] of views.entries()) {
      if (normalizeContainerName(r.container) === '🧅 Tor Zırhlı') {
        torPartitions.add(getPartitionName('🧅 Tor Zırhlı', tabId));
      }
    }
    for (const part of torPartitions) {
      const torSes = session.fromPartition(part);
      await torSes.clearStorageData();
      await torSes.clearCache();
      await torSes.clearHostResolverCache();
      await torSes.clearAuthCache();
      await torSes.closeAllConnections();
    }
    await applyNetworkProxiesToAllSessions();
  } catch {}
  sessionSalt = crypto.randomBytes(12).toString('hex');
  try {
    if (sponsorBlockService && typeof sponsorBlockService.clearCache === 'function') {
      sponsorBlockService.clearCache();
    }
    if (translatorService && typeof translatorService.clearCache === 'function') {
      translatorService.clearCache();
    }
  } catch {}
  return status;
});

ipcMain.handle('installTor', async () => {
  if (!torManager) return null;
  const status = await torManager.installTorBinary();
  await applyNetworkProxiesToAllSessions();
  return status;
});

ipcMain.handle('verifyTorIp', async () => {
  if (!torManager) return null;
  return await torManager.verifyTorExitIp();
});

/* ---------- Canlı İstek Denetçisi (Inspector) & Kalkan IPC ---------- */
ipcMain.handle('getInspector', (_e, id) => {
  const targetId = id ?? active;
  if (!adblockEngine || !targetId) return null;
  return adblockEngine.getTabInspectorReport(targetId);
});

ipcMain.handle('toggleSiteShield', (_e, host) => {
  if (!adblockEngine || !host) return false;
  const whitelisted = adblockEngine.toggleSiteWhitelist(host);
  const rec = views.get(active);
  if (rec) rec.view.webContents.reload();
  return whitelisted;
});

ipcMain.handle('setDomainRule', (_e, domain, action) => {
  if (!adblockEngine || !domain) return false;
  adblockEngine.setCustomDomainRule(domain, action);
  const rec = views.get(active);
  if (rec) rec.view.webContents.reload();
  return true;
});

async function resolveServiceRuntimeNetwork(senderWc, opts = {}) {
  let tabRec = null;
  if (senderWc && win && senderWc.id !== win.webContents.id) {
    for (const r of views.values()) {
      if (r.view && r.view.webContents && r.view.webContents.id === senderWc.id) {
        tabRec = r;
        break;
      }
    }
  }
  if (!tabRec && active) {
    tabRec = views.get(active) || null;
  }

  const inTorTab = !!(tabRec && normalizeContainerName(tabRec.container) === '🧅 Tor Zırhlı');
  const torConnected = !!(torManager && torManager.state === 'connected');
  const preferTor = !opts.forceNonTor && (inTorTab || torConnected);

  if (inTorTab && !torConnected && !opts.forceNonTor) {
    return {
      torRequired: true,
      torConnected: false,
      torBlocked: true,
      torBlockedReason: t('err.torTitle'),
      proxyUrl: '',
      fetchFn: () => Promise.reject(new Error(t('err.torTitle')))
    };
  }

  if (preferTor && torConnected) {
    let targetHost = '';
    try {
      if (opts.targetUrl && /^https?:\/\//i.test(opts.targetUrl)) {
        targetHost = new URL(opts.targetUrl).hostname;
      }
    } catch {}
    const svcKey = `service-${opts.serviceTag || 'gen'}-${tabRec?.id || 'global'}`;
    const isolatedProxy = await torManager.getIsolatedHttpProxyUrl(targetHost || svcKey);
    return {
      torRequired: inTorTab,
      torConnected: true,
      torBlocked: false,
      proxyUrl: isolatedProxy || `socks5h://127.0.0.1:${torManager.socksPort}`,
      fetchFn: async (url, reqOpts = {}) => {
        let reqHost = targetHost;
        try {
          reqHost = new URL(url).hostname || targetHost;
        } catch {}
        const torSes = await ensureSessionReady('🧅 Tor Zırhlı', svcKey, reqHost || svcKey);
        return torSes.fetch(url, {
          ...reqOpts,
          credentials: 'omit',
          referrerPolicy: 'no-referrer'
        });
      }
    };
  }

  const svcSes = await getHardenedEphemeralSession(SERVICE_EPHEMERAL_PARTITION, 'Geçici');

  const dpiProxyUrl =
    dpiManager && dpiManager.enabled && dpiManager.proxyPort > 0
      ? `http://127.0.0.1:${dpiManager.proxyPort}`
      : '';

  return {
    torRequired: false,
    torConnected: false,
    torBlocked: false,
    proxyUrl: dpiProxyUrl,
    fetchFn: async (url, reqOpts = {}) =>
      svcSes.fetch(url, {
        ...reqOpts,
        credentials: 'omit',
        referrerPolicy: 'no-referrer'
      })
  };
}

ipcMain.handle('updateAdblockLists', async e => {
  if (!adblockEngine) return { ok: false };
  const rt = await resolveServiceRuntimeNetwork(e?.sender);
  if (rt.torBlocked) return { ok: false, error: rt.torBlockedReason };
  return await adblockEngine.updateFilterListsOnline(rt.fetchFn);
});

/* ---------- Zaslon Meta-Arama Motoru (zaslon://search) ---------- */
async function resolveMetaSearchRuntimeOpts(sender, optsOrSearx) {
  const opts =
    typeof optsOrSearx === 'string'
      ? { searxngUrl: optsOrSearx }
      : optsOrSearx && typeof optsOrSearx === 'object'
        ? optsOrSearx
        : {};

  let tabRec = opts.tabId ? views.get(opts.tabId) : null;
  if (!tabRec && sender) {
    for (const r of views.values()) {
      if (r.view && r.view.webContents && r.view.webContents.id === sender.id) {
        tabRec = r;
        break;
      }
    }
  }
  if (!tabRec && active) tabRec = views.get(active) || null;

  const isTorTab = normalizeContainerName(tabRec?.container) === '🧅 Tor Zırhlı';
  const routing = String(opts.routing || prefs.metaSearchRouting || 'tab').toLowerCase();
  const requireTor = Boolean(opts.requireTor ?? prefs.metaSearchRequireTor);
  const regional = Boolean(opts.regional ?? prefs.metaSearchRegional);
  const torConnected = Boolean(torManager && torManager.state === 'connected');
  const shouldUseTor = isTorTab || routing === 'tor' || requireTor || (torConnected && routing === 'tab');

  let routedVia = shouldUseTor ? 'tor' : 'ephemeral';
  let fetchFn;

  if (shouldUseTor) {
    if (!torConnected) {
      fetchFn = async () => {
        throw new Error(t('search.errTorRequired'));
      };
    } else {
      const searchTabKey = tabRec?.id ? `search-tab-${tabRec.id}` : 'search-tab-global';
      const torSes = await ensureSessionReady('🧅 Tor Zırhlı', searchTabKey, `${searchTabKey}.local`);
      fetchFn = (url, o) => torSes.fetch(url, { ...(o || {}), credentials: 'omit' });
    }
  } else {
    const metaSes = await getHardenedEphemeralSession('zaslon-ephemeral-metasearch', 'Kişisel');
    fetchFn = (url, o) => metaSes.fetch(url, { ...(o || {}), credentials: 'omit' });
  }

  const providers = {
    ...(prefs.metaSearchProviders || {}),
    ...(opts.providers && typeof opts.providers === 'object' ? opts.providers : {})
  };

  return {
    fetchFn,
    searxngUrl: opts.searxngUrl || '',
    providers,
    regional,
    routedVia,
    requireTor: shouldUseTor,
    torConnected,
    torError: t('search.errTorRequired')
  };
}

ipcMain.handle('metaSearch', async (e, query, optsOrSearx) => {
  try {
    const runtimeOpts = await resolveMetaSearchRuntimeOpts(e.sender, optsOrSearx);
    const res = await performMetaSearch(query, runtimeOpts);
    if (res.strippedCount > 0) {
      trackedDelta += res.strippedCount;
    }
    return res;
  } catch (err) {
    return {
      ok: false,
      query: String(query || ''),
      tookMs: 0,
      results: [],
      instant: null,
      providers: {},
      strippedCount: 0,
      error: err.message
    };
  }
});

ipcMain.handle('metaFetchImage', async (e, imgUrl, opts = {}) => {
  try {
    const u = new URL(String(imgUrl || '').trim());
    if (u.protocol !== 'https:') return { ok: false };
    const runtimeOpts = await resolveMetaSearchRuntimeOpts(e.sender, opts);
    if (runtimeOpts.requireTor && !runtimeOpts.torConnected) {
      return { ok: false, blockedByTor: true };
    }
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 4500);
    try {
      const res = await runtimeOpts.fetchFn(u.toString(), {
        method: 'GET',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        signal: ctrl.signal
      });
      if (!res.ok) return { ok: false };
      const ctype = String(res.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
      if (!ctype.startsWith('image/') || ctype === 'image/svg+xml') return { ok: false };
      const lenHdr = Number(res.headers.get('content-length') || 0);
      if (lenHdr > 2 * 1024 * 1024) return { ok: false };
      const buf = Buffer.from(await res.arrayBuffer());
      if (!buf.length || buf.length > 2 * 1024 * 1024) return { ok: false };
      return { ok: true, dataUrl: `data:${ctype};base64,${buf.toString('base64')}` };
    } finally {
      clearTimeout(timer);
    }
  } catch {
    return { ok: false };
  }
});

ipcMain.handle('clearContainerData', async (_e, container) => {
  try {
    const ses = session.fromPartition(getPartitionName(container || 'Kişisel'));
    await ses.clearStorageData({
      storages: [
        'cookies',
        'filesystem',
        'indexdb',
        'localstorage',
        'shadercache',
        'websql',
        'serviceworkers',
        'cachestorage'
      ]
    });
    await ses.clearCache();
    await ses.clearHostResolverCache();
    await ses.clearAuthCache();
    return true;
  } catch {
    return false;
  }
});

/* ---------- Panik / Her Şeyi Yak (🔥) & Veri Temizleme Kancaları ---------- */
const privacyCleanupHooks = new Set();

function registerPrivacyCleanupHook(fn) {
  if (typeof fn === 'function') privacyCleanupHooks.add(fn);
  return () => privacyCleanupHooks.delete(fn);
}

async function wipeAllSessionsAndStorage(opts = {}) {
  for (const hook of privacyCleanupHooks) {
    try {
      await hook(opts);
    } catch {}
  }
  const sessionsToClear = [
    session.defaultSession,
    session.fromPartition(SERVICE_EPHEMERAL_PARTITION),
    session.fromPartition(DOH_DIRECT_PARTITION),
    session.fromPartition('zaslon-ephemeral-metasearch'),
    session.fromPartition('zaslon-ephemeral-translator')
  ];
  for (const part of prepared) {
    sessionsToClear.push(session.fromPartition(part));
  }
  for (const r of views.values()) {
    try {
      if (r.container === '🧅 Tor Zırhlı') {
        sessionsToClear.push(r.ses || session.fromPartition(getPartitionName(r.container, r.id)));
      }
      if (r.view && r.view.webContents && !r.view.webContents.isDestroyed()) {
        sessionsToClear.push(r.view.webContents.session);
      }
    } catch {}
  }
  if (Array.isArray(opts.extraSessions)) {
    for (const extraSes of opts.extraSessions) {
      if (extraSes) sessionsToClear.push(extraSes);
    }
  }
  for (const ses of [...new Set(sessionsToClear)]) {
    try {
      await ses.clearStorageData({
        storages: [
          'cookies',
          'filesystem',
          'indexdb',
          'localstorage',
          'shadercache',
          'websql',
          'serviceworkers',
          'cachestorage'
        ]
      });
      await ses.clearCache();
      await ses.clearHostResolverCache();
      await ses.clearAuthCache();
      if (typeof ses.closeAllConnections === 'function') {
        await ses.closeAllConnections();
      }
    } catch {}
  }
  if (encryptedVault) {
    encryptedVault.checkpointWal();
  }
}

ipcMain.handle('clearData', async () => {
  await wipeAllSessionsAndStorage();
  return true;
});

ipcMain.handle('panicBurn', async () => {
  // 1. Aktif tüm yt-dlp / HLS / medya indirme süreçlerini ve geçici çerez dosyalarını anında sonlandır
  if (ytDlpManager) {
    try { ytDlpManager.cancelAllJobs(true); } catch {}
  }
  send('ytdlp-progress', null);

  // 2. Sistem panosunu (kopyalanmış URL/parola/metin) temizle ve LAN eşitleme sunucusu açıksa kapat
  try { clipboard.clear(); } catch {}
  if (lanSyncManager && lanSyncManager.running) {
    try { await lanSyncManager.stop(); } catch {}
  }

  // 3. Tüm açık WebContentsView sekmelerini (ses/video/WebRTC dahil) anında sustur ve yok et
  //    (views.clear() öncesi aktif Tor/sekme oturum referanslarını topla)
  const extraSessionsToWipe = [];
  for (const [tabId, rec] of views.entries()) {
    try {
      const wc = rec.view.webContents;
      if (wc && !wc.isDestroyed()) {
        if (wc.session) extraSessionsToWipe.push(wc.session);
        try { wc.setAudioMuted(true); } catch {}
        try { wc.stop(); } catch {}
      }
      if (normalizeContainerName(rec.container) === '🧅 Tor Zırhlı') {
        extraSessionsToWipe.push(rec.ses || session.fromPartition(getPartitionName(rec.container, tabId)));
      }
      if (win && !win.isDestroyed()) win.contentView.removeChildView(rec.view);
      if (wc && !wc.isDestroyed()) wc.close();
    } catch {}
  }
  views.clear();
  active = null;
  fsView = false;

  // 4. Canlı İstek Denetçisi, Medya Yakalayıcı, Tor devresini ve oturum parmak izi tuzunu sıfırla
  if (adblockEngine) adblockEngine.clearAllReports();
  if (streamSniffer) streamSniffer.clearAll();
  if (torManager) await torManager.newIdentity().catch(() => {});
  sessionSalt = crypto.randomBytes(12).toString('hex');

  // 5. Şifreli yerel kasadaki geçmiş, oturum ve okuma izlerini kriptografik olarak ez (VACUUM)
  if (encryptedVault) {
    encryptedVault.panicWipe(false);
  }

  // 6. Tüm çerezleri, önbelleği, DNS önbelleğini, açık soketleri ve site depolarını kalıntısız sil
  await wipeAllSessionsAndStorage({ extraSessions: extraSessionsToWipe });
  return { ok: true, wipedAt: Date.now() };
});

/* ---------- Faz 4: Medya Üssü, SingleFile, Tam Sayfa Çeviri, Ekran Görüntüsü, RSS ve UserScript ---------- */
ipcMain.handle('freeze', async () => {
  const rec = views.get(active);
  if (!rec) return null;
  try {
    const img = await rec.view.webContents.capturePage();
    rec.view.setVisible(false);
    return 'data:image/jpeg;base64,' + img.toJPEG(82).toString('base64');
  } catch {
    rec.view.setVisible(false);
    return null;
  }
});

// Gelişmiş Ekran Görüntüsü: Görünür Alan (visible), Bölge Kırpma (region) ve Tam Sayfa Kaydırmalı (fullpage)
ipcMain.handle('shot', async (_e, opts) => {
  const rec = views.get(active);
  if (!rec) return null;
  const picturesDir = app.getPath('pictures');
  const mode = opts && typeof opts === 'object' ? opts.mode : 'visible';
  try {
    if (mode === 'region' && opts.rect) {
      const res = await captureCroppedRegion(rec.view.webContents, opts.rect, picturesDir, clipboard);
      return res.ok ? res.path : null;
    }
    if (mode === 'fullpage') {
      const res = await captureFullPageScrolling(rec.view.webContents, picturesDir, clipboard, nativeImage);
      return res.ok ? res.path : null;
    }
    const res = await captureVisibleViewport(rec.view.webContents, picturesDir, clipboard);
    return res.ok ? res.path : null;
  } catch {
    return null;
  }
});

// Tek Dosya Sayfa Kaydedici (SingleFile .html Çevrimdışı Arşivleme)
ipcMain.handle('saveSingleFile', async (_e, id) => {
  const r = views.get(id ?? active);
  if (!r) return { ok: false, error: t('err.noActiveTab') };
  const dlDir = app.getPath('downloads');
  const res = await saveSingleFileArchive(r.view.webContents, dlDir);
  if (res && res.ok) {
    send('dl', {
      id: `sf-${Date.now()}`,
      name: res.fileName,
      received: res.sizeBytes,
      total: res.sizeBytes,
      state: 'done',
      path: res.path
    });
    shell.showItemInFolder(res.path);
  }
  return res;
});

ipcMain.handle('pdf', async (_e, id) => {
  const r = views.get(id ?? active);
  if (!r) return null;
  try {
    const buf = await r.view.webContents.printToPDF({ printBackground: true });
    const f = path.join(app.getPath('downloads'), `Zaslon-${Date.now()}.pdf`);
    fs.writeFileSync(f, buf);
    shell.showItemInFolder(f);
    return f;
  } catch {
    return null;
  }
});

ipcMain.handle('pip', async (_e, id) => {
  const r = views.get(id ?? active);
  if (!r) return 'no';
  try {
    return await r.view.webContents.executeJavaScript(
      `(() => {
        const v = [...document.querySelectorAll('video')].sort((a, b) => b.clientWidth * b.clientHeight - a.clientWidth * a.clientHeight)[0];
        if (!v) return 'no';
        v.removeAttribute('disablepictureinpicture');
        v.disablePictureInPicture = false;
        if (document.pictureInPictureElement === v) {
          return document.exitPictureInPicture().then(() => 'exited').catch(e => String(e));
        }
        return v.requestPictureInPicture().then(() => 'ok').catch(e => String(e));
      })()`,
      true
    );
  } catch {
    return 'no';
  }
});

// 0.25x - 4.0x Evrensel Video Hız Kontrolü, Ses Güçlendirici (GainNode %100-%300) ve Döngü
ipcMain.handle('videoControl', async (_e, id, actionOrObj, maybeVal) => {
  const r = views.get(id ?? active);
  if (!r) return { ok: false, error: t('err.tabNotFound') };
  const wc = r.view?.webContents;
  if (!wc || wc.isDestroyed()) return { ok: false, error: t('err.tabNotFound') };
  const action = actionOrObj && typeof actionOrObj === 'object' ? actionOrObj.action : actionOrObj;
  const value = actionOrObj && typeof actionOrObj === 'object' ? actionOrObj.value : maybeVal;
  const reqId = `vc-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  return await new Promise(resolve => {
    const channel = `zaslon-video-control-res-${reqId}`;
    const timer = setTimeout(() => {
      ipcMain.removeAllListeners(channel);
      resolve({ ok: false, error: t('err.noPlayableVideo') });
    }, 2500);
    ipcMain.once(channel, (_ev, result) => {
      clearTimeout(timer);
      resolve(result || { ok: false, error: t('err.noPlayableVideo') });
    });
    try {
      wc.send('zaslon-video-control', { reqId, action, value });
    } catch (err) {
      clearTimeout(timer);
      ipcMain.removeAllListeners(channel);
      resolve({ ok: false, error: err.message });
    }
  });
});

// Medya Akış Yakalayıcı (StreamSniffer) & SponsorBlock IPC
ipcMain.on('dom-media-detected', (e, info) => {
  if (!streamSniffer) return;
  const tabId = streamSniffer.wcToTabId.get(e.sender.id);
  if (tabId) {
    streamSniffer.recordDomMedia(tabId, info);
  }
});

ipcMain.handle('getTabStreams', (_e, id) => {
  const targetId = id ?? active;
  if (!streamSniffer || !targetId) return [];
  return streamSniffer.getTabStreams(targetId);
});

ipcMain.handle('clearTabStreams', (_e, id) => {
  const targetId = id ?? active;
  if (streamSniffer && targetId) streamSniffer.clearTabStreams(targetId);
  return [];
});

ipcMain.handle('get-sponsorblock-segments', async (e, url) => {
  if (!sponsorBlockService || !prefs.sponsorBlock) return [];
  const rt = await resolveServiceRuntimeNetwork(e?.sender);
  return await sponsorBlockService.getSegmentsForVideo(url, rt);
});

ipcMain.on('sponsorblock-skipped', (_e, info) => {
  if (!sponsorBlockService) return;
  const st = sponsorBlockService.recordSkip(info?.duration || 0);
  send('sponsorblock-stats', st);
});

ipcMain.handle('getSponsorBlockStats', () => {
  return sponsorBlockService ? sponsorBlockService.getStats() : { enabled: true, skippedCount: 0, savedSeconds: 0 };
});

// Sınırsız Video & Ses İndirici (yt-dlp + Yerleşik Akış/HLS İndirici)
async function buildTabDownloadContext(targetUrl) {
  const ctx = {
    referer: '',
    userAgent: '',
    cookieHeader: '',
    cookiesTxtPath: '',
    fallbackStreams: []
  };
  try {
    const rec = views.get(active);
    if (!rec || !rec.view || !rec.view.webContents || rec.view.webContents.isDestroyed()) {
      return ctx;
    }
    const wc = rec.view.webContents;
    ctx.referer = wc.getURL() || '';
    ctx.userAgent =
      normalizeContainerName(rec.container) === '🧅 Tor Zırhlı'
        ? UNIFORM_BROWSER_UA
        : (wc.getUserAgent() || UNIFORM_BROWSER_UA);
    if (streamSniffer && active) {
      ctx.fallbackStreams = streamSniffer
        .getTabStreams(active)
        .filter(s => s && !s.isPlatformPage && /^https?:\/\//i.test(s.url));
    }

    const ses = wc.session;
    if (ses && ses.cookies && targetUrl && /^https?:\/\//i.test(targetUrl)) {
      // Yalnızca hedef URL kapsamındaki çerezleri bellek içinde al (asla diske cookies.txt yazma)
      try {
        const urlCookies = await ses.cookies.get({ url: targetUrl });
        if (urlCookies && urlCookies.length) {
          ctx.cookieHeader = urlCookies.map(c => `${c.name}=${c.value}`).join('; ');
        }
      } catch {}
    }
  } catch {}
  return ctx;
}

ipcMain.handle('getYtDlpStatus', () => {
  return ytDlpManager ? ytDlpManager.getStatus() : { hasYtDlp: false };
});

ipcMain.handle('installYtDlp', async e => {
  if (!ytDlpManager) return { hasYtDlp: false };
  const rt = await resolveServiceRuntimeNetwork(e?.sender);
  return await ytDlpManager.installYtDlpBinary(rt);
});

ipcMain.handle('downloadMedia', async (e, opts = {}) => {
  if (!ytDlpManager) return { ok: false, error: t('err.dlNotReady') };
  const safeOpts = opts && typeof opts === 'object' ? opts : {};
  const [ctx, rt] = await Promise.all([
    buildTabDownloadContext(safeOpts.url),
    resolveServiceRuntimeNetwork(e?.sender, { targetUrl: safeOpts.url, serviceTag: 'ytdlp' })
  ]);
  return await ytDlpManager.startDownload({ ...safeOpts, ...ctx, ...rt, args: null });
});

ipcMain.handle('cancelMediaDownload', () => {
  if (!ytDlpManager) return { ok: false };
  return ytDlpManager.cancelAllJobs(false);
});

const ALLOWED_YTDLP_QUALITIES = new Set(['best', '1080p', '720p', '480p', 'audio-mp3', 'audio-m4a']);
ipcMain.on('ytdlp', async (e, url, qualityArg) => {
  if (ytDlpManager) {
    const cleanUrl = String(url || '').trim();
    if (!/^https?:\/\//i.test(cleanUrl) || /[\r\n\0]/.test(cleanUrl)) return;
    const quality = ALLOWED_YTDLP_QUALITIES.has(qualityArg) ? qualityArg : 'best';
    const [ctx, rt] = await Promise.all([
      buildTabDownloadContext(cleanUrl),
      resolveServiceRuntimeNetwork(e?.sender, { targetUrl: cleanUrl, serviceTag: 'ytdlp' })
    ]);
    ytDlpManager.startDownload({ ...ctx, ...rt, url: cleanUrl, quality, args: null });
  }
});

// Seçilebilir Çift Katmanlı (Hibrit Yerel NMT + Çevrimiçi) Çeviri & Tam Sayfa DOM Çevirisi
async function resolveTranslatorRuntimeOpts(senderWc, body = {}) {
  let tabRec = null;
  if (senderWc && win && senderWc.id !== win.webContents.id) {
    for (const r of views.values()) {
      if (r.view?.webContents?.id === senderWc.id) {
        tabRec = r;
        break;
      }
    }
  }
  if (!tabRec && body.tabId != null) {
    tabRec = views.get(body.tabId) || null;
  }
  if (!tabRec && active != null) {
    tabRec = views.get(active) || null;
  }

  const normContainer = normalizeContainerName(tabRec?.container);
  const isTorTab = normContainer === '🧅 Tor Zırhlı';
  const reqEngine = body.engine || prefs.trEngine || 'auto_private';
  const reqRouting = body.routing || prefs.trRouting || 'tab';
  const torConnected = Boolean(torManager && torManager.state === 'connected');
  const effectiveRouting =
    reqRouting === 'offline'
      ? 'offline'
      : isTorTab || reqRouting === 'tor' || (torConnected && reqRouting === 'tab')
        ? 'tor'
        : 'direct';

  let fetchFn = (url, opts) => net.fetch(url, opts);
  let torNotReadyError = '';

  if (effectiveRouting === 'tor') {
    if (!torConnected) {
      torNotReadyError = t('translator.errTorNotReady');
      fetchFn = async () => {
        throw new Error(torNotReadyError);
      };
    } else {
      const trTabKey = tabRec?.id ? `translate-tab-${tabRec.id}` : 'translate-tab-global';
      const torSes = await ensureSessionReady('🧅 Tor Zırhlı', trTabKey, `${trTabKey}.local`);
      fetchFn = (url, opts) => torSes.fetch(url, { ...(opts || {}), credentials: 'omit' });
    }
  } else if (effectiveRouting === 'direct') {
    const anonSes = await getHardenedEphemeralSession('zaslon-ephemeral-translator', 'Kişisel');
    fetchFn = (url, opts) => anonSes.fetch(url, { ...(opts || {}), credentials: 'omit' });
  }

  return {
    engine: reqEngine,
    routing: reqRouting,
    routedVia: effectiveRouting,
    isTorTab,
    allowGoogle: !isTorTab && reqRouting !== 'offline',
    torNotReadyError,
    fetchFn,
    lingvaUrl: body.lingvaUrl ?? prefs.trLingvaUrl ?? '',
    localConfig: {
      type: body.localServerType || prefs.trLocalServerType || 'libretranslate',
      url: body.localServerUrl ?? prefs.trLocalServerUrl ?? '',
      model: body.localServerModel || prefs.trLocalServerModel || 'qwen2.5:3b'
    }
  };
}

ipcMain.handle('translate', async (e, body) => {
  if (!translatorService) return { ok: false, error: t('err.translatorNotReady') };
  const runtimeOpts = await resolveTranslatorRuntimeOpts(e.sender, body || {});
  return await translatorService.translateText(body || {}, runtimeOpts);
});

ipcMain.handle('translateBatch', async (e, body) => {
  if (!translatorService) return { ok: false, translations: [] };
  const runtimeOpts = await resolveTranslatorRuntimeOpts(e.sender, body || {});
  return await translatorService.translateBatch(body || {}, runtimeOpts);
});

ipcMain.handle('translatorGetState', () => {
  if (!translatorService) return null;
  const activeRec = views.get(active) || null;
  const isTorTab = normalizeContainerName(activeRec?.container) === '🧅 Tor Zırhlı';
  return {
    ...translatorService.localEngine.getModelsStatus(),
    activeTabIsTor: isTorTab,
    torConnected: !!(torManager && torManager.state === 'connected')
  };
});

ipcMain.handle('translatorInstallModel', async (_e, pair, opts = {}) => {
  if (!translatorService) return { ok: false, error: t('err.translatorNotReady') };
  let fetchFn;
  if ((opts?.useTor || (torManager && torManager.state === 'connected')) && torManager && torManager.state === 'connected') {
    const torSes = await ensureSessionReady('🧅 Tor Zırhlı', 'translate-model-install', 'translate-model-install.local');
    fetchFn = (url, o) => torSes.fetch(url, { ...(o || {}), credentials: 'omit' });
  } else {
    const anonSes = await getHardenedEphemeralSession('zaslon-ephemeral-translator', 'Kişisel');
    fetchFn = (url, o) => anonSes.fetch(url, { ...(o || {}), credentials: 'omit' });
  }
  return await translatorService.localEngine.installModelPair(pair, {
    fetchFn,
    onProgress: prog => send('translator-model-progress', prog)
  });
});

ipcMain.handle('translatorDeleteModel', async (_e, pair) => {
  if (!translatorService) return { ok: false, error: t('err.translatorNotReady') };
  return await translatorService.localEngine.deleteModelPair(pair);
});

ipcMain.handle('translatePageDom', async (_e, id, opts = {}) => {
  const r = views.get(id ?? active);
  if (!r) return { ok: false, error: t('err.noActiveWebPage') };
  const wc = r.view.webContents;
  const url = wc.getURL() || '';
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    return { ok: false, error: t('err.onlyWebPagesTranslate') };
  }
  return await new Promise(resolve => {
    const timeout = setTimeout(() => {
      ipcMain.removeListener('zaslon-dom-translate-done', onDone);
      resolve({ ok: false, error: t('err.translateTimeout') });
    }, 30000);
    const onDone = (ev, res) => {
      if (ev.sender.id !== wc.id) return;
      clearTimeout(timeout);
      ipcMain.removeListener('zaslon-dom-translate-done', onDone);
      resolve(res);
    };
    ipcMain.on('zaslon-dom-translate-done', onDone);
    wc.send('zaslon-dom-translate', opts);
  });
});

// Algoritmasız Yerel RSS & YouTube Kanal Okuyucusu
ipcMain.handle('fetchRssFeed', async (e, url) => {
  if (!rssService) return { ok: false, error: t('err.rssNotReady') };
  const rt = await resolveServiceRuntimeNetwork(e?.sender);
  return await rssService.fetchSingleFeed(url, rt);
});

ipcMain.handle('fetchMultipleRss', async (e, feeds) => {
  if (!rssService) return { ok: false, feeds: [], items: [] };
  const rt = await resolveServiceRuntimeNetwork(e?.sender);
  return await rssService.fetchMultipleFeeds(feeds, rt);
});

// Hafif UserScript Motoru
ipcMain.handle('getUserScripts', () => {
  return userScriptManager ? userScriptManager.getAllScripts() : [];
});

ipcMain.handle('saveUserScript', (_e, scriptData) => {
  if (!userScriptManager) return null;
  const saved = userScriptManager.upsertScript(scriptData);
  const rec = views.get(active);
  if (rec) rec.view.webContents.reload();
  return saved;
});

ipcMain.handle('toggleUserScript', (_e, id, enabled) => {
  if (!userScriptManager) return null;
  const updated = userScriptManager.toggleScript(id, enabled);
  const rec = views.get(active);
  if (rec) rec.view.webContents.reload();
  return updated;
});

ipcMain.handle('deleteUserScript', (_e, id) => {
  if (!userScriptManager) return false;
  return userScriptManager.deleteScript(id);
});

/* ---------- Faz 5: AES-256-GCM Şifreli Yerel Kasa (EncryptedVault) & Bulutsuz LAN Eşitleme ---------- */
ipcMain.handle('vaultGetStatus', () => {
  return encryptedVault ? encryptedVault.getStatus() : null;
});

ipcMain.handle('vaultLoadAll', () => {
  if (!encryptedVault) return { ok: false, locked: false, data: {} };
  const all = encryptedVault.getAll();
  return {
    ...all,
    status: encryptedVault.getStatus()
  };
});

ipcMain.handle('vaultSaveKey', (_e, key, value) => {
  if (!encryptedVault) return { ok: false };
  return encryptedVault.set(key, value);
});

ipcMain.handle('vaultSaveBatch', (_e, entriesObj) => {
  if (!encryptedVault) return { ok: false };
  return encryptedVault.setBatch(entriesObj);
});

ipcMain.handle('vaultUnlock', (_e, password) => {
  if (!encryptedVault) return { ok: false, error: t('err.vaultNotReady') };
  const res = encryptedVault.unlock(password);
  if (!res.ok) return res;
  const all = encryptedVault.getAll();
  const status = encryptedVault.getStatus();
  send('vault-status', status);
  return {
    ok: true,
    locked: false,
    data: all.data,
    status
  };
});

ipcMain.handle('vaultLock', () => {
  if (!encryptedVault) return { ok: false };
  const res = encryptedVault.lock();
  const status = encryptedVault.getStatus();
  send('vault-status', status);
  return { ...res, status };
});

ipcMain.handle('vaultSetMasterPassword', (_e, newPassword, currentPassword) => {
  if (!encryptedVault) return { ok: false };
  const res = encryptedVault.setMasterPassword(newPassword, currentPassword);
  const status = encryptedVault.getStatus();
  send('vault-status', status);
  return { ...res, status };
});

ipcMain.handle('vaultRemoveMasterPassword', (_e, currentPassword) => {
  if (!encryptedVault) return { ok: false };
  const res = encryptedVault.removeMasterPassword(currentPassword);
  const status = encryptedVault.getStatus();
  send('vault-status', status);
  return { ...res, status };
});

ipcMain.handle('vaultExportBackup', (_e, password) => {
  if (!encryptedVault) return { ok: false, error: t('err.vaultNotReady') };
  return encryptedVault.exportBackup(password);
});

ipcMain.handle('vaultImportBackup', (_e, rawText, password) => {
  if (!encryptedVault) return { ok: false, error: t('err.vaultNotReady') };
  const res = encryptedVault.importBackup(rawText, password);
  if (res.ok) {
    send('vault-status', encryptedVault.getStatus());
  }
  return res;
});

ipcMain.handle('vaultFactoryReset', async () => {
  if (encryptedVault) encryptedVault.factoryReset();
  await wipeAllSessionsAndStorage();
  return { ok: true, status: encryptedVault ? encryptedVault.getStatus() : null };
});

// Bulutsuz Yerel Ağ (LAN Wi-Fi) Cihazlar Arası Eşitleme & Aktarım IPC
ipcMain.handle('getLanStatus', () => {
  return lanSyncManager ? lanSyncManager.getStatus() : null;
});

ipcMain.handle('startLanSync', async (_e, snapshot, discover = false) => {
  if (!lanSyncManager) return null;
  if (snapshot) lanSyncManager.updateSharedState(snapshot);
  return await lanSyncManager.start(undefined, { discover: !!discover });
});

ipcMain.handle('setLanDiscovery', (_e, active) => {
  if (!lanSyncManager) return false;
  return active ? lanSyncManager.startDiscovery(120000) : lanSyncManager.stopDiscovery();
});

ipcMain.handle('stopLanSync', async () => {
  if (!lanSyncManager) return null;
  return await lanSyncManager.stop();
});

ipcMain.handle('regenerateLanPin', () => {
  if (!lanSyncManager) return null;
  return lanSyncManager.regeneratePin();
});

ipcMain.handle('updateLanSharedState', (_e, snapshot) => {
  if (lanSyncManager && snapshot) {
    lanSyncManager.updateSharedState(snapshot);
  }
  return true;
});

ipcMain.handle('pushToLanPeer', async (_e, opts = {}) => {
  if (!lanSyncManager) return { ok: false, error: t('err.lanNotReady') };
  return await lanSyncManager.pushToPeer(opts.host, opts.port, opts.pin, opts.payload || {});
});

ipcMain.handle('pullFromLanPeer', async (_e, opts = {}) => {
  if (!lanSyncManager) return { ok: false, error: t('err.lanNotReady') };
  return await lanSyncManager.pullFromPeer(opts.host, opts.port, opts.pin);
});

function syncGitHubUpdaterConfigFromVault() {
  if (!githubUpdater) return;
  let cfg = null;
  try {
    if (encryptedVault && !encryptedVault.locked) {
      const res = encryptedVault.get('github_updater_config');
      if (res && res.ok && res.value && typeof res.value === 'object') {
        cfg = res.value;
      }
    }
  } catch {}
  if (!cfg || !cfg.repo) {
    // Opsiyonel kurulum tohum dosyası (yalnızca repo adını ön doldurur)
    const seedCandidates = [
      path.join(path.dirname(process.execPath), 'zaslon-github.json'),
      path.join(app.getPath('userData'), 'zaslon-github.json')
    ];
    for (const p of seedCandidates) {
      try {
        if (fs.existsSync(p)) {
          const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
          if (raw && raw.repo) {
            cfg = { ...(cfg || {}), repo: String(raw.repo) };
            break;
          }
        }
      } catch {}
    }
  }
  if (!cfg) {
    cfg = { repo: 'BeybarsSamuel/zaslon-browser' };
  }
  githubUpdater.setConfig({
    repo: cfg.repo,
    token: cfg.token !== undefined ? cfg.token : undefined
  });
}

ipcMain.handle('updaterGetStatus', () => {
  if (!githubUpdater) return null;
  syncGitHubUpdaterConfigFromVault();
  return githubUpdater.getStatus();
});

ipcMain.handle('updaterSaveConfig', (_e, cfg = {}) => {
  if (!githubUpdater) return { ok: false };
  const nextRepo = cfg.repo !== undefined ? String(cfg.repo) : githubUpdater.repo;
  const nextToken = cfg.token !== undefined ? String(cfg.token) : githubUpdater.token;
  githubUpdater.setConfig({ repo: nextRepo, token: nextToken });
  if (encryptedVault && !encryptedVault.locked) {
    encryptedVault.set('github_updater_config', {
      repo: githubUpdater.repo,
      token: githubUpdater.token
    });
  }
  return { ok: true, status: githubUpdater.getStatus() };
});

ipcMain.handle('updaterCheck', async (_e, cfg = {}) => {
  if (!githubUpdater) return { ok: false, error: 'Updater not ready' };
  syncGitHubUpdaterConfigFromVault();
  const nextRepo = cfg && cfg.repo !== undefined ? String(cfg.repo) : undefined;
  const nextToken = cfg && cfg.token !== undefined ? String(cfg.token) : undefined;
  const res = await githubUpdater.checkForUpdates({ repo: nextRepo, token: nextToken });
  if (encryptedVault && !encryptedVault.locked && (nextRepo !== undefined || nextToken !== undefined)) {
    encryptedVault.set('github_updater_config', {
      repo: githubUpdater.repo,
      token: githubUpdater.token
    });
  }
  return res;
});

ipcMain.handle('updaterDownload', async () => {
  if (!githubUpdater) return { ok: false, error: 'Updater not ready' };
  return await githubUpdater.downloadUpdate();
});

ipcMain.handle('updaterInstall', () => {
  if (!githubUpdater) return { ok: false, error: 'Updater not ready' };
  const res = githubUpdater.installUpdate();
  if (res.ok && res.shouldQuit) {
    setTimeout(() => {
      try {
        app.quit();
      } catch {}
    }, 350);
  }
  return res;
});

/* ---------- Pencere ---------- */
function createWindow() {
  const userDataPath = app.getPath('userData');
  const resourcesPath = app.isPackaged
    ? process.resourcesPath
    : path.join(__dirname, 'resources');
  const downloadsPath = app.getPath('downloads');

  // Faz 5: AES-256-GCM Şifreli Yerel Kasa & Bulutsuz LAN Eşitleme Yöneticisi
  encryptedVault = new EncryptedVault({
    userDataPath,
    safeStorage
  });

  lanSyncManager = new LanSyncManager({
    onStatusChange: st => send('lan-status', st),
    onReceiveItem: item => send('lan-item', item)
  });

  adblockEngine = new AdblockAndInspectorEngine({
    userDataPath,
    resourcesPath,
    onStatsIncrement: (type, count) => {
      if (type === 'ads') blockedDelta += count;
    },
    onInspectorUpdate: (tabId, report) => {
      if (tabId === active) {
        send('inspector', report);
      }
    }
  });

  // Faz 3: Şifreli DNS (DoH), DPI Aşıcı ve Tor Devre İzolasyonu Yöneticileri
  // Not: DoH istekleri DPI proxy döngüsüne girmemeli; yerleşik sağlayıcılarda bootstrap IP + HTTP/2,
  // özel (custom) uç noktalarda ise doğrudan (direct) izole oturum kullanılır.
  dohManager = new DohManager({
    app,
    fallbackFetchFn: async (url, opts) => {
      const dohSes = session.fromPartition(DOH_DIRECT_PARTITION);
      if (!prepared.has(DOH_DIRECT_PARTITION)) {
        prepared.add(DOH_DIRECT_PARTITION);
        try {
          dohSes.setSpellCheckerEnabled?.(false);
          dohSes.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
          dohSes.setPermissionCheckHandler?.(() => false);
          dohSes.setUserAgent(UNIFORM_BROWSER_UA);
          dohSes.webRequest.onBeforeSendHeaders((details, cb) => {
            const h = { ...(details.requestHeaders || {}) };
            for (const hdrKey of Object.keys(h)) {
              const lower = hdrKey.toLowerCase();
              if (
                lower.startsWith('sec-ch-ua') ||
                lower === 'x-client-data' ||
                lower === 'user-agent' ||
                lower === 'accept-language' ||
                lower === 'referer' ||
                lower === 'origin'
              ) {
                delete h[hdrKey];
              }
            }
            h['User-Agent'] = UNIFORM_BROWSER_UA;
            h['Accept-Language'] = 'en-US,en;q=0.5';
            cb({ requestHeaders: h });
          });
        } catch {}
      }
      if (appliedSessionProxyKeys.get(dohSes) !== 'direct') {
        try {
          await dohSes.setProxy({ mode: 'direct' });
          appliedSessionProxyKeys.set(dohSes, 'direct');
        } catch {}
      }
      return dohSes.fetch(url, {
        ...(opts || {}),
        credentials: 'omit',
        referrerPolicy: 'no-referrer'
      });
    }
  });
  dohManager.applyConfig({
    enabled: prefs.dohEnabled,
    provider: prefs.dohProvider,
    customUrl: prefs.dohCustomUrl,
    strictMode: prefs.dohStrict
  });

  dpiManager = new DpiManager({
    dohManager,
    userDataPath,
    resourcesPath,
    onStatusChange: st => send('dpi-status', st)
  });

  torManager = new TorManager({
    userDataPath,
    resourcesPath,
    allowExternalTor: !!prefs.allowExternalTor,
    clearTorDataOnExit: !!prefs.clearTorDataOnExit,
    fetchFn: async (url, opts) => {
      const rt = await resolveServiceRuntimeNetwork(null, { forceNonTor: true });
      return rt.fetchFn(url, opts);
    },
    onStatusChange: st => {
      send('tor-status', st);
      if (st && st.state === 'connected') {
        for (const [tabId, rec] of views.entries()) {
          if (normalizeContainerName(rec.container) === '🧅 Tor Zırhlı' && rec.pendingTorUrl) {
            const targetUrl = rec.pendingTorUrl;
            rec.pendingTorUrl = '';
            let fpHost = '';
            try {
              fpHost = new URL(targetUrl).hostname;
            } catch {}
            ensureSessionReady(rec.container, tabId, fpHost)
              .then(() => {
                if (rec.view && !rec.view.webContents.isDestroyed()) {
                  rec.view.webContents.loadURL(targetUrl).catch(() => {});
                }
              })
              .catch(() => {});
          }
        }
      }
    }
  });
  torManager.ensureIsolationGateway().catch(() => {});

  // Faz 4: Medya Üssü, Çeviri, RSS ve UserScript Yöneticileri
  streamSniffer = new StreamSniffer({
    onUpdate: (tabId, streams) => {
      if (tabId === active) {
        send('media-streams', { tabId, streams });
      }
    }
  });

  sponsorBlockService = new SponsorBlockService({
    fetchFn: async (url, opts) => {
      const rt = await resolveServiceRuntimeNetwork(null);
      return rt.fetchFn(url, opts);
    },
    enabled: prefs.sponsorBlock
  });

  ytDlpManager = new YtDlpManager({
    userDataPath,
    resourcesPath,
    downloadsPath,
    fetchFn: async (url, opts) => {
      const rt = await resolveServiceRuntimeNetwork(null);
      return rt.fetchFn(url, opts);
    },
    onProgress: prog => send('ytdlp-progress', prog),
    onDlEvent: dlItem => send('dl', dlItem),
    onToast: msg => send('toast', msg)
  });

  translatorService = new TranslatorService({
    userDataPath,
    fetchFn: async (url, opts) => {
      const rt = await resolveServiceRuntimeNetwork(null);
      return rt.fetchFn(url, opts);
    }
  });

  rssService = new RssService({
    fetchFn: async (url, opts) => {
      const rt = await resolveServiceRuntimeNetwork(null);
      return rt.fetchFn(url, opts);
    }
  });

  userScriptManager = new UserScriptManager({
    userDataPath
  });

  githubUpdater = new GitHubUpdater({
    userDataPath,
    currentVersion: app.getVersion(),
    preferPortable: !!process.env.PORTABLE_EXECUTABLE_FILE,
    fetchFn: async (url, opts) => {
      const rt = await resolveServiceRuntimeNetwork(null);
      return rt.fetchFn(url, opts);
    },
    onProgress: st => send('updater-status', st)
  });
  syncGitHubUpdaterConfigFromVault();

  const iconPath = path.join(__dirname, 'resources', 'icon.ico');
  win = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#08101f',
    title: 'Zaslon Browser',
    icon: fs.existsSync(iconPath) ? iconPath : undefined,
    titleBarStyle: 'hidden',
    titleBarOverlay: { color: '#08101f', symbolColor: '#e6ecfa', height: 42 },
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      sandbox: true,
      spellcheck: false
    }
  });
  win.loadFile(path.join(__dirname, 'ui.html'));
  win.on('app-command', (e, cmd) => {
    if (cmd === 'browser-backward') {
      e.preventDefault();
      send('cmd', 'back');
    } else if (cmd === 'browser-forward') {
      e.preventDefault();
      send('cmd', 'fwd');
    }
  });
  win.on('closed', () => {
    win = null;
  });
}

app.on('second-instance', () => {
  if (win) {
    if (win.isMinimized()) win.restore();
    win.focus();
  }
});

app.whenReady().then(() => {
  hardenDefaultSession();
  Menu.setApplicationMenu(null);
  createWindow();
});

app.on('before-quit', async () => {
  if (ytDlpManager) {
    try { ytDlpManager.cancelAllJobs(true); } catch {}
  }
  if (translatorService && translatorService.localEngine) {
    await translatorService.localEngine.destroy().catch(() => {});
  }
  if (lanSyncManager) await lanSyncManager.stop().catch(() => {});
  if (dpiManager) await dpiManager.stop(false).catch(() => {});
  if (torManager) await torManager.stop(!!prefs.clearOnExit || !!prefs.clearTorDataOnExit).catch(() => {});
  if (prefs.clearOnExit) {
    if (encryptedVault) encryptedVault.panicWipe(false);
    await wipeAllSessionsAndStorage({ aggressive: true });
  } else if (encryptedVault) {
    encryptedVault.checkpointWal();
  }
});

app.on('window-all-closed', () => app.quit());
