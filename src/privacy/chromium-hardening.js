/**
 * Zaslon Browser — Faz 1: Chromium Motor Karartması & Telemetri Güvenlik Duvarı
 * Tüm arka plan Google/Chromium servislerini, WebRTC UDP sızıntılarını ve telemetri uç noktalarını kapatır.
 */

const TELEMETRY_HOSTS = new Set([
  // Chromium / Google arka plan servisleri ve telemetri
  'connectivitycheck.gstatic.com',
  'clients1.google.com',
  'clients2.google.com',
  'clients3.google.com',
  'clients4.google.com',
  'clients5.google.com',
  'clients6.google.com',
  'update.googleapis.com',
  'safebrowsing.googleapis.com',
  'sb-ssl.google.com',
  'safebrowsing-cache.google.com',
  'content-autofill.googleapis.com',
  'optimizationguide-pa.googleapis.com',
  'clientservices.googleapis.com',
  'chromereporting-pa.googleapis.com',
  'woolyss.com',
  'redirector.gvt1.com',
  'gvt1.com',
  'gvt2.com',
  'edgedl.me.gvt1.com',
  'tools.google.com',
  'dl.google.com',
  'dl-ssl.google.com',
  'clients.l.google.com',
  'spellcheck-pa.googleapis.com',
  'chromesync-pa.googleapis.com',
  'safebrowsing.google.com',
  'crash2.l.google.com',
  'sb.l.google.com',
  'beacons.gcp.gvt2.com',
  'beacons2.gvt2.com',
  'beacons3.gvt2.com',
  'ssl.google-analytics.com',
  'www.google-analytics.com',
  'google-analytics.com',
  'stats.g.doubleclick.net',
  'firebaselogging.googleapis.com',
  'firebaselogging-pa.googleapis.com',
  'app-measurement.com',
  'crashlytics.com',
  'reports.crashlytics.com',
  // Microsoft / Mozilla / Genel telemetri
  'vortex.data.microsoft.com',
  'settings-win.data.microsoft.com',
  'oca.telemetry.microsoft.com',
  'watson.telemetry.microsoft.com',
  'pipe.aria.microsoft.com',
  'browser.events.data.msn.com',
  'telemetry.mozilla.org',
  'incoming.telemetry.mozilla.org',
  'shavar.services.mozilla.com'
]);

/**
 * Electron app.whenReady() öncesinde çağrılmalıdır.
 * Chromium'un arka planda dış sunucularla konuşmasını, ağ durumu korelasyonunu ve WebRTC sızıntısını motor seviyesinde engeller.
 */
function applyChromiumHardeningFlags(app, opts = {}) {
  const secLevel = String(opts?.securityLevel || 'standard').toLowerCase();
  const switches = [
    ['disable-background-networking'],
    ['disable-component-update'],
    ['disable-domain-reliability'],
    ['disable-client-side-phishing-detection'],
    ['disable-sync'],
    ['disable-translate'],
    ['disable-breakpad'],
    ['disable-crash-reporter'],
    ['no-pings'],
    ['no-default-browser-check'],
    ['no-first-run'],
    ['disable-quic'],
    ['disable-background-mode'],
    ['disable-metrics-reporting'],
    ['disable-spell-checking'],
    ['disable-speech-api'],
    ['disable-speech-synthesis-api'],
    ['disable-remote-playback-api'],
    ['disable-notifications'],
    ['dns-prefetch-disable'],
    ['force-color-profile', 'srgb'],
    ['host-resolver-rules', 'MAP dns.quad9.net 9.9.9.9, MAP dns.mullvad.net 194.242.2.2, MAP dns.adguard-dns.com 94.140.14.14, MAP cloudflare-dns.com 1.1.1.1'],
    ['webrtc-ip-handling-policy', 'disable_non_proxied_udp'],
    ['enforce-webrtc-ip-permission-check'],
    [
      'enable-features',
      [
        'SplitCacheByNetworkIsolationKey',
        'PartitionConnectionsByNetworkIsolationKey',
        'SplitCodeCacheByNetworkIsolationKey'
      ].join(',')
    ],
    [
      'disable-features',
      [
        'OptimizationHints',
        'OptimizationHintsFetching',
        'OptimizationGuideModelDownloading',
        'OptimizationTargetPrediction',
        'MediaRouter',
        'Mediafeeds',
        'Translate',
        'AutofillServerCommunication',
        'InterestFeedContentSuggestions',
        'InterestFeedV2',
        'PrivacySandboxSettings4',
        'PrivacySandboxAdsAPIs',
        'FencedFrames',
        'BrowsingTopics',
        'BrowsingTopicsParameters',
        'TopicsAPI',
        'Fledge',
        'ProtectedAudience',
        'TrustTokens',
        'PrivateStateTokens',
        'AttributionReporting',
        'AttributionReportingCrossAppWeb',
        'ChromeWhatsNewUI',
        'HeavyAdPrivacyMitigations',
        'NetworkTimeServiceQuerying',
        'LiveCaption',
        'Reporting',
        'NetworkErrorLogging',
        'SignedExchange',
        'WebOTP',
        'FederatedCredentialManagement',
        'SpellcheckDictionaryDownload',
        'WebBluetooth',
        'WebUSB',
        'WebSerial',
        'WebHID',
        'IdleDetection',
        'ComputePressure',
        'DigitalGoods',
        'PaymentRequest',
        'GenericSensorExtraClasses',
        'FontAccess',
        'WindowManagement',
        'NetworkQualityEstimator'
      ].join(',')
    ]
  ];

  if (secLevel === 'safer' || secLevel === 'safest') {
    switches.push(['js-flags', '--jitless']);
  }

  for (const [key, val] of switches) {
    if (val !== undefined) app.commandLine.appendSwitch(key, val);
    else app.commandLine.appendSwitch(key);
  }
}

/**
 * Bir hostname'in telemetri güvenlik duvarı listesinde olup olmadığını kontrol eder.
 */
function isTelemetryHost(hostname) {
  if (!hostname) return false;
  let h = hostname.toLowerCase();
  while (h) {
    if (TELEMETRY_HOSTS.has(h)) return true;
    const dot = h.indexOf('.');
    if (dot < 0) break;
    h = h.slice(dot + 1);
  }
  return false;
}

/**
 * WebContentsView örneğine WebRTC IP sızıntı kilidini ve güvenlik politikasını uygular.
 */
function hardenWebContents(wc, _securityLevel = 'standard') {
  try {
    if (typeof wc.setWebRTCIPHandlingPolicy === 'function') {
      wc.setWebRTCIPHandlingPolicy('disable_non_proxied_udp');
    }
  } catch {}
}

/**
 * Letterboxing (Tor Browser ekran boyutu gizleme):
 * İç görünüm alanını 200x100 pikselin katlarına yuvarlayarak pencere boyutundan parmak izi çıkarılmasını önler.
 */
function computeLetterboxBounds(bounds, enabled = false) {
  if (!enabled || !bounds || bounds.width < 400 || bounds.height < 300) {
    return bounds;
  }
  const stepW = 200;
  const stepH = 100;
  const w = Math.max(400, Math.floor(bounds.width / stepW) * stepW);
  const h = Math.max(300, Math.floor(bounds.height / stepH) * stepH);
  const offsetX = Math.floor((bounds.width - w) / 2);
  const offsetY = Math.floor((bounds.height - h) / 2);
  return {
    x: bounds.x + offsetX,
    y: bounds.y + offsetY,
    width: w,
    height: h
  };
}

/**
 * Electron'un gerçek Chromium motor ana sürümünü döndürür (TLS/HTTP2/JS izi ile UA uyumsuzluğunu önler).
 * Electron dışı Node testlerinde güvenli olarak '131' döner.
 */
const TOR_BROWSER_ESR_MAJOR = '128';

function getZaslonAppVersion() {
  try {
    const pkg = require('../../package.json');
    if (pkg && pkg.version) return String(pkg.version);
  } catch {}
  return '1.0.0';
}

function getUniformChromeMajor() {
  const raw = (typeof process !== 'undefined' && process.versions && process.versions.chrome) ? String(process.versions.chrome) : '';
  const m = raw.match(/^(\d+)/);
  return m ? m[1] : '131';
}

function normalizeIdentityMode(mode) {
  const m = String(mode || '').trim().toLowerCase();
  if (m === 'tor' || m === 'zaslon' || m === 'chrome') return m;
  return 'tor';
}

/**
 * Seçili tarayıcı kimliği ('tor' | 'zaslon' | 'chrome') için HTTP + JS uyumlu profil döndürür.
 */
function getIdentityProfile(mode = 'tor', chromeMajorArg = null, zaslonVersionArg = null) {
  const normMode = normalizeIdentityMode(mode);
  const chromeMajor = String(chromeMajorArg || getUniformChromeMajor()).replace(/[^\d]/g, '') || '131';
  const zaslonVersion = String(zaslonVersionArg || getZaslonAppVersion()).replace(/[^0-9A-Za-z._-]/g, '') || '1.0.0';

  if (normMode === 'tor') {
    const ua = `Mozilla/5.0 (Windows NT 10.0; rv:${TOR_BROWSER_ESR_MAJOR}.0) Gecko/20100101 Firefox/${TOR_BROWSER_ESR_MAJOR}.0`;
    return {
      mode: 'tor',
      label: 'Tor Browser',
      ua,
      appVersion: '5.0 (Windows)',
      vendor: '',
      platform: 'Win32',
      oscpu: 'Windows NT 10.0; Win64; x64',
      productSub: '20100101',
      buildID: '20181001000000',
      hideUserAgentData: true,
      hideWindowChrome: true,
      chromeMajor,
      zaslonVersion
    };
  }

  if (normMode === 'zaslon') {
    const appVer = `5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeMajor}.0.0.0 Safari/537.36 Zaslon/${zaslonVersion}`;
    return {
      mode: 'zaslon',
      label: 'Zaslon Browser',
      ua: `Mozilla/${appVer}`,
      appVersion: appVer,
      vendor: 'Google Inc.',
      platform: 'Win32',
      oscpu: undefined,
      productSub: '20030107',
      buildID: undefined,
      hideUserAgentData: false,
      hideWindowChrome: false,
      chromeMajor,
      zaslonVersion
    };
  }

  const chromeAppVer = `5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeMajor}.0.0.0 Safari/537.36`;
  return {
    mode: 'chrome',
    label: 'Chromium',
    ua: `Mozilla/${chromeAppVer}`,
    appVersion: chromeAppVer,
    vendor: 'Google Inc.',
    platform: 'Win32',
    oscpu: undefined,
    productSub: '20030107',
    buildID: undefined,
    hideUserAgentData: false,
    hideWindowChrome: false,
    chromeMajor,
    zaslonVersion
  };
}

/**
 * Tüm ağ katmanları ve servis istekleri için tek tip, motorla senkronize User-Agent üretir.
 * Argümansız çağrıldığında mevcut Chromium UA uyumluluğunu korur.
 */
function getUniformBrowserUserAgent(mode = 'chrome', chromeMajorArg = null, zaslonVersionArg = null) {
  return getIdentityProfile(mode, chromeMajorArg, zaslonVersionArg).ua;
}

module.exports = {
  applyChromiumHardeningFlags,
  isTelemetryHost,
  hardenWebContents,
  computeLetterboxBounds,
  getUniformChromeMajor,
  getUniformBrowserUserAgent,
  getZaslonAppVersion,
  normalizeIdentityMode,
  getIdentityProfile,
  TOR_BROWSER_ESR_MAJOR,
  TELEMETRY_HOSTS
};
