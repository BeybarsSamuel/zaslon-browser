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
 * Chromium'un arka planda dış sunucularla konuşmasını donanım/motor seviyesinde engeller.
 */
function applyChromiumHardeningFlags(app) {
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
    ['host-resolver-rules', 'MAP dns.quad9.net 9.9.9.9, MAP dns.mullvad.net 194.242.2.2, MAP dns.adguard-dns.com 94.140.14.14, MAP cloudflare-dns.com 1.1.1.1'],
    ['webrtc-ip-handling-policy', 'disable_non_proxied_udp'],
    ['enforce-webrtc-ip-permission-check'],
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
        'GenericSensorExtraClasses'
      ].join(',')
    ]
  ];

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
function getUniformChromeMajor() {
  const raw = (typeof process !== 'undefined' && process.versions && process.versions.chrome) ? String(process.versions.chrome) : '';
  const m = raw.match(/^(\d+)/);
  return m ? m[1] : '131';
}

/**
 * Tüm ağ katmanları ve servis istekleri için tek tip, motorla senkronize User-Agent üretir.
 */
function getUniformBrowserUserAgent() {
  return `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${getUniformChromeMajor()}.0.0.0 Safari/537.36`;
}

module.exports = {
  applyChromiumHardeningFlags,
  isTelemetryHost,
  hardenWebContents,
  computeLetterboxBounds,
  getUniformChromeMajor,
  getUniformBrowserUserAgent,
  TELEMETRY_HOSTS
};
