/**
 * Zaslon Browser — Faz 1: Sayfa İçi Gizlilik Kalkanı (page-preload.js)
 * Her WebContentsView içine yüklenir.
 * 1) Parmak İzi Kalkanı: Canvas, WebGL, AudioContext, Font, Battery, CPU/RAM ve WebRTC koruması
 * 2) Çerez & Bildirim Pop-up Engelleyici: GDPR/Çerez kutularını sessizce reddeder ve gizler
 * 3) Zorunlu PiP hazırlığı: disablePictureInPicture engelini kaldırır
 */

const { webFrame, ipcRenderer } = require('electron');

// Başlangıç argümanlarından yapılandırmayı oku
const args = process.argv || [];
const getArg = (prefix, def) => {
  const found = args.find(a => a.startsWith(prefix));
  return found ? found.slice(prefix.length) : def;
};

const sessionSalt = getArg('--zaslon-salt=', 'zaslon-default-salt');
let fpEnabled = getArg('--zaslon-fp=', '1') !== '0';
let adblockEnabled = getArg('--zaslon-adblock=', '1') !== '0';
let popupsEnabled = getArg('--zaslon-popups=', '1') !== '0';
let sponsorBlockEnabled = getArg('--zaslon-sb=', '1') !== '0';
let videoHoverHudEnabled = getArg('--zaslon-vhud=', '1') !== '0';
let securityLevel = getArg('--zaslon-sec=', 'standard');
const chromeMajor = getArg('--zaslon-chrome-major=', '131');
let isTorTab = getArg('--zaslon-tor=', '0') === '1';
let letterboxEnabled = getArg('--zaslon-letterbox=', '0') === '1';
let currentLang = getArg('--zaslon-lang=', 'tr');

// Faz 6: Zaslon RGX (Gerçek Zamanlı GPU Video & Görsel Keskinleştirme / İyileştirme)
let rgxEnabled = getArg('--zaslon-rgx=', '0') === '1';
let rgxPreset = getArg('--zaslon-rgx-preset=', 'std');
let rgxVideos = getArg('--zaslon-rgx-vid=', '1') !== '0';
let rgxImages = getArg('--zaslon-rgx-img=', '0') === '1';
let rgxHudEnabled = getArg('--zaslon-rgx-hud=', '1') !== '0';
let rgxSplitPreview = false;
let rgxSplitRatio = 50; // %10 - %90 arası bölünmüş ekran oranı
let rgxSharpness = Number(getArg('--zaslon-rgx-sharp=', '55')) || 55;
let rgxSaturation = Number(getArg('--zaslon-rgx-sat=', '112')) || 112;
let rgxContrast = Number(getArg('--zaslon-rgx-con=', '106')) || 106;
let rgxBrightness = Number(getArg('--zaslon-rgx-bri=', '100')) || 100;
let rgxDisabledHosts = [];

const PAGE_I18N = {
  tr: {
    sbReady: 'SponsorBlock hazır ({n} sponsorlu bölüm işaretlendi)',
    sbSkipped: 'SponsorBlock: {label} atlandı (+{sec} sn)',
    domNoText: 'Sayfada çevrilecek metin bulunamadı',
    domTranslating: '🌐 Sayfa yapısı korunarak çevriliyor…',
    domNoResp: 'Çeviri yanıtı alınamadı',
    domTranslated: '✅ {count} metin bloğu çevrildi ({provider})',
    domProviderDefault: 'Zaslon Çeviri',
    domRestored: '↩️ Sayfa orijinal diline döndürüldü',
    rgxCompare: '◫ Karşılaştır',
    rgxOriginal: 'ORİJİNAL',
    rgxActiveBadge: '✨ RGX AKTİF',
    rgxToastOn: '✨ RGX Aktif ({preset} · Keskinlik %{sharp})',
    rgxToastOff: '✨ RGX Modu Kapatıldı',
    rgxSplitOn: '◫ RGX Öncesi / Sonrası Karşılaştırma Açık (Çizgiyi sürükleyin)',
    rgxSplitOff: '◫ Tam Video RGX Görünümüne Geçildi',
    noVideo: 'Oynatılabilir video bulunamadı'
  },
  en: {
    sbReady: 'SponsorBlock ready ({n} sponsored segments marked)',
    sbSkipped: 'SponsorBlock: {label} skipped (+{sec}s)',
    domNoText: 'No translatable text found on page',
    domTranslating: '🌐 Translating while preserving page layout…',
    domNoResp: 'No translation response received',
    domTranslated: '✅ Translated {count} text blocks ({provider})',
    domProviderDefault: 'Zaslon Translate',
    domRestored: '↩️ Page restored to original language',
    rgxCompare: '◫ Split View',
    rgxOriginal: 'ORIGINAL',
    rgxActiveBadge: '✨ RGX ACTIVE',
    rgxToastOn: '✨ RGX Active ({preset} · Sharpness {sharp}%)',
    rgxToastOff: '✨ RGX Mode Disabled',
    rgxSplitOn: '◫ RGX Split Comparison On (Drag divider)',
    rgxSplitOff: '◫ Full Video RGX View Restored',
    noVideo: 'No playable video found'
  },
  ru: {
    sbReady: 'SponsorBlock готов (отмечено сегментов: {n})',
    sbSkipped: 'SponsorBlock: «{label}» пропущено (+{sec} с)',
    domNoText: 'На странице не найден текст для перевода',
    domTranslating: '🌐 Перевод с сохранением структуры страницы…',
    domNoResp: 'Ответ от сервиса перевода не получен',
    domTranslated: '✅ Переведено блоков текста: {count} ({provider})',
    domProviderDefault: 'Zaslon Перевод',
    domRestored: '↩️ Восстановлен исходный язык страницы',
    rgxCompare: '◫ Сравнить',
    rgxOriginal: 'ОРИГИНАЛ',
    rgxActiveBadge: '✨ RGX АКТИВЕН',
    rgxToastOn: '✨ RGX Активен ({preset} · Резкость {sharp}%)',
    rgxToastOff: '✨ Режим RGX выключен',
    rgxSplitOn: '◫ Сравнение До / После включено',
    rgxSplitOff: '◫ Полный режим RGX',
    noVideo: 'Воспроизводимое видео не найдено'
  },
  de: {
    sbReady: 'SponsorBlock bereit ({n} gesponserte Abschnitte markiert)',
    sbSkipped: 'SponsorBlock: {label} übersprungen (+{sec} s)',
    domNoText: 'Kein übersetzbarer Text auf der Seite gefunden',
    domTranslating: '🌐 Seite wird unter Beibehaltung des Layouts übersetzt…',
    domNoResp: 'Keine Übersetzungsantwort erhalten',
    domTranslated: '✅ {count} Textblöcke übersetzt ({provider})',
    domProviderDefault: 'Zaslon Übersetzer',
    domRestored: '↩️ Originalsprache der Seite wiederhergestellt',
    rgxCompare: '◫ Vergleich',
    rgxOriginal: 'ORIGINAL',
    rgxActiveBadge: '✨ RGX AKTIV',
    rgxToastOn: '✨ RGX Aktiv ({preset} · Schärfe {sharp}%)',
    rgxToastOff: '✨ RGX-Modus deaktiviert',
    rgxSplitOn: '◫ RGX Vorher/Nachher-Vergleich aktiv',
    rgxSplitOff: '◫ Vollbild-RGX wiederhergestellt',
    noVideo: 'Kein abspielbares Video gefunden'
  }
};

function pt(key, params = {}) {
  const dict = PAGE_I18N[currentLang] || PAGE_I18N.tr;
  const tpl = dict[key] || PAGE_I18N.tr[key] || key;
  return String(tpl).replace(/\{(\w+)\}/g, (_m, k) => (params[k] !== undefined && params[k] !== null ? String(params[k]) : ''));
}

/**
 * Sayfanın kendi Main World (window) bağlamına enjekte edilecek Anti-Fingerprinting kodu.
 * Her site (domain) için deterministik gürültü üretir:
 * - Aynı sitedeki çoklu okumalar tutarlıdır (anti-spoof dedektörlerine yakalanmaz).
 * - Farklı siteler tamamen farklı donanım/canvas imzası görür (siteler arası takip imkansızlaşır).
 */
function buildMainWorldShieldScript(salt, secLevel, isTor = false, letterbox = false, chromeMajorArg = '131') {
  const strictMode = Boolean(isTor || secLevel === 'safest');
  const screenMaskMode = Boolean(strictMode || letterbox);
  const safeChromeMajor = String(chromeMajorArg || '131').replace(/[^\d]/g, '') || '131';
  return `(function() {
    try {
      const strictMode = ${JSON.stringify(strictMode)};
      const screenMaskMode = ${JSON.stringify(screenMaskMode)};
      const secLevel = ${JSON.stringify(secLevel)};
      const chromeMajor = ${JSON.stringify(safeChromeMajor)};
      const uniformUa = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/' + chromeMajor + '.0.0.0 Safari/537.36';
      const uniformAppVer = '5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/' + chromeMajor + '.0.0.0 Safari/537.36';
      const host = (typeof location !== 'undefined' && location && location.hostname) ? location.hostname : 'local';
      const seedStr = host + '::' + ${JSON.stringify(salt)};
      let seed = 2166136261 >>> 0;
      for (let i = 0; i < seedStr.length; i++) {
        seed ^= seedStr.charCodeAt(i);
        seed = Math.imul(seed, 16777619) >>> 0;
      }
      const detNoise = (idx) => {
        let x = (seed ^ Math.imul(idx + 1, 374761393)) >>> 0;
        x = Math.imul(x ^ (x >>> 13), 1274126177) >>> 0;
        return ((x ^ (x >>> 16)) & 0xff);
      };

      const nativeToStringMap = new WeakMap();
      const registerNative = (fn, name) => {
        try {
          if (typeof fn === 'function') {
            const label = typeof name === 'string' ? name : (fn.name || '');
            try {
              Object.defineProperty(fn, 'name', { value: label, configurable: true });
            } catch {}
            nativeToStringMap.set(fn, 'function ' + label + '() { [native code] }');
          }
        } catch {}
        return fn;
      };
      try {
        const origToString = Function.prototype.toString;
        const maskedToString = function toString() {
          if (typeof this === 'function' && nativeToStringMap.has(this)) {
            return nativeToStringMap.get(this);
          }
          return origToString.call(this);
        };
        registerNative(maskedToString, 'toString');
        Object.defineProperty(Function.prototype, 'toString', {
          value: maskedToString,
          configurable: true,
          writable: true
        });
      } catch {}

      const applyImageDataNoise = (imgData) => {
        try {
          const d = imgData && imgData.data;
          const len = d ? d.length : 0;
          if (len >= 16) {
            const step = Math.max(16, Math.floor(len / 64) & ~3);
            for (let i = 0, k = 0; i < len; i += step, k++) {
              const delta = (detNoise(k) % 3) - 1; // -1, 0 veya +1
              d[i] = Math.max(0, Math.min(255, d[i] + delta));
            }
          }
        } catch {}
        return imgData;
      };

      const noisedAudioBuffers = new WeakSet();
      const patchedWins = new WeakSet();

      const patchWindowContext = (win) => {
        if (!win) return;
        try {
          if (patchedWins.has(win)) return;
          patchedWins.add(win);
        } catch {
          return;
        }

        const SafeObject = win.Object || Object;
        const SafePromise = win.Promise || Promise;
        const SafeDOMException = win.DOMException || DOMException;
        const SafeDate = win.Date || Date;
        const SafeIntl = win.Intl || Intl;
        const SafeBlob = win.Blob || Blob;
        const SafeURL = win.URL || URL;

        /* 1. Gezgin (Navigator), Donanım, Dil ve Batarya Kalkanı */
        if (win.navigator) {
          const navProto = SafeObject.getPrototypeOf(win.navigator);
          const defineNav = (prop, getter) => {
            try {
              registerNative(getter, 'get ' + prop);
              SafeObject.defineProperty(navProto, prop, {
                get: getter,
                configurable: true,
                enumerable: true
              });
            } catch {}
          };

          defineNav('doNotTrack', () => '1');
          defineNav('globalPrivacyControl', () => true);
          defineNav('webdriver', () => false);
          defineNav('hardwareConcurrency', () => (strictMode ? 4 : 8));
          defineNav('deviceMemory', () => (strictMode ? 4 : 8));
          defineNav('userAgent', () => uniformUa);
          defineNav('appVersion', () => uniformAppVer);
          defineNav('vendor', () => 'Google Inc.');

          try {
            const uaBrands = SafeObject.freeze([
              SafeObject.freeze({ brand: 'Chromium', version: chromeMajor }),
              SafeObject.freeze({ brand: 'Not-A.Brand', version: '24' }),
              SafeObject.freeze({ brand: 'Google Chrome', version: chromeMajor })
            ]);
            const fakeUaData = {
              brands: uaBrands,
              mobile: false,
              platform: 'Windows',
              getHighEntropyValues: registerNative((hints) => {
                const res = { brands: uaBrands, mobile: false, platform: 'Windows' };
                const list = Array.isArray(hints) ? hints : [];
                for (let i = 0; i < list.length; i++) {
                  const h = list[i];
                  if (h === 'architecture') res.architecture = 'x86';
                  else if (h === 'bitness') res.bitness = '64';
                  else if (h === 'model') res.model = '';
                  else if (h === 'platformVersion') res.platformVersion = '15.0.0';
                  else if (h === 'uaFullVersion') res.uaFullVersion = chromeMajor + '.0.0.0';
                  else if (h === 'fullVersionList') {
                    res.fullVersionList = uaBrands.map((b) => ({
                      brand: b.brand,
                      version: b.brand === 'Not-A.Brand' ? '24.0.0.0' : chromeMajor + '.0.0.0'
                    }));
                  } else if (h === 'wow64') {
                    res.wow64 = false;
                  }
                }
                return SafePromise.resolve(res);
              }, 'getHighEntropyValues'),
              toJSON: registerNative(() => ({ brands: uaBrands, mobile: false, platform: 'Windows' }), 'toJSON')
            };
            defineNav('userAgentData', () => fakeUaData);
          } catch {}

          if (typeof win.navigator.getGamepads === 'function') {
            try {
              SafeObject.defineProperty(navProto, 'getGamepads', {
                value: registerNative(() => [], 'getGamepads'),
                configurable: true
              });
            } catch {}
          }

          if (strictMode) {
            defineNav('language', () => 'en-US');
            defineNav('languages', () => SafeObject.freeze(['en-US', 'en']));
            defineNav('platform', () => 'Win32');
            for (const hwProp of ['connection', 'bluetooth', 'usb', 'hid', 'serial', 'gpu']) {
              if (hwProp in win.navigator) {
                defineNav(hwProp, () => undefined);
              }
            }
            if (win.navigator.mediaDevices) {
              try {
                const rawMd = win.navigator.mediaDevices;
                const blockedErr = () => SafePromise.reject(new SafeDOMException('Permission denied', 'NotAllowedError'));
                const safeEnum = registerNative(() => SafePromise.resolve([]), 'enumerateDevices');
                const safeGum = registerNative(blockedErr, 'getUserMedia');
                const safeGdm = registerNative(blockedErr, 'getDisplayMedia');
                if (win.MediaDevices && win.MediaDevices.prototype) {
                  win.MediaDevices.prototype.enumerateDevices = safeEnum;
                  if (typeof win.MediaDevices.prototype.getUserMedia === 'function') {
                    win.MediaDevices.prototype.getUserMedia = safeGum;
                  }
                  if (typeof win.MediaDevices.prototype.getDisplayMedia === 'function') {
                    win.MediaDevices.prototype.getDisplayMedia = safeGdm;
                  }
                }
                rawMd.enumerateDevices = safeEnum;
                if (typeof rawMd.getUserMedia === 'function') rawMd.getUserMedia = safeGum;
                if (typeof rawMd.getDisplayMedia === 'function') rawMd.getDisplayMedia = safeGdm;
                defineNav('mediaDevices', () => rawMd);
              } catch {}
            }
            if (win.navigator.keyboard && typeof win.navigator.keyboard.getLayoutMap === 'function') {
              try {
                const rawKb = win.navigator.keyboard;
                const safeMap = registerNative(() => SafePromise.resolve(new Map()), 'getLayoutMap');
                if (win.Keyboard && win.Keyboard.prototype) {
                  win.Keyboard.prototype.getLayoutMap = safeMap;
                }
                rawKb.getLayoutMap = safeMap;
                defineNav('keyboard', () => rawKb);
              } catch {}
            }
          }

          if (win.speechSynthesis && typeof win.speechSynthesis.getVoices === 'function') {
            try {
              win.speechSynthesis.getVoices = registerNative(() => [], 'getVoices');
            } catch {}
          }

          if (typeof win.navigator.getBattery === 'function') {
            const fakeBattery = {
              charging: true,
              chargingTime: 0,
              dischargingTime: Infinity,
              level: 1,
              onchargingchange: null,
              onchargingtimechange: null,
              ondischargingtimechange: null,
              onlevelchange: null,
              addEventListener: registerNative(() => {}, 'addEventListener'),
              removeEventListener: registerNative(() => {}, 'removeEventListener'),
              dispatchEvent: registerNative(() => true, 'dispatchEvent')
            };
            try {
              SafeObject.defineProperty(navProto, 'getBattery', {
                value: registerNative(() => SafePromise.resolve(fakeBattery), 'getBattery'),
                configurable: true
              });
            } catch {}
          }

          if (strictMode && win.navigator.serviceWorker) {
            try {
              const blockedSw = {
                controller: null,
                ready: new SafePromise(() => {}),
                register: registerNative(
                  () => SafePromise.reject(new SafeDOMException('ServiceWorker disabled', 'SecurityError')),
                  'register'
                ),
                getRegistration: registerNative(() => SafePromise.resolve(undefined), 'getRegistration'),
                getRegistrations: registerNative(() => SafePromise.resolve([]), 'getRegistrations'),
                startMessages: registerNative(() => {}, 'startMessages'),
                addEventListener: registerNative(() => {}, 'addEventListener'),
                removeEventListener: registerNative(() => {}, 'removeEventListener'),
                dispatchEvent: registerNative(() => false, 'dispatchEvent')
              };
              const swGetter = registerNative(() => blockedSw, 'get serviceWorker');
              SafeObject.defineProperty(navProto, 'serviceWorker', {
                get: swGetter,
                configurable: true
              });
            } catch {}
          }
        }

        /* 2. Bildirim İsteklerini Sessizce Reddet */
        if (win.Notification) {
          try {
            SafeObject.defineProperty(win.Notification, 'permission', {
              get: registerNative(() => 'denied', 'get permission'),
              configurable: true
            });
            win.Notification.requestPermission = registerNative(() => SafePromise.resolve('denied'), 'requestPermission');
          } catch {}
        }

        /* 2b. Zamanlama Çözünürlüğü Kısıtlama (performance.now) */
        if (win.Performance && win.Performance.prototype && win.Performance.prototype.now) {
          try {
            const origPerfNow = win.Performance.prototype.now;
            win.Performance.prototype.now = registerNative(function now() {
              const raw = origPerfNow.call(this);
              return strictMode ? Math.floor(raw / 2) * 2 : Math.floor(raw * 10) / 10;
            }, 'now');
          } catch {}
        }

        /* 2c. Tor / Strict Modda UTC+0 Saat Dilimi, Ekran/DPR Sabitleme, Locale ve Worker İzolasyonu */
        if (strictMode) {
          try {
            const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
            const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
            const pad2 = (n) => (n < 10 ? '0' + n : String(n));
            const utcDateStr = (d) =>
              DAYS[d.getUTCDay()] + ' ' + MONTHS[d.getUTCMonth()] + ' ' + pad2(d.getUTCDate()) + ' ' + d.getUTCFullYear();
            const utcTimeStr = (d) =>
              pad2(d.getUTCHours()) + ':' + pad2(d.getUTCMinutes()) + ':' + pad2(d.getUTCSeconds()) + ' GMT+0000 (Coordinated Universal Time)';

            SafeDate.prototype.getTimezoneOffset = registerNative(() => 0, 'getTimezoneOffset');
            SafeDate.prototype.toDateString = registerNative(function toDateString() {
              if (isNaN(this.getTime())) return 'Invalid Date';
              return utcDateStr(this);
            }, 'toDateString');
            SafeDate.prototype.toTimeString = registerNative(function toTimeString() {
              if (isNaN(this.getTime())) return 'Invalid Date';
              return utcTimeStr(this);
            }, 'toTimeString');
            SafeDate.prototype.toString = registerNative(function toString() {
              if (isNaN(this.getTime())) return 'Invalid Date';
              return utcDateStr(this) + ' ' + utcTimeStr(this);
            }, 'toString');
            SafeDate.prototype.toLocaleString = registerNative(function toLocaleString(locales, options) {
              if (isNaN(this.getTime())) return 'Invalid Date';
              const loc = (locales === undefined || locales === null || (Array.isArray(locales) && !locales.length)) ? 'en-US' : locales;
              const opt = options ? { ...options } : { year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', minute: 'numeric', second: 'numeric' };
              if (!opt.timeZone) opt.timeZone = 'UTC';
              return new SafeIntl.DateTimeFormat(loc, opt).format(this);
            }, 'toLocaleString');
            SafeDate.prototype.toLocaleDateString = registerNative(function toLocaleDateString(locales, options) {
              if (isNaN(this.getTime())) return 'Invalid Date';
              const loc = (locales === undefined || locales === null || (Array.isArray(locales) && !locales.length)) ? 'en-US' : locales;
              const opt = options ? { ...options } : { year: 'numeric', month: 'numeric', day: 'numeric' };
              if (!opt.timeZone) opt.timeZone = 'UTC';
              return new SafeIntl.DateTimeFormat(loc, opt).format(this);
            }, 'toLocaleDateString');
            SafeDate.prototype.toLocaleTimeString = registerNative(function toLocaleTimeString(locales, options) {
              if (isNaN(this.getTime())) return 'Invalid Date';
              const loc = (locales === undefined || locales === null || (Array.isArray(locales) && !locales.length)) ? 'en-US' : locales;
              const opt = options ? { ...options } : { hour: 'numeric', minute: 'numeric', second: 'numeric' };
              if (!opt.timeZone) opt.timeZone = 'UTC';
              return new SafeIntl.DateTimeFormat(loc, opt).format(this);
            }, 'toLocaleTimeString');
          } catch {}

          try {
            const explicitIntlInstances = new WeakSet();
            const wrapIntlCtor = (ctorName, forceUtc) => {
              const OrigCtor = SafeIntl && SafeIntl[ctorName];
              if (typeof OrigCtor !== 'function') return;
              const origResolved = OrigCtor.prototype && OrigCtor.prototype.resolvedOptions;
              if (typeof origResolved === 'function') {
                OrigCtor.prototype.resolvedOptions = registerNative(function resolvedOptions(...a) {
                  const opts = origResolved.apply(this, a);
                  try {
                    if (forceUtc) opts.timeZone = 'UTC';
                    if (!explicitIntlInstances.has(this)) {
                      opts.locale = 'en-US';
                    }
                  } catch {}
                  return opts;
                }, 'resolvedOptions');
              }
              const WrappedCtor = registerNative(function (locales, options) {
                const hasExplicit = !(locales === undefined || locales === null || (Array.isArray(locales) && locales.length === 0));
                const loc = hasExplicit ? locales : 'en-US';
                const opt = options ? { ...options } : {};
                if (forceUtc && !opt.timeZone) opt.timeZone = 'UTC';
                const inst = new OrigCtor(loc, opt);
                if (hasExplicit) explicitIntlInstances.add(inst);
                return inst;
              }, ctorName);
              WrappedCtor.prototype = OrigCtor.prototype;
              if (typeof OrigCtor.supportedLocalesOf === 'function') {
                WrappedCtor.supportedLocalesOf = registerNative(
                  OrigCtor.supportedLocalesOf.bind(OrigCtor),
                  'supportedLocalesOf'
                );
              }
              SafeIntl[ctorName] = WrappedCtor;
            };

            wrapIntlCtor('DateTimeFormat', true);
            wrapIntlCtor('NumberFormat', false);
            wrapIntlCtor('RelativeTimeFormat', false);
            wrapIntlCtor('ListFormat', false);
            wrapIntlCtor('PluralRules', false);
            wrapIntlCtor('Collator', false);
            wrapIntlCtor('DisplayNames', false);
          } catch {}

          if (typeof win.matchMedia === 'function') {
            try {
              const origMatchMedia = win.matchMedia.bind(win);
              win.matchMedia = registerNative(function matchMedia(query) {
                const mql = origMatchMedia(query);
                const q = String(query || '').toLowerCase();
                let override = null;
                if (/prefers-color-scheme\\s*:\\s*dark/.test(q)) override = false;
                else if (/prefers-color-scheme\\s*:\\s*light/.test(q)) override = true;
                else if (/prefers-reduced-motion\\s*:\\s*reduce/.test(q)) override = false;
                if (override !== null && mql && typeof mql === 'object') {
                  try {
                    SafeObject.defineProperty(mql, 'matches', {
                      get: registerNative(() => override, 'get matches'),
                      configurable: true
                    });
                  } catch {}
                }
                return mql;
              }, 'matchMedia');
            } catch {}
          }

          try {
            SafeObject.defineProperty(win, 'SharedWorker', { value: undefined, configurable: true });
          } catch {}
        }

        if (screenMaskMode) {
          try {
            const scrTargets = [];
            if (win.Screen && win.Screen.prototype) scrTargets.push(win.Screen.prototype);
            if (win.screen) scrTargets.push(win.screen);
            const stdScreen = {
              width: 1920,
              height: 1080,
              availWidth: 1920,
              availHeight: 1040,
              availLeft: 0,
              availTop: 0,
              colorDepth: 24,
              pixelDepth: 24
            };
            for (const target of scrTargets) {
              for (const [k, v] of Object.entries(stdScreen)) {
                try {
                  SafeObject.defineProperty(target, k, {
                    get: registerNative(() => v, 'get ' + k),
                    configurable: true
                  });
                } catch {}
              }
            }
            const zeroGeom = ['screenX', 'screenY', 'screenLeft', 'screenTop'];
            for (const gp of zeroGeom) {
              try {
                SafeObject.defineProperty(win, gp, {
                  get: registerNative(() => 0, 'get ' + gp),
                  configurable: true
                });
              } catch {}
            }
            if (typeof win.innerWidth === 'number' && typeof win.innerHeight === 'number') {
              try {
                SafeObject.defineProperty(win, 'outerWidth', {
                  get: registerNative(() => win.innerWidth, 'get outerWidth'),
                  configurable: true
                });
                SafeObject.defineProperty(win, 'outerHeight', {
                  get: registerNative(() => win.innerHeight, 'get outerHeight'),
                  configurable: true
                });
              } catch {}
            }
            SafeObject.defineProperty(win, 'devicePixelRatio', {
              get: registerNative(() => 1, 'get devicePixelRatio'),
              configurable: true
            });
          } catch {}
        }

        if (win.Worker) {
          try {
            const OrigWorker = win.Worker;
            const workerPrelude = \`(function(){try{
              const s=\${strictMode ? 'true' : 'false'};
              const ua=\${JSON.stringify(uniformUa)};
              const av=\${JSON.stringify(uniformAppVer)};
              const cm=\${JSON.stringify(chromeMajor)};
              const np=Object.getPrototypeOf(self.navigator);
              try{Object.defineProperty(np,'hardwareConcurrency',{get:()=>s?4:8,configurable:true})}catch{}
              try{Object.defineProperty(np,'deviceMemory',{get:()=>s?4:8,configurable:true})}catch{}
              try{Object.defineProperty(np,'userAgent',{get:()=>ua,configurable:true})}catch{}
              try{Object.defineProperty(np,'appVersion',{get:()=>av,configurable:true})}catch{}
              try{Object.defineProperty(np,'vendor',{get:()=>'Google Inc.',configurable:true})}catch{}
              try{
                const wb=Object.freeze([Object.freeze({brand:'Chromium',version:cm}),Object.freeze({brand:'Not-A.Brand',version:'24'}),Object.freeze({brand:'Google Chrome',version:cm})]);
                Object.defineProperty(np,'userAgentData',{get:()=>({brands:wb,mobile:false,platform:'Windows',getHighEntropyValues:()=>Promise.resolve({brands:wb,mobile:false,platform:'Windows',architecture:'x86',bitness:'64',platformVersion:'15.0.0'}),toJSON:()=>({brands:wb,mobile:false,platform:'Windows'})}),configurable:true});
              }catch{}
              if(s){
                try{Object.defineProperty(np,'language',{get:()=>'en-US',configurable:true})}catch{}
                try{Object.defineProperty(np,'languages',{get:()=>Object.freeze(['en-US','en']),configurable:true})}catch{}
                try{Object.defineProperty(np,'platform',{get:()=>'Win32',configurable:true})}catch{}
                try{Object.defineProperty(np,'connection',{get:()=>undefined,configurable:true})}catch{}
                try{Date.prototype.getTimezoneOffset=()=>0}catch{}
                try{
                  const OD=Intl.DateTimeFormat;
                  Intl.DateTimeFormat=function(l,o){const opt=o?{...o}:{};if(!opt.timeZone)opt.timeZone='UTC';return new OD(l||'en-US',opt);};
                  Intl.DateTimeFormat.prototype=OD.prototype;
                }catch{}
              }
              if(self.Performance&&Performance.prototype&&Performance.prototype.now){
                const on=Performance.prototype.now;
                Performance.prototype.now=function(){const v=on.call(this);return s?Math.floor(v/2)*2:Math.floor(v*10)/10;};
              }
            }catch{}})();\n\`;

            const WrappedWorker = registerNative(function Worker(scriptURL, opts) {
              if ((!opts || opts.type !== 'module') && typeof scriptURL === 'string' && !scriptURL.startsWith('data:')) {
                try {
                  const baseHref = (typeof location !== 'undefined' && location && location.href) ? location.href : undefined;
                  const absUrl = new URL(scriptURL, baseHref).href;
                  const shimBlob = new SafeBlob([workerPrelude + 'importScripts(' + JSON.stringify(absUrl) + ');'], {
                    type: 'application/javascript'
                  });
                  const blobUrl = SafeURL.createObjectURL(shimBlob);
                  return new OrigWorker(blobUrl, opts);
                } catch {}
              }
              return new OrigWorker(scriptURL, opts);
            }, 'Worker');
            WrappedWorker.prototype = OrigWorker.prototype;
            win.Worker = WrappedWorker;
          } catch {}
        }

        /* 3. Canvas Parmak İzi Kalkanı (Tam Alan Deterministik Mikro-Gürültü + OffscreenCanvas) */
        if (win.CanvasRenderingContext2D && win.CanvasRenderingContext2D.prototype) {
          const origGetImageData = win.CanvasRenderingContext2D.prototype.getImageData;
          if (origGetImageData) {
            win.CanvasRenderingContext2D.prototype.getImageData = registerNative(function getImageData(sx, sy, sw, sh) {
              const res = origGetImageData.call(this, sx, sy, sw, sh);
              return applyImageDataNoise(res);
            }, 'getImageData');
          }

          const cloneWithNoise = (canvas) => {
            try {
              const w = canvas.width, h = canvas.height;
              if (!w || !h || w * h > 4096 * 4096 || !win.document) return canvas;
              const c2 = win.document.createElement('canvas');
              c2.width = w;
              c2.height = h;
              const ctx2 = c2.getContext('2d');
              ctx2.drawImage(canvas, 0, 0);
              const img = origGetImageData.call(ctx2, 0, 0, w, h);
              applyImageDataNoise(img);
              ctx2.putImageData(img, 0, 0);
              return c2;
            } catch {
              return canvas;
            }
          };

          if (win.HTMLCanvasElement && win.HTMLCanvasElement.prototype) {
            if (win.HTMLCanvasElement.prototype.toDataURL) {
              const origToDataURL = win.HTMLCanvasElement.prototype.toDataURL;
              win.HTMLCanvasElement.prototype.toDataURL = registerNative(function toDataURL(...a) {
                return origToDataURL.apply(cloneWithNoise(this), a);
              }, 'toDataURL');
            }
            if (win.HTMLCanvasElement.prototype.toBlob) {
              const origToBlob = win.HTMLCanvasElement.prototype.toBlob;
              win.HTMLCanvasElement.prototype.toBlob = registerNative(function toBlob(...a) {
                return origToBlob.apply(cloneWithNoise(this), a);
              }, 'toBlob');
            }
          }

          /* 4. Font Ölçümü (measureText) Parmak İzi Kalkanı */
          if (win.CanvasRenderingContext2D.prototype.measureText) {
            const origMeasureText = win.CanvasRenderingContext2D.prototype.measureText;
            const jitterDelta = ((seed & 0xff) - 128) * 0.00015;
            win.CanvasRenderingContext2D.prototype.measureText = registerNative(function measureText(text) {
              const metrics = origMeasureText.call(this, text);
              try {
                const origWidth = metrics.width;
                if (!text || String(text).length === 0 || origWidth === 0) {
                  return metrics;
                }
                SafeObject.defineProperty(metrics, 'width', {
                  get: registerNative(() => origWidth + jitterDelta, 'get width'),
                  configurable: true
                });
              } catch {}
              return metrics;
            }, 'measureText');
          }
        }

        if (win.OffscreenCanvasRenderingContext2D && win.OffscreenCanvasRenderingContext2D.prototype) {
          const origOffGetImg = win.OffscreenCanvasRenderingContext2D.prototype.getImageData;
          if (origOffGetImg) {
            win.OffscreenCanvasRenderingContext2D.prototype.getImageData = registerNative(function getImageData(sx, sy, sw, sh) {
              const res = origOffGetImg.call(this, sx, sy, sw, sh);
              return applyImageDataNoise(res);
            }, 'getImageData');
          }
          if (win.OffscreenCanvasRenderingContext2D.prototype.measureText) {
            const origOffMeasure = win.OffscreenCanvasRenderingContext2D.prototype.measureText;
            const jitterDelta = ((seed & 0xff) - 128) * 0.00015;
            win.OffscreenCanvasRenderingContext2D.prototype.measureText = registerNative(function measureText(text) {
              const metrics = origOffMeasure.call(this, text);
              try {
                const origWidth = metrics.width;
                if (!text || String(text).length === 0 || origWidth === 0) return metrics;
                SafeObject.defineProperty(metrics, 'width', {
                  get: registerNative(() => origWidth + jitterDelta, 'get width'),
                  configurable: true
                });
              } catch {}
              return metrics;
            }, 'measureText');
          }
        }

        if (win.OffscreenCanvas && win.OffscreenCanvas.prototype && win.OffscreenCanvas.prototype.convertToBlob) {
          const origConvertToBlob = win.OffscreenCanvas.prototype.convertToBlob;
          win.OffscreenCanvas.prototype.convertToBlob = registerNative(function convertToBlob(...a) {
            try {
              const w = this.width, h = this.height;
              if (w > 0 && h > 0 && w * h <= 4096 * 4096) {
                const tmp = new win.OffscreenCanvas(w, h);
                const ctx = tmp.getContext('2d');
                if (ctx) {
                  ctx.drawImage(this, 0, 0);
                  const img = ctx.getImageData(0, 0, w, h);
                  applyImageDataNoise(img);
                  ctx.putImageData(img, 0, 0);
                  return origConvertToBlob.apply(tmp, a);
                }
              }
            } catch {}
            return origConvertToBlob.apply(this, a);
          }, 'convertToBlob');
        }

        /* 5. WebGL Parmak İzi Kalkanı (Ekran Kartı Modelini Tek Tip Windows D3D11 Havuzuna Maskeleme + readPixels Gürültüsü) */
        const maskWebGL = (proto) => {
          if (!proto || !proto.getParameter) return;
          const origGetParam = proto.getParameter;
          const vendors = ['Google Inc. (Intel)', 'Google Inc. (AMD)'];
          const renderers = [
            'ANGLE (Intel, Intel(R) UHD Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)',
            'ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)',
            'ANGLE (AMD, AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)'
          ];
          const vPick = strictMode ? vendors[0] : vendors[seed % vendors.length];
          const rPick = strictMode ? renderers[0] : renderers[seed % renderers.length];

          proto.getParameter = registerNative(function getParameter(param) {
            if (param === 7936) return 'WebKit'; // GL_VENDOR
            if (param === 7937) return 'WebKit WebGL'; // GL_RENDERER
            if (param === 37445) return vPick; // UNMASKED_VENDOR_WEBGL
            if (param === 37446) return rPick; // UNMASKED_RENDERER_WEBGL
            return origGetParam.call(this, param);
          }, 'getParameter');

          if (typeof proto.readPixels === 'function') {
            const origReadPixels = proto.readPixels;
            proto.readPixels = registerNative(function readPixels(x, y, width, height, format, type, pixels, ...rest) {
              const out = origReadPixels.call(this, x, y, width, height, format, type, pixels, ...rest);
              try {
                if (pixels && typeof pixels.length === 'number' && pixels.length >= 16) {
                  const step = Math.max(16, Math.floor(pixels.length / 64) & ~3);
                  for (let i = 0, k = 0; i < pixels.length; i += step, k++) {
                    const delta = (detNoise(k + 91) % 3) - 1;
                    pixels[i] = Math.max(0, Math.min(255, pixels[i] + delta));
                  }
                }
              } catch {}
              return out;
            }, 'readPixels');
          }
        };
        if (win.WebGLRenderingContext) maskWebGL(win.WebGLRenderingContext.prototype);
        if (win.WebGL2RenderingContext) maskWebGL(win.WebGL2RenderingContext.prototype);

        /* 6. AudioContext & AnalyserNode Ses Parmak İzi Kalkanı (WeakSet ile sıfır özellik sızıntısı) */
        if (win.AudioBuffer && win.AudioBuffer.prototype && win.AudioBuffer.prototype.getChannelData) {
          const origGetChannelData = win.AudioBuffer.prototype.getChannelData;
          win.AudioBuffer.prototype.getChannelData = registerNative(function getChannelData(channel) {
            const data = origGetChannelData.call(this, channel);
            try {
              if (data && data.length > 0 && !noisedAudioBuffers.has(this)) {
                noisedAudioBuffers.add(this);
                const step = Math.max(1, Math.floor(data.length / 64));
                for (let i = 0; i < data.length; i += step) {
                  data[i] += ((detNoise(i) - 128) * 1e-7);
                }
              }
            } catch {}
            return data;
          }, 'getChannelData');
        }
        if (win.AnalyserNode && win.AnalyserNode.prototype) {
          const anProto = win.AnalyserNode.prototype;
          for (const mName of ['getFloatFrequencyData', 'getFloatTimeDomainData']) {
            if (typeof anProto[mName] === 'function') {
              const origFn = anProto[mName];
              anProto[mName] = registerNative(function (arr) {
                const res = origFn.call(this, arr);
                try {
                  if (arr && arr.length > 0) {
                    const step = Math.max(1, Math.floor(arr.length / 32));
                    for (let i = 0; i < arr.length; i += step) {
                      arr[i] += ((detNoise(i + 17) - 128) * 1e-5);
                    }
                  }
                } catch {}
                return res;
              }, mName);
            }
          }
          for (const mName of ['getByteFrequencyData', 'getByteTimeDomainData']) {
            if (typeof anProto[mName] === 'function') {
              const origFn = anProto[mName];
              anProto[mName] = registerNative(function (arr) {
                const res = origFn.call(this, arr);
                try {
                  if (arr && arr.length > 0) {
                    const step = Math.max(1, Math.floor(arr.length / 32));
                    for (let i = 0; i < arr.length; i += step) {
                      arr[i] = Math.max(0, Math.min(255, arr[i] + ((detNoise(i + 31) % 3) - 1)));
                    }
                  }
                } catch {}
                return res;
              }, mName);
            }
          }
        }

        /* 7. WebRTC IP Sızıntı Kalkanı (Tor/Paranoyak Modda Tamamen Devre Dışı, Normalde iceServers=[] Kilitli) */
        if (strictMode || secLevel === 'safest') {
          try {
            win.RTCPeerConnection = undefined;
            win.webkitRTCPeerConnection = undefined;
            win.mozRTCPeerConnection = undefined;
            win.RTCDataChannel = undefined;
          } catch {}
        } else if (win.RTCPeerConnection) {
          const OrigPeerConnection = win.RTCPeerConnection;
          if (OrigPeerConnection.prototype && OrigPeerConnection.prototype.setConfiguration) {
            const origSetConfig = OrigPeerConnection.prototype.setConfiguration;
            OrigPeerConnection.prototype.setConfiguration = registerNative(function setConfiguration(cfg) {
              const safeCfg = cfg && typeof cfg === 'object' ? { ...cfg, iceServers: [] } : { iceServers: [] };
              return origSetConfig.call(this, safeCfg);
            }, 'setConfiguration');
          }
          const WrappedPeerConnection = registerNative(function RTCPeerConnection(config, constraints) {
            if (config && typeof config === 'object') {
              config = { ...config, iceServers: [] };
            }
            return new OrigPeerConnection(config, constraints);
          }, 'RTCPeerConnection');
          WrappedPeerConnection.prototype = OrigPeerConnection.prototype;
          try {
            win.RTCPeerConnection = WrappedPeerConnection;
            win.webkitRTCPeerConnection = WrappedPeerConnection;
          } catch {}
        }

        /* 8. Same-Origin Iframe / Subframe Bağlamlarına Zırh Yayılımı (about:blank / srcdoc baypasını kapatır) */
        if (win.HTMLIFrameElement && win.HTMLIFrameElement.prototype) {
          try {
            const cwDesc = SafeObject.getOwnPropertyDescriptor(win.HTMLIFrameElement.prototype, 'contentWindow');
            if (cwDesc && typeof cwDesc.get === 'function') {
              const origCwGet = cwDesc.get;
              SafeObject.defineProperty(win.HTMLIFrameElement.prototype, 'contentWindow', {
                configurable: true,
                enumerable: cwDesc.enumerable,
                get: registerNative(function contentWindow() {
                  const childWin = origCwGet.call(this);
                  try {
                    if (childWin) patchWindowContext(childWin);
                  } catch {}
                  return childWin;
                }, 'get contentWindow')
              });
            }
            const cdDesc = SafeObject.getOwnPropertyDescriptor(win.HTMLIFrameElement.prototype, 'contentDocument');
            if (cdDesc && typeof cdDesc.get === 'function') {
              const origCdGet = cdDesc.get;
              SafeObject.defineProperty(win.HTMLIFrameElement.prototype, 'contentDocument', {
                configurable: true,
                enumerable: cdDesc.enumerable,
                get: registerNative(function contentDocument() {
                  const doc = origCdGet.call(this);
                  try {
                    if (doc && doc.defaultView) patchWindowContext(doc.defaultView);
                  } catch {}
                  return doc;
                }, 'get contentDocument')
              });
            }
          } catch {}
        }

        if (win.Node && win.Node.prototype) {
          const patchAttachedNode = (node) => {
            try {
              if (!node || typeof node !== 'object') return;
              if (node.tagName === 'IFRAME' && node.contentWindow) {
                patchWindowContext(node.contentWindow);
              }
              if (typeof node.querySelectorAll === 'function') {
                const frames = node.querySelectorAll('iframe');
                for (let i = 0; i < frames.length; i++) {
                  if (frames[i].contentWindow) patchWindowContext(frames[i].contentWindow);
                }
              }
            } catch {}
          };
          if (win.Node.prototype.appendChild) {
            const origAppend = win.Node.prototype.appendChild;
            win.Node.prototype.appendChild = registerNative(function appendChild(node) {
              const res = origAppend.call(this, node);
              patchAttachedNode(node);
              return res;
            }, 'appendChild');
          }
          if (win.Node.prototype.insertBefore) {
            const origInsert = win.Node.prototype.insertBefore;
            win.Node.prototype.insertBefore = registerNative(function insertBefore(node, ref) {
              const res = origInsert.call(this, node, ref);
              patchAttachedNode(node);
              return res;
            }, 'insertBefore');
          }
          if (win.Node.prototype.replaceChild) {
            const origReplace = win.Node.prototype.replaceChild;
            win.Node.prototype.replaceChild = registerNative(function replaceChild(node, oldChild) {
              const res = origReplace.call(this, node, oldChild);
              patchAttachedNode(node);
              return res;
            }, 'replaceChild');
          }
        }
        if (win.Element && win.Element.prototype) {
          for (const methodName of ['append', 'prepend']) {
            if (typeof win.Element.prototype[methodName] === 'function') {
              const origMethod = win.Element.prototype[methodName];
              win.Element.prototype[methodName] = registerNative(function (...nodes) {
                const res = origMethod.apply(this, nodes);
                for (let i = 0; i < nodes.length; i++) {
                  if (nodes[i] && typeof nodes[i] === 'object') {
                    try {
                      if (nodes[i].tagName === 'IFRAME' && nodes[i].contentWindow) {
                        patchWindowContext(nodes[i].contentWindow);
                      } else if (typeof nodes[i].querySelectorAll === 'function') {
                        const frames = nodes[i].querySelectorAll('iframe');
                        for (let j = 0; j < frames.length; j++) {
                          if (frames[j].contentWindow) patchWindowContext(frames[j].contentWindow);
                        }
                      }
                    } catch {}
                  }
                }
                return res;
              }, methodName);
            }
          }
        }
        if (win.Document && win.Document.prototype && win.Document.prototype.write) {
          const origDocWrite = win.Document.prototype.write;
          win.Document.prototype.write = registerNative(function write(...args) {
            const res = origDocWrite.apply(this, args);
            try {
              const frames = this.querySelectorAll ? this.querySelectorAll('iframe') : [];
              for (let i = 0; i < frames.length; i++) {
                if (frames[i].contentWindow) patchWindowContext(frames[i].contentWindow);
              }
            } catch {}
            return res;
          }, 'write');
        }
      };

      patchWindowContext(window);
    } catch {}
  })();`;
}

function buildYouTubeAdblockMainWorldScript() {
  return `(function() {
    try {
      if (typeof location === 'undefined' || !location.hostname || !location.hostname.includes('youtube.com')) {
        return;
      }
      const stripYtAdFields = (obj) => {
        if (!obj || typeof obj !== 'object') return obj;
        try {
          delete obj.adPlacements;
          delete obj.playerAds;
          delete obj.adSlots;
          delete obj.adBreakHeartbeatParams;
          if (obj.playerResponse && typeof obj.playerResponse === 'object') {
            delete obj.playerResponse.adPlacements;
            delete obj.playerResponse.playerAds;
            delete obj.playerResponse.adSlots;
          }
        } catch {}
        return obj;
      };

      // 1) ytInitialPlayerResponse yakalayıcı (yalnızca youtube.com)
      let _ytInitialPlayerResponse = window.ytInitialPlayerResponse;
      if (_ytInitialPlayerResponse) stripYtAdFields(_ytInitialPlayerResponse);
      try {
        Object.defineProperty(window, 'ytInitialPlayerResponse', {
          configurable: true,
          get() { return _ytInitialPlayerResponse; },
          set(val) { _ytInitialPlayerResponse = stripYtAdFields(val); }
        });
      } catch {}

      // 2) Response.prototype.json sarmalayıcı (/youtubei/v1/player ve /youtubei/v1/next yanıtlarındaki reklam dizilerini temizler)
      const origJson = Response.prototype.json;
      const wrappedJson = async function json(...a) {
        const data = await origJson.apply(this, a);
        try {
          stripYtAdFields(data);
        } catch {}
        return data;
      };
      Response.prototype.json = wrappedJson;
    } catch {}
  })();`;
}

if (fpEnabled || isTorTab) {
  try {
    webFrame.executeJavaScript(buildMainWorldShieldScript(sessionSalt, securityLevel, isTorTab, letterboxEnabled, chromeMajor));
  } catch {}
}
if (adblockEnabled) {
  try {
    webFrame.executeJavaScript(buildYouTubeAdblockMainWorldScript());
  } catch {}
}

/* ---------- Mouse Geri/İleri (Yan Tuşlar) & Orta Tuşla Arka Planda Sekme Açma ---------- */
window.addEventListener(
  'mouseup',
  e => {
    if (e.button === 3) {
      e.preventDefault();
      e.stopPropagation();
      ipcRenderer.send('mouse-nav', 'back');
    } else if (e.button === 4) {
      e.preventDefault();
      e.stopPropagation();
      ipcRenderer.send('mouse-nav', 'fwd');
    }
  },
  true
);

window.addEventListener(
  'auxclick',
  e => {
    if (e.button !== 1) return;
    const link = e.target && e.target.closest ? e.target.closest('a[href]') : null;
    if (!link) return;
    const href = link.href || '';
    if (/^https?:\/\//i.test(href)) {
      e.preventDefault();
      e.stopPropagation();
      ipcRenderer.send('open-bg-tab', href);
    }
  },
  true
);

/* ---------- YouTube Video & Sayfa İçi Reklam Kalkanı ---------- */
const YOUTUBE_AD_HIDE_CSS = `
  ytd-ad-slot-renderer,
  ytd-in-feed-ad-layout-renderer,
  ytd-promoted-sparkles-web-renderer,
  ytd-promoted-sparkles-text-search-renderer,
  ytd-promoted-video-renderer,
  ytd-compact-promoted-video-renderer,
  ytd-display-ad-renderer,
  ytd-statement-banner-renderer,
  ytd-banner-promo-renderer,
  ytd-video-masthead-ad-v3-renderer,
  ytd-primetime-promo-renderer,
  ytd-RichItemRenderer:has(ytd-ad-slot-renderer),
  ytd-rich-item-renderer:has(ytd-ad-slot-renderer),
  #masthead-ad,
  #player-ads,
  #panels ytd-engagement-panel-section-list-renderer[target-id="engagement-panel-ads"],
  .ytp-ad-overlay-container,
  .ytp-ad-overlay-slot,
  .ytp-ad-image-overlay,
  .ytp-ad-text-overlay,
  .ytp-ad-message-container,
  .ytp-ad-player-overlay-flyout-cta,
  .ytd-mealbar-promo-renderer,
  tp-yt-paper-dialog:has(ytd-enforcement-message-view-model) {
    display: none !important;
    height: 0 !important;
    min-height: 0 !important;
    visibility: hidden !important;
    pointer-events: none !important;
  }
`;

const opaqueTag = (() => {
  let h = 0x811c9dc5;
  for (let i = 0; i < sessionSalt.length; i++) {
    h ^= sessionSalt.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return 'z' + h.toString(36).slice(0, 6);
})();

const clickedButtons = new WeakSet();
const hookedVideos = new WeakSet();
const attachedHudVideos = new WeakSet();
const reportedVideoKeys = new WeakMap();
const videoAudioBoostMap = new WeakMap();
let ytAdCssKey = null;
let cookieCssKey = null;
let hudBadgeTimer = null;
let lastRgxSvgMarkup = '';

let ytWasInAd = false;
let ytPreAdMuted = false;

async function syncYouTubeAdblockStyle() {
  try {
    if (!location.hostname.includes('youtube.com')) return;
    if (typeof webFrame.insertCSS === 'function') {
      if (adblockEnabled && !ytAdCssKey) {
        ytAdCssKey = await webFrame.insertCSS(YOUTUBE_AD_HIDE_CSS);
      } else if (!adblockEnabled && ytAdCssKey) {
        webFrame.removeInsertedCSS?.(ytAdCssKey);
        ytAdCssKey = null;
      }
    }
  } catch {}
}

async function syncCookieShieldStyle() {
  try {
    if (typeof webFrame.insertCSS === 'function') {
      if (popupsEnabled && !cookieCssKey) {
        cookieCssKey = await webFrame.insertCSS(COOKIE_POPUP_HIDE_CSS);
      } else if (!popupsEnabled && cookieCssKey) {
        webFrame.removeInsertedCSS?.(cookieCssKey);
        cookieCssKey = null;
      }
    }
  } catch {}
}

function skipYouTubeAdsFast() {
  if (!adblockEnabled || !location.hostname.includes('youtube.com')) return;
  try {
    const player = document.getElementById('movie_player') || document.querySelector('.html5-video-player');
    const video = document.querySelector('#movie_player video.html5-main-video') || document.querySelector('video');
    if (!player || !video) return;

    const isAdShowing =
      player.classList.contains('ad-showing') ||
      player.classList.contains('ad-interrupting') ||
      !!document.querySelector('.ad-showing, .ad-interrupting');

    // Her türlü "Reklamı Atla" veya "Kapat" butonuna anında tıkla
    const skipButtons = document.querySelectorAll(
      '.ytp-ad-skip-button, .ytp-ad-skip-button-modern, .ytp-skip-ad-button, .ytp-ad-skip-button-slot button, [id^="skip-button"] button, .ytp-ad-overlay-close-button'
    );
    skipButtons.forEach(btn => {
      try { btn.click(); } catch {}
    });

    if (isAdShowing) {
      if (!ytWasInAd) {
        ytWasInAd = true;
        ytPreAdMuted = !!video.muted;
        ipcRenderer.send('yt-ad-skipped');
      }
      video.muted = true;
      if (Number.isFinite(video.duration) && video.duration > 0.3 && video.currentTime < video.duration - 0.1) {
        try {
          video.currentTime = Math.max(0, video.duration - 0.05);
        } catch {}
      }
      try {
        video.playbackRate = 16;
      } catch {}
    } else if (ytWasInAd) {
      ytWasInAd = false;
      video.muted = ytPreAdMuted;
      try {
        video.playbackRate = currentPlaybackRate || 1;
      } catch {}
    }
  } catch {}
}

/* ---------- Çerez & Bildirim Pop-up Engelleyici + Zorunlu PiP ---------- */
const COOKIE_POPUP_HIDE_CSS = `
  #onetrust-consent-sdk, #onetrust-banner-sdk, .onetrust-pc-dark-filter,
  #CybotCookiebotDialog, #CybotCookiebotDialogBodyUnderlay,
  #qc-cmp2-container, .qc-cmp2-container, .qc-cmp-cleanslate,
  #didomi-host, #didomi-popup, .didomi-popup-backdrop,
  .fc-consent-root, .fc-dialog-overlay,
  ytd-consent-bump-v2-lightbox, tp-yt-iron-overlay-backdrop.opened,
  #cky-consent, .cky-consent-container, .cky-overlay, .cky-modal,
  #usercentrics-root, #usercentrics-cmp-ui,
  div[id^="sp_message_container_"], div[class*="sp_message_container"],
  #cmplz-cookiebanner-container, .cmplz-cookiebanner,
  #truste-consent-track, .truste_overlay, .truste_box_overlay,
  #iubenda-cs-banner, .iubenda-cs-container,
  .osano-cm-window, #BorlabsCookieBox,
  #klaro, .klaro .cookie-modal, .klaro .cookie-notice,
  #termly-code-snippet-support, .t-consentPrompt,
  #axeptio_overlay, .axeptio_widget,
  #tc-privacy-wrapper, #privacy-overlay,
  #cookiescript_injected, #cookiescript_injected_wrapper,
  #moove_gdpr_cookie_info_bar, #moove_gdpr_cookie_modal,
  .ccc-notify, #ccc-module,
  .cc-window, .cc-banner, .cc-floating,
  #cookie-law-info-bar, #cookie-notice, #cookieConsent,
  .efilli-layout-default, #efilli-banner, #setrow-cookie-banner,
  [id*="cookie-banner" i], [class*="cookie-banner" i],
  [id*="cookie_banner" i], [class*="cookie_banner" i],
  [id*="cookie-consent" i], [class*="cookie-consent" i],
  [id*="cookie_consent" i], [class*="cookie_consent" i],
  [id*="cookie-popup" i], [class*="cookie-popup" i],
  [id*="cookie-modal" i], [class*="cookie-modal" i],
  [id*="cookie-notice" i], [class*="cookie-notice" i],
  [id*="cookie-bar" i], [class*="cookie-bar" i],
  [id*="cookie-overlay" i], [class*="cookie-overlay" i],
  [id*="gdpr-banner" i], [class*="gdpr-banner" i],
  [id*="gdpr-modal" i], [class*="gdpr-modal" i],
  [id*="consent-banner" i], [class*="consent-banner" i],
  [id*="consent-modal" i], [class*="consent-modal" i],
  [id*="cerez-banner" i], [class*="cerez-banner" i],
  [id*="cerez-modal" i], [class*="cerez-modal" i],
  [id*="cerez-popup" i], [class*="cerez-popup" i],
  [id*="çerez" i][class*="banner" i], [id*="çerez" i][class*="modal" i],
  [aria-label*="cookie" i][role="dialog"],
  [aria-label*="çerez" i][role="dialog"],
  [aria-label*="consent" i][role="dialog"] {
    display: none !important;
    visibility: hidden !important;
    opacity: 0 !important;
    pointer-events: none !important;
    z-index: -9999 !important;
  }
`;

const KNOWN_CMP_SELECTORS =
  '#onetrust-consent-sdk, #onetrust-banner-sdk, #CybotCookiebotDialog, #didomi-host, .fc-consent-root, .qc-cmp2-container, #cky-consent, .cky-consent-container, #usercentrics-root, div[id^="sp_message_container_"], #cmplz-cookiebanner-container, #iubenda-cs-banner, .osano-cm-window, #klaro, #cookiescript_injected, .cc-window, #cookieConsent';

const CMP_CONTAINER_SELECTOR =
  '[id*="cookie" i], [class*="cookie" i], [id*="consent" i], [class*="consent" i], [id*="gdpr" i], [class*="gdpr" i], [id*="çerez" i], [class*="çerez" i], [id*="cerez" i], [class*="cerez" i], [id*="kvkk" i], [class*="kvkk" i], [id*="cky" i], [class*="cky" i], [id*="usercentrics" i], [id^="sp_message_container_"], [role="dialog"][aria-modal="true"]';

const REJECT_PATTERNS = [
  /^(tümünü|hepsini)?\s*reddet$/i,
  /^çerezleri\s*reddet$/i,
  /^kabul\s*etme$/i,
  /^reddediyorum$/i,
  /^(sadece|yalnızca)\s*(zorunlu|gerekli)(\s*çerezler[ei]?)?(\s*(izin ver|kabul et))?$/i,
  /^zorunlu\s*(çerezler|olmayanları reddet)/i,
  /^(reject|decline|deny|refuse)(\s*(all|cookies|optional|non-essential))?$/i,
  /^(only|strictly)?\s*(necessary|essential|required)\s*(cookies)?(\s*only)?$/i,
  /^use necessary cookies only$/i,
  /^continue without accepting$/i,
  /^do not (accept|consent|sell|share)/i,
  /^(alle\s*)?ablehnen$/i,
  /^nur\s*(notwendige|erforderliche)(\s*cookies)?$/i,
  /^ohne einwilligung fortfahren$/i,
  /^(отклонить|отказать)(\s*все)?$/i,
  /^только\s*(необходимые|обязательные)(\s*файлы\s*cookie)?$/i,
  /^не\s*принимать$/i
];

let hasDismissedConsentOnPage = false;

function walkDomRoots(root, visitor, seen = new Set()) {
  if (!root || seen.has(root)) return;
  seen.add(root);
  visitor(root);
  try {
    const els = root.querySelectorAll ? root.querySelectorAll('*') : [];
    const maxScan = Math.min(els.length, 4000);
    for (let i = 0; i < maxScan; i++) {
      const el = els[i];
      if (el && el.shadowRoot) {
        walkDomRoots(el.shadowRoot, visitor, seen);
      }
    }
  } catch {}
}

function getButtonNormalizedText(btn) {
  const raw =
    btn.innerText ||
    btn.textContent ||
    btn.getAttribute?.('aria-label') ||
    btn.getAttribute?.('title') ||
    btn.value ||
    '';
  return String(raw).replace(/\s+/g, ' ').trim();
}

function isConsentBoxElement(el) {
  if (!el || el.nodeType !== 1) return false;
  const tag = (el.tagName || '').toLowerCase();
  if (tag === 'html' || tag === 'body' || tag === 'main' || tag === 'nav' || tag === 'header') {
    return false;
  }
  const sig = `${el.id || ''} ${typeof el.className === 'string' ? el.className : ''} ${el.getAttribute?.('aria-label') || ''}`.toLowerCase();
  if (/(cookie|çerez|cerez|consent|gdpr|kvkk|onetrust|cookiebot|didomi|usercentrics|sp_message|cky-|cmplz-|iubenda|osano|klaro|axeptio|cookiescript)/i.test(sig)) {
    return true;
  }
  if (el.getAttribute?.('role') === 'dialog' && el.getAttribute?.('aria-modal') === 'true') {
    const txt = (el.innerText || el.textContent || '').slice(0, 600).toLowerCase();
    return /(cookie|çerez|cerez|kvkk|gdpr|gizlilik tercihi|privacy preference)/i.test(txt);
  }
  return false;
}

function cleanCookiePopupsAndEnablePiP() {
  try {
    // 1. Sitelerin koyduğu disablePictureInPicture engelini kaldır
    document.querySelectorAll('video[disablepictureinpicture]').forEach(v => {
      v.removeAttribute('disablepictureinpicture');
      v.disablePictureInPicture = false;
    });

    if (!popupsEnabled) return;

    // 2. Shadow DOM dahil tüm kökleri tara, stil enjekte et, reddet düğmelerine tıkla ve görünür çerez katmanlarını gizle
    walkDomRoots(document, root => {
      // Open shadowRoot için stil enjeksiyonu (yalnızca CMP gölgesi ise)
      if (root !== document && root.host) {
        try {
          const hostSig = `${root.host.id || ''} ${typeof root.host.className === 'string' ? root.host.className : ''} ${root.host.tagName || ''}`.toLowerCase();
          const hasShadowStyle = Boolean(root.querySelector?.('style[data-zaslon-cookie-shield]'));
          if (!hasShadowStyle && /(cookie|çerez|cerez|consent|cmp|gdpr|usercentrics|cky|didomi|onetrust|fc-|sp_)/i.test(hostSig)) {
            const st = document.createElement('style');
            st.setAttribute('data-zaslon-cookie-shield', '1');
            st.textContent = COOKIE_POPUP_HIDE_CSS;
            root.appendChild(st);
            hasDismissedConsentOnPage = true;
          }
        } catch {}
      }

      // Bilinen "Reddet / Sadece Zorunlu" seçicilerine tıkla
      const candidates = root.querySelectorAll
        ? root.querySelectorAll(
            '#onetrust-reject-all-handler, #CybotCookiebotDialogBodyButtonDecline, [data-cky-tag="reject-button"], .cky-btn-reject, button[data-testid="uc-deny-all-button"], button[data-testid*="reject" i], button[data-testid*="decline" i], button[data-testid*="deny" i], .fc-cta-do-not-consent, .didomi-components-button--secondary, button[title*="Reject" i], button[title*="Reddet" i], .js-reject-cookies, [data-action*="reject" i], [id*="reject" i] button, button[id*="reject" i], button[class*="reject" i], button[id*="decline" i], button[class*="decline" i], a[class*="reject" i]'
          )
        : [];
      candidates.forEach(btn => {
        if (btn && !clickedButtons.has(btn)) {
          clickedButtons.add(btn);
          hasDismissedConsentOnPage = true;
          try { btn.click(); } catch {}
        }
      });

      // Metin tabanlı çerez reddetme kontrolü ve dirençli fixed/sticky katman gizleme
      const containers = root.querySelectorAll ? root.querySelectorAll(CMP_CONTAINER_SELECTOR) : [];
      containers.forEach(box => {
        if (!isConsentBoxElement(box)) return;

        const buttons = box.querySelectorAll('button, a[role="button"], input[type="button"], input[type="submit"], [role="button"]');
        buttons.forEach(btn => {
          if (clickedButtons.has(btn)) return;
          const txt = getButtonNormalizedText(btn);
          const foldedTxt = txt.replace(/\u0130/g, 'i').replace(/\u0307/g, '');
          if (
            txt.length > 2 &&
            txt.length <= 64 &&
            REJECT_PATTERNS.some(rx => rx.test(txt) || rx.test(foldedTxt))
          ) {
            clickedButtons.add(btn);
            hasDismissedConsentOnPage = true;
            try { btn.click(); } catch {}
          }
        });

        try {
          const cs = typeof getComputedStyle === 'function' ? getComputedStyle(box) : null;
          if (cs && cs.display !== 'none' && (cs.position === 'fixed' || cs.position === 'sticky' || cs.position === 'absolute')) {
            const boxTxt = (box.innerText || box.textContent || '').slice(0, 800).toLowerCase();
            if (/(cookie|çerez|cerez|gdpr|kvkk|kişisel veri|gizlilik|consent|partners|vendors)/i.test(boxTxt)) {
              box.style.setProperty('display', 'none', 'important');
              box.style.setProperty('visibility', 'hidden', 'important');
              box.style.setProperty('pointer-events', 'none', 'important');
              if (box.dataset) box.dataset.zaslonConsentHidden = '1';
              hasDismissedConsentOnPage = true;
            }
          }
        } catch {}
      });
    });

    // 3. Eğer çerez kutusu gizlendiği/reddedildiği için body scroll kilitli kaldıysa aç
    const bodyLocked = document.body && getComputedStyle(document.body).overflow === 'hidden';
    const htmlLocked = document.documentElement && getComputedStyle(document.documentElement).overflow === 'hidden';
    if (bodyLocked || htmlLocked) {
      const hasLockedConsent = hasDismissedConsentOnPage || Boolean(document.querySelector(KNOWN_CMP_SELECTORS));
      if (hasLockedConsent) {
        if (document.body) document.body.style.setProperty('overflow', 'auto', 'important');
        document.documentElement.style.setProperty('overflow', 'auto', 'important');
      }
    }
  } catch {}
}

window.addEventListener('DOMContentLoaded', () => {
  syncCookieShieldStyle();
  syncYouTubeAdblockStyle();
  skipYouTubeAdsFast();
  if (location.hostname.includes('youtube.com')) {
    setInterval(skipYouTubeAdsFast, 180);
  }
  cleanCookiePopupsAndEnablePiP();
  [300, 900, 2000, 4000, 6500].forEach(ms => setTimeout(cleanCookiePopupsAndEnablePiP, ms));

  initMediaAndSponsorBlockEngine();
  syncRgxDomState();

  // Dinamik yüklenen videolar ve çerez pencereleri için gözlemci
  try {
    let debounce = null;
    const obs = new MutationObserver(() => {
      skipYouTubeAdsFast();
      if (debounce) return;
      debounce = setTimeout(() => {
        debounce = null;
        syncYouTubeAdblockStyle();
        cleanCookiePopupsAndEnablePiP();
        scanDomVideosAndAttachHooks();
        syncRgxDomState();
      }, 400);
    });
    obs.observe(document.documentElement, { childList: true, subtree: true });
  } catch {}
});

/* ---------- Faz 4: SponsorBlock + Evrensel Video Hız/PiP + Medya Yakalayıcı ---------- */
let currentSbUrl = '';
let currentSbSegments = [];
let lastSkippedUuid = '';
let currentPlaybackRate = 1;

let overlayHostEl = null;
let overlayShadowRoot = null;
let toastBadgeEl = null;
let rgxFlashEl = null;

function getOverlayShadowRoot() {
  try {
    const parent = document.fullscreenElement || document.body || document.documentElement;
    if (!parent) return null;
    if (!overlayHostEl || !overlayShadowRoot) {
      overlayHostEl = document.createElement('div');
      overlayHostEl.style.cssText = 'all:initial;position:fixed;inset:0;pointer-events:none;z-index:2147483647';
      overlayShadowRoot = overlayHostEl.attachShadow({ mode: 'closed' });
    }
    if (overlayHostEl.parentElement !== parent) {
      parent.appendChild(overlayHostEl);
    }
    return overlayShadowRoot;
  } catch {
    return null;
  }
}

function showOnPageBadge(text) {
  try {
    const sr = getOverlayShadowRoot();
    if (!sr) return;
    if (!toastBadgeEl) {
      toastBadgeEl = document.createElement('div');
      toastBadgeEl.style.cssText =
        'position:fixed;bottom:24px;right:24px;z-index:2147483647;background:rgba(13,24,46,0.94);color:#e6ecfa;border:1px solid #3b82f6;border-radius:12px;padding:9px 15px;font:600 13px "Segoe UI",system-ui,sans-serif;box-shadow:0 8px 24px rgba(0,0,0,0.5);pointer-events:none;transition:opacity 0.2s ease,transform 0.2s ease;opacity:0;transform:translateY(8px)';
      sr.appendChild(toastBadgeEl);
    }
    toastBadgeEl.textContent = text;
    toastBadgeEl.style.opacity = '1';
    toastBadgeEl.style.transform = 'translateY(0)';
    clearTimeout(hudBadgeTimer);
    hudBadgeTimer = setTimeout(() => {
      if (toastBadgeEl) {
        toastBadgeEl.style.opacity = '0';
        toastBadgeEl.style.transform = 'translateY(8px)';
      }
    }, 2400);
  } catch {}
}

async function refreshSponsorBlockForPage() {
  if (!sponsorBlockEnabled) {
    currentSbSegments = [];
    return;
  }
  const href = location.href || '';
  if (!/youtube\.com\/(watch|shorts|live)|youtu\.be\//i.test(href)) {
    currentSbSegments = [];
    currentSbUrl = href;
    return;
  }
  if (href === currentSbUrl && currentSbSegments.length > 0) return;
  currentSbUrl = href;
  lastSkippedUuid = '';

  try {
    const segs = await ipcRenderer.invoke('get-sponsorblock-segments', href);
    if (Array.isArray(segs)) {
      currentSbSegments = segs;
      if (segs.length > 0) {
        showOnPageBadge(pt('sbReady', { n: segs.length }));
      }
    }
  } catch {
    currentSbSegments = [];
  }
}

function reportVideoToMain(video) {
  try {
    const src = video.currentSrc || video.src || '';
    const pageUrl = location.href || '';
    if (!pageUrl.startsWith('http')) return;
    ipcRenderer.send('dom-media-detected', {
      src,
      pageUrl,
      title: document.title || '',
      hasVideo: true,
      width: video.videoWidth || 0,
      height: video.videoHeight || 0,
      duration: Number.isFinite(video.duration) ? Math.round(video.duration) : 0
    });
  } catch {}
}

/* ---------- Faz 6: Zaslon RGX (Gerçek Zamanlı GPU Video & Görsel Keskinleştirme / İyileştirme) ---------- */
const RGX_PRESETS = {
  std: { label: 'CAS', sharpness: 55, saturation: 112, contrast: 106, brightness: 100 },
  cinema: { label: 'HDR', sharpness: 45, saturation: 124, contrast: 114, brightness: 102 },
  anime: { label: 'ANIME', sharpness: 80, saturation: 120, contrast: 110, brightness: 100 },
  ultra: { label: 'ULTRA', sharpness: 95, saturation: 108, contrast: 112, brightness: 100 }
};

let activeRgxVideo = null;
let rgxHudEl = null;
let rgxSplitEl = null;
let rgxHudHideTimer = null;
let rgxDraggingSplit = false;

function isRgxAllowedOnCurrentHost() {
  try {
    const h = (location.hostname || '').replace(/^www\./, '').toLowerCase();
    if (!h) return true;
    return !(Array.isArray(rgxDisabledHosts) && rgxDisabledHosts.includes(h));
  } catch {
    return true;
  }
}

function isRgxEffective() {
  return Boolean(rgxEnabled && isRgxAllowedOnCurrentHost());
}

function computeCasKernel(sharpnessPct, scaleFactor = 0.78) {
  const s = (Math.max(0, Math.min(100, Number(sharpnessPct) || 0)) / 100) * scaleFactor;
  const corner = -(s * 0.25);
  const edge = -(s * 0.5);
  const center = 1 + s * 3.0; // Toplam = 1.0000 (parlaklık kayması olmaz)
  const c = corner.toFixed(4);
  const e = edge.toFixed(4);
  const m = center.toFixed(4);
  return `${c} ${e} ${c} ${e} ${m} ${e} ${c} ${e} ${c}`;
}

function syncRgxDomState() {
  try {
    const root = document.documentElement || document.body;
    if (!root) return;

    const effective = isRgxEffective();
    const vSharp = Math.max(0, Math.min(100, Number(rgxSharpness) ?? 55));
    const sat = Math.max(70, Math.min(180, Number(rgxSaturation) ?? 112));
    const con = Math.max(80, Math.min(150, Number(rgxContrast) ?? 106));
    const bri = Math.max(75, Math.min(140, Number(rgxBrightness) ?? 100));

    // 1. Görünmez 0x0 GPU SVG Konvolüsyon Matrisi (<feConvolveMatrix>) oluştur/güncelle
    const svgId = `${opaqueTag}_svg`;
    const vfId = `${opaqueTag}_vf`;
    const ifId = `${opaqueTag}_if`;
    const styleId = `${opaqueTag}_st`;
    let svgEl = document.getElementById(svgId);
    if (effective && (rgxVideos || rgxImages)) {
      const vKernel = computeCasKernel(vSharp, 0.78);
      const iKernel = computeCasKernel(vSharp, 0.56);
      if (!svgEl) {
        svgEl = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svgEl.id = svgId;
        svgEl.setAttribute('width', '0');
        svgEl.setAttribute('height', '0');
        svgEl.setAttribute('aria-hidden', 'true');
        svgEl.style.cssText =
          'position:fixed;top:-9999px;left:-9999px;width:0;height:0;pointer-events:none;visibility:hidden;overflow:hidden';
        root.appendChild(svgEl);
      }
      const nextMarkup = `<defs>
        <filter id="${vfId}" color-interpolation-filters="sRGB">
          <feConvolveMatrix order="3 3" kernelMatrix="${vKernel}" preserveAlpha="true"/>
        </filter>
        <filter id="${ifId}" color-interpolation-filters="sRGB">
          <feConvolveMatrix order="3 3" kernelMatrix="${iKernel}" preserveAlpha="true"/>
        </filter>
      </defs>`;
      if (lastRgxSvgMarkup !== nextMarkup) {
        svgEl.innerHTML = nextMarkup;
        lastRgxSvgMarkup = nextMarkup;
      }
    } else if (svgEl) {
      svgEl.remove();
      lastRgxSvgMarkup = '';
    }

    // 2. Video ve Görsel CSS Filtre Kurallarını oluştur/güncelle
    let styleEl = document.getElementById(styleId);
    if (effective && (rgxVideos || rgxImages)) {
      const vFilterChain =
        vSharp > 0
          ? `url(#${vfId}) contrast(${con}%) saturate(${sat}%) brightness(${bri}%)`
          : `contrast(${con}%) saturate(${sat}%) brightness(${bri}%)`;
      const iFilterChain =
        vSharp > 0
          ? `url(#${ifId}) contrast(${Math.round(100 + (con - 100) * 0.65)}%) saturate(${Math.round(100 + (sat - 100) * 0.65)}%)`
          : `contrast(${Math.round(100 + (con - 100) * 0.65)}%) saturate(${Math.round(100 + (sat - 100) * 0.65)}%)`;

      let cssRules = '';
      if (rgxVideos && !rgxSplitPreview) {
        cssRules += `
          video:not([data-z-ign="1"]) {
            filter: ${vFilterChain} !important;
            will-change: filter;
          }
        `;
      }
      if (rgxImages) {
        cssRules += `
          img:not([width="16"]):not([width="20"]):not([width="24"]):not([width="32"]):not([height="16"]):not([height="20"]):not([height="24"]):not([height="32"]):not([src$=".svg"]):not([class*="icon" i]):not([class*="logo" i]):not([class*="avatar" i]):not([class*="emoji" i]) {
            filter: ${iFilterChain} !important;
          }
        `;
      }

      if (!styleEl) {
        styleEl = document.createElement('style');
        styleEl.id = styleId;
        (document.head || root).appendChild(styleEl);
      }
      if (styleEl.textContent !== cssRules) {
        styleEl.textContent = cssRules;
      }
    } else if (styleEl) {
      styleEl.remove();
    }

    updateRgxHudAndSplitOverlay();
  } catch {}
}

function triggerRgxVideoFlash(video) {
  try {
    if (!video) return;
    const rect = video.getBoundingClientRect();
    if (rect.width < 120 || rect.height < 80) return;
    const sr = getOverlayShadowRoot();
    if (!sr) return;
    if (!rgxFlashEl) {
      rgxFlashEl = document.createElement('div');
      sr.appendChild(rgxFlashEl);
    }
    rgxFlashEl.style.cssText = `
      position:fixed;
      left:${Math.round(rect.left)}px;
      top:${Math.round(rect.top)}px;
      width:${Math.round(rect.width)}px;
      height:${Math.round(rect.height)}px;
      z-index:2147483645;
      pointer-events:none;
      border:2px solid #22d3ee;
      border-radius:8px;
      box-shadow:inset 0 0 32px rgba(34,211,238,0.45), 0 0 24px rgba(59,130,246,0.45);
      background:linear-gradient(115deg, rgba(34,211,238,0.18) 0%, rgba(59,130,246,0.05) 50%, transparent 100%);
      opacity:1;
      transition:opacity 0.45s cubic-bezier(0.2,0,0,1);
    `;
    requestAnimationFrame(() => {
      if (rgxFlashEl) rgxFlashEl.style.opacity = '0';
    });
  } catch {}
}

function notifyMainRgxInlineChange() {
  try {
    ipcRenderer.send('rgx-inline-toggle', {
      enabled: rgxEnabled,
      preset: rgxPreset,
      sharpness: rgxSharpness,
      saturation: rgxSaturation,
      contrast: rgxContrast,
      brightness: rgxBrightness,
      split: rgxSplitPreview
    });
  } catch {}
}

function ensureRgxHudElement() {
  const sr = getOverlayShadowRoot();
  if (!sr) return null;
  if (rgxHudEl && sr.contains(rgxHudEl)) return rgxHudEl;

  const el = document.createElement('div');
  el.style.cssText = `
    position:fixed;
    z-index:2147483646;
    display:none;
    pointer-events:auto;
    align-items:center;
    gap:4px;
    padding:4px 6px;
    border-radius:999px;
    background:rgba(8,16,31,0.88);
    backdrop-filter:blur(10px);
    border:1px solid rgba(56,189,248,0.38);
    box-shadow:0 6px 20px rgba(0,0,0,0.55), 0 0 14px rgba(14,165,233,0.22);
    font:700 11.5px/1 "Segoe UI",system-ui,sans-serif;
    color:#e6ecfa;
    user-select:none;
    transition:opacity 0.18s ease, transform 0.18s ease;
    opacity:0;
    transform:translate(-50%, -4px);
  `;

  el.innerHTML = `
    <button type="button" data-rgx-act="toggle" style="all:unset;cursor:pointer;display:inline-flex;align-items:center;gap:5px;padding:5px 10px;border-radius:999px;font-weight:800;letter-spacing:0.4px;transition:all 0.15s ease">
      <span style="font-size:12px">✨</span><span>RGX</span>
    </button>
    <button type="button" data-rgx-act="preset" title="RGX Profilini Değiştir (CAS / HDR / Anime / Ultra)" style="all:unset;cursor:pointer;padding:4px 7px;border-radius:999px;font-size:10px;font-weight:700;background:rgba(255,255,255,0.08);color:#7dd3fc;transition:all 0.15s ease">CAS</button>
    <button type="button" data-rgx-act="split" style="all:unset;cursor:pointer;padding:4px 8px;border-radius:999px;font-size:10.5px;font-weight:600;background:rgba(255,255,255,0.07);color:#cbd5e1;transition:all 0.15s ease"></button>
  `;

  el.addEventListener('mouseenter', () => {
    clearTimeout(rgxHudHideTimer);
  });
  el.addEventListener('mouseleave', () => {
    scheduleHideRgxHud(1200);
  });

  el.addEventListener(
    'click',
    e => {
      e.preventDefault();
      e.stopPropagation();
      const btn = e.target.closest ? e.target.closest('[data-rgx-act]') : null;
      if (!btn) return;
      const act = btn.getAttribute('data-rgx-act');
      if (act === 'toggle') {
        rgxEnabled = !rgxEnabled;
        if (!rgxEnabled) rgxSplitPreview = false;
        syncRgxDomState();
        notifyMainRgxInlineChange();
        if (rgxEnabled && activeRgxVideo) triggerRgxVideoFlash(activeRgxVideo);
        const pInfo = RGX_PRESETS[rgxPreset] || RGX_PRESETS.std;
        showOnPageBadge(
          rgxEnabled
            ? pt('rgxToastOn', { preset: pInfo.label, sharp: rgxSharpness })
            : pt('rgxToastOff')
        );
      } else if (act === 'preset') {
        const keys = Object.keys(RGX_PRESETS);
        const nextIdx = (keys.indexOf(rgxPreset) + 1) % keys.length;
        rgxPreset = keys[nextIdx];
        const pr = RGX_PRESETS[rgxPreset];
        rgxSharpness = pr.sharpness;
        rgxSaturation = pr.saturation;
        rgxContrast = pr.contrast;
        rgxBrightness = pr.brightness;
        rgxEnabled = true;
        syncRgxDomState();
        notifyMainRgxInlineChange();
        if (activeRgxVideo) triggerRgxVideoFlash(activeRgxVideo);
        showOnPageBadge(pt('rgxToastOn', { preset: pr.label, sharp: rgxSharpness }));
      } else if (act === 'split') {
        if (!rgxEnabled) {
          rgxEnabled = true;
          rgxSplitPreview = true;
        } else {
          rgxSplitPreview = !rgxSplitPreview;
        }
        syncRgxDomState();
        notifyMainRgxInlineChange();
        showOnPageBadge(rgxSplitPreview ? pt('rgxSplitOn') : pt('rgxSplitOff'));
      }
    },
    true
  );

  sr.appendChild(el);
  rgxHudEl = el;
  return el;
}

function ensureRgxSplitOverlay() {
  const sr = getOverlayShadowRoot();
  if (!sr) return null;
  if (rgxSplitEl && sr.contains(rgxSplitEl)) return rgxSplitEl;

  const wrap = document.createElement('div');
  wrap.style.cssText = 'position:fixed;z-index:2147483644;pointer-events:none;display:none;overflow:hidden;user-select:none';
  wrap.innerHTML = `
    <div data-split-left style="position:absolute;top:12px;left:12px;padding:4px 9px;border-radius:6px;background:rgba(8,16,31,0.78);color:#94a3b8;font:700 10.5px 'Segoe UI',system-ui,sans-serif;letter-spacing:0.6px;border:1px solid rgba(255,255,255,0.12)"></div>
    <div data-split-right style="position:absolute;top:0;bottom:0;right:0;pointer-events:none;overflow:hidden">
      <div data-split-badge style="position:absolute;top:12px;right:12px;padding:4px 10px;border-radius:6px;background:rgba(6,182,212,0.22);color:#67e8f9;font:800 10.5px 'Segoe UI',system-ui,sans-serif;letter-spacing:0.6px;border:1px solid rgba(34,211,238,0.55);box-shadow:0 0 12px rgba(6,182,212,0.35)"></div>
    </div>
    <div data-split-handle style="position:absolute;top:0;bottom:0;width:18px;transform:translateX(-50%);cursor:ew-resize;pointer-events:auto;display:flex;align-items:center;justify-content:center">
      <div style="width:2px;height:100%;background:linear-gradient(180deg,#38bdf8,#22d3ee,#3b82f6);box-shadow:0 0 10px #22d3ee"></div>
      <div style="position:absolute;width:26px;height:26px;border-radius:50%;background:#08101f;border:2px solid #22d3ee;color:#67e8f9;display:grid;place-items:center;font:700 11px sans-serif;box-shadow:0 4px 12px rgba(0,0,0,0.6)">⇔</div>
    </div>
  `;

  const handle = wrap.querySelector('[data-split-handle]');
  if (handle) {
    handle.addEventListener(
      'mousedown',
      e => {
        e.preventDefault();
        e.stopPropagation();
        rgxDraggingSplit = true;
      },
      true
    );
  }

  window.addEventListener(
    'mousemove',
    e => {
      if (!rgxDraggingSplit || !activeRgxVideo) return;
      const r = activeRgxVideo.getBoundingClientRect();
      if (r.width <= 40) return;
      const pct = ((e.clientX - r.left) / r.width) * 100;
      rgxSplitRatio = Math.max(10, Math.min(90, Math.round(pct)));
      updateRgxHudAndSplitOverlay();
    },
    true
  );

  window.addEventListener(
    'mouseup',
    () => {
      rgxDraggingSplit = false;
    },
    true
  );

  sr.appendChild(wrap);
  rgxSplitEl = wrap;
  return wrap;
}

function updateRgxHudAndSplitOverlay() {
  try {
    const effective = isRgxEffective();
    const hud = rgxHudEl;
    if (hud) {
      // Tam ekran geçişinde kapalı gölge DOM kapsayıcısını güncelle
      getOverlayShadowRoot();
      const togBtn = hud.querySelector('[data-rgx-act="toggle"]');
      const preBtn = hud.querySelector('[data-rgx-act="preset"]');
      const splBtn = hud.querySelector('[data-rgx-act="split"]');
      if (togBtn) {
        togBtn.style.background = effective
          ? 'linear-gradient(135deg, #06b6d4, #2563eb)'
          : 'rgba(255,255,255,0.08)';
        togBtn.style.color = effective ? '#ffffff' : '#94a3b8';
        togBtn.style.boxShadow = effective ? '0 0 12px rgba(6,182,212,0.55)' : 'none';
      }
      if (preBtn) {
        const pr = RGX_PRESETS[rgxPreset] || RGX_PRESETS.std;
        preBtn.textContent = pr.label;
      }
      if (splBtn) {
        splBtn.textContent = pt('rgxCompare');
        splBtn.style.background =
          effective && rgxSplitPreview ? 'rgba(34,211,238,0.22)' : 'rgba(255,255,255,0.07)';
        splBtn.style.color = effective && rgxSplitPreview ? '#67e8f9' : '#cbd5e1';
        splBtn.style.border =
          effective && rgxSplitPreview ? '1px solid rgba(34,211,238,0.45)' : '1px solid transparent';
      }
      if (activeRgxVideo && hud.style.display !== 'none') {
        const r = activeRgxVideo.getBoundingClientRect();
        if (r.width >= 200 && r.height >= 110) {
          hud.style.left = `${Math.round(r.left + r.width / 2)}px`;
          hud.style.top = `${Math.max(8, Math.round(r.top + 12))}px`;
        } else {
          hud.style.display = 'none';
        }
      }
    }

    // Bölünmüş Ekran (Split-View) Katmanı
    if (effective && rgxVideos && rgxSplitPreview) {
      if (!activeRgxVideo || !document.contains(activeRgxVideo)) {
        const vids = [...document.querySelectorAll('video')].sort(
          (a, b) => b.clientWidth * b.clientHeight - a.clientWidth * a.clientHeight
        );
        activeRgxVideo = vids[0] || null;
      }
      if (activeRgxVideo) {
        const r = activeRgxVideo.getBoundingClientRect();
        if (r.width >= 160 && r.height >= 100) {
          const sp = ensureRgxSplitOverlay();
          if (sp) {
            getOverlayShadowRoot();

            const vSharp = Math.max(0, Math.min(100, Number(rgxSharpness) ?? 55));
            const sat = Math.max(70, Math.min(180, Number(rgxSaturation) ?? 112));
            const con = Math.max(80, Math.min(150, Number(rgxContrast) ?? 106));
            const bri = Math.max(75, Math.min(140, Number(rgxBrightness) ?? 100));
            const vFilterChain =
              vSharp > 0
                ? `url(#${opaqueTag}_vf) contrast(${con}%) saturate(${sat}%) brightness(${bri}%)`
                : `contrast(${con}%) saturate(${sat}%) brightness(${bri}%)`;

            sp.style.display = 'block';
            sp.style.left = `${Math.round(r.left)}px`;
            sp.style.top = `${Math.round(r.top)}px`;
            sp.style.width = `${Math.round(r.width)}px`;
            sp.style.height = `${Math.round(r.height)}px`;

            const leftLbl = sp.querySelector('[data-split-left]');
            const rightPane = sp.querySelector('[data-split-right]');
            const rightBadge = sp.querySelector('[data-split-badge]');
            const handle = sp.querySelector('[data-split-handle]');

            if (leftLbl) leftLbl.textContent = pt('rgxOriginal');
            if (rightBadge) rightBadge.textContent = pt('rgxActiveBadge');
            if (rightPane) {
              rightPane.style.left = `${rgxSplitRatio}%`;
              rightPane.style.backdropFilter = vFilterChain;
              rightPane.style.webkitBackdropFilter = vFilterChain;
            }
            if (handle) {
              handle.style.left = `${rgxSplitRatio}%`;
            }
            return;
          }
        }
      }
    }

    if (rgxSplitEl) {
      rgxSplitEl.style.display = 'none';
    }
  } catch {}
}

function showRgxHudForVideo(video) {
  if (!videoHoverHudEnabled || !rgxHudEnabled || !isRgxAllowedOnCurrentHost()) return;
  try {
    const r = video.getBoundingClientRect();
    if (r.width < 220 || r.height < 120) return;
    activeRgxVideo = video;
    const hud = ensureRgxHudElement();
    if (!hud) return;
    updateRgxHudAndSplitOverlay();
    hud.style.display = 'inline-flex';
    requestAnimationFrame(() => {
      hud.style.opacity = '1';
      hud.style.transform = 'translate(-50%, 0)';
    });
    scheduleHideRgxHud(2400);
  } catch {}
}

function scheduleHideRgxHud(delayMs = 2000) {
  clearTimeout(rgxHudHideTimer);
  rgxHudHideTimer = setTimeout(() => {
    if (rgxHudEl && !rgxDraggingSplit) {
      rgxHudEl.style.opacity = '0';
      rgxHudEl.style.transform = 'translate(-50%, -4px)';
      setTimeout(() => {
        if (rgxHudEl && rgxHudEl.style.opacity === '0') {
          rgxHudEl.style.display = 'none';
        }
      }, 190);
    }
  }, delayMs);
}

window.addEventListener(
  'scroll',
  () => {
    if (rgxSplitPreview && isRgxEffective()) {
      updateRgxHudAndSplitOverlay();
    } else if (rgxHudEl && rgxHudEl.style.display !== 'none') {
      updateRgxHudAndSplitOverlay();
    }
  },
  { passive: true, capture: true }
);

window.addEventListener(
  'resize',
  () => {
    if ((rgxSplitPreview && isRgxEffective()) || (rgxHudEl && rgxHudEl.style.display !== 'none')) {
      updateRgxHudAndSplitOverlay();
    }
  },
  { passive: true }
);

function attachVideoHoverController(video) {
  if (!videoHoverHudEnabled || attachedHudVideos.has(video)) return;
  attachedHudVideos.add(video);

  video.addEventListener('loadedmetadata', () => {
    reportVideoToMain(video);
    syncRgxDomState();
  });
  video.addEventListener('playing', () => {
    reportVideoToMain(video);
    syncRgxDomState();
  });
  video.addEventListener('mouseenter', () => showRgxHudForVideo(video), { passive: true });
  video.addEventListener('mousemove', () => showRgxHudForVideo(video), { passive: true });
  video.addEventListener('mouseleave', () => scheduleHideRgxHud(900), { passive: true });
}

function scanDomVideosAndAttachHooks() {
  try {
    if (location.href !== currentSbUrl) {
      refreshSponsorBlockForPage();
    }
    const videos = document.querySelectorAll('video');
    videos.forEach(video => {
      video.removeAttribute('disablepictureinpicture');
      video.disablePictureInPicture = false;

      if (!hookedVideos.has(video)) {
        hookedVideos.add(video);
        if (currentPlaybackRate !== 1) {
          try { video.playbackRate = currentPlaybackRate; } catch {}
        }

        // SponsorBlock zaman kontrolü
        video.addEventListener('timeupdate', () => {
          if (!sponsorBlockEnabled || !currentSbSegments.length) return;
          const t = video.currentTime;
          for (const seg of currentSbSegments) {
            if (t >= seg.start && t < seg.end - 0.35 && lastSkippedUuid !== seg.uuid) {
              lastSkippedUuid = seg.uuid;
              const skippedSec = Math.max(1, Math.round(seg.end - t));
              try {
                video.currentTime = seg.end;
              } catch {}
              ipcRenderer.send('sponsorblock-skipped', {
                uuid: seg.uuid,
                category: seg.category,
                label: seg.label,
                duration: skippedSec
              });
              showOnPageBadge(pt('sbSkipped', { label: seg.label, sec: skippedSec }));
              break;
            }
          }
        });

        attachVideoHoverController(video);
      }

      const src = video.currentSrc || video.src || '';
      const reportKey = `${location.href}::${src}::${document.title}`;
      if ((src || video.readyState >= 1) && reportedVideoKeys.get(video) !== reportKey) {
        reportedVideoKeys.set(video, reportKey);
        reportVideoToMain(video);
      }
    });
  } catch {}
}

function initMediaAndSponsorBlockEngine() {
  refreshSponsorBlockForPage();
  scanDomVideosAndAttachHooks();
  window.addEventListener('yt-navigate-finish', () => {
    currentSbUrl = '';
    refreshSponsorBlockForPage();
    setTimeout(scanDomVideosAndAttachHooks, 400);
    setTimeout(scanDomVideosAndAttachHooks, 1500);
  });
  window.addEventListener('popstate', () => {
    currentSbUrl = '';
    refreshSponsorBlockForPage();
    setTimeout(scanDomVideosAndAttachHooks, 400);
  });
}

/* ---------- Faz 4: Tam Sayfa Yerinde (In-Place) DOM Çevirisi & Orijinale Dön ---------- */
const originalDomTexts = new Map(); // TextNode -> originalString
let isPageTranslated = false;

const SKIP_TRANSLATE_TAGS = new Set([
  'SCRIPT',
  'STYLE',
  'NOSCRIPT',
  'CODE',
  'PRE',
  'KBD',
  'SAMP',
  'VAR',
  'TEXTAREA',
  'INPUT',
  'SVG',
  'MATH',
  'CANVAS'
]);

function collectTranslatableTextNodes() {
  const nodes = [];
  if (!document.body) return nodes;

  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      const parent = node.parentElement;
      if (!parent) return NodeFilter.FILTER_REJECT;
      if (SKIP_TRANSLATE_TAGS.has(parent.tagName)) return NodeFilter.FILTER_REJECT;
      if (parent.closest('code, pre, script, style, svg, [translate="no"], .notranslate')) {
        return NodeFilter.FILTER_REJECT;
      }
      const raw = node.nodeValue || '';
      const trimmed = raw.trim();
      if (trimmed.length < 2) return NodeFilter.FILTER_REJECT;
      // Yalnızca sayı veya noktalama işareti olan düğümleri atla
      if (/^[\d\s.,:/\-+()%$€£₺@#&*!?<>[\]{}|\\~`"'=]+$/.test(trimmed)) {
        return NodeFilter.FILTER_REJECT;
      }
      return NodeFilter.FILTER_ACCEPT;
    }
  });

  let n;
  while ((n = walker.nextNode()) && nodes.length < 280) {
    nodes.push(n);
  }
  return nodes;
}

async function translateFullPageInPlace(source = 'auto', target = currentLang || 'tr', extraOpts = {}) {
  try {
    const nodes = collectTranslatableTextNodes();
    if (!nodes.length) {
      return { ok: false, error: pt('domNoText') };
    }

    showOnPageBadge(pt('domTranslating'));

    const textsToTranslate = nodes.map(node => {
      if (!originalDomTexts.has(node)) {
        originalDomTexts.set(node, node.nodeValue);
      }
      return (originalDomTexts.get(node) || node.nodeValue || '').trim();
    });

    const res = await ipcRenderer.invoke('translateBatch', {
      texts: textsToTranslate,
      source,
      target,
      ...(extraOpts && typeof extraOpts === 'object' ? extraOpts : {})
    });

    if (!res || !res.ok || !Array.isArray(res.translations)) {
      return { ok: false, error: res?.error || pt('domNoResp') };
    }

    let replacedCount = 0;
    for (let i = 0; i < nodes.length; i++) {
      const node = nodes[i];
      const translated = res.translations[i];
      if (!node || !translated) continue;
      const orig = originalDomTexts.get(node) || node.nodeValue || '';
      const leadMatch = orig.match(/^\s*/);
      const trailMatch = orig.match(/\s*$/);
      const lead = leadMatch ? leadMatch[0] : '';
      const trail = trailMatch ? trailMatch[0] : '';
      node.nodeValue = `${lead}${translated}${trail}`;
      replacedCount++;
    }

    isPageTranslated = true;
    const providerName = res.provider || pt('domProviderDefault');
    showOnPageBadge(pt('domTranslated', { count: replacedCount, provider: providerName }));
    return {
      ok: true,
      translatedCount: replacedCount,
      provider: providerName,
      isPageTranslated: true
    };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

function restoreOriginalPageDom() {
  let restoredCount = 0;
  for (const [node, origText] of originalDomTexts.entries()) {
    try {
      if (node && typeof origText === 'string') {
        node.nodeValue = origText;
        restoredCount++;
      }
    } catch {}
  }
  originalDomTexts.clear();
  isPageTranslated = false;
  showOnPageBadge(pt('domRestored'));
  return { ok: true, restoredCount, isPageTranslated: false };
}

function applyIncomingRgxConfig(cfg, showFeedback = false) {
  if (!cfg || typeof cfg !== 'object') return;
  const prevEnabled = rgxEnabled;
  const prevSplit = rgxSplitPreview;
  if (typeof cfg.rgxEnabled === 'boolean') rgxEnabled = cfg.rgxEnabled;
  if (typeof cfg.rgxPreset === 'string') rgxPreset = cfg.rgxPreset;
  if (typeof cfg.rgxVideos === 'boolean') rgxVideos = cfg.rgxVideos;
  if (typeof cfg.rgxImages === 'boolean') rgxImages = cfg.rgxImages;
  if (typeof cfg.rgxHud === 'boolean') rgxHudEnabled = cfg.rgxHud;
  if (typeof cfg.rgxSplit === 'boolean') rgxSplitPreview = cfg.rgxSplit;
  if (typeof cfg.rgxSharpness === 'number') rgxSharpness = cfg.rgxSharpness;
  if (typeof cfg.rgxSaturation === 'number') rgxSaturation = cfg.rgxSaturation;
  if (typeof cfg.rgxContrast === 'number') rgxContrast = cfg.rgxContrast;
  if (typeof cfg.rgxBrightness === 'number') rgxBrightness = cfg.rgxBrightness;
  if (Array.isArray(cfg.rgxDisabledHosts)) rgxDisabledHosts = cfg.rgxDisabledHosts;

  syncRgxDomState();

  if (showFeedback) {
    const vids = [...document.querySelectorAll('video')].sort(
      (a, b) => b.clientWidth * b.clientHeight - a.clientWidth * a.clientHeight
    );
    const topVid = vids[0] || activeRgxVideo;
    if (rgxEnabled && !prevEnabled && topVid) {
      triggerRgxVideoFlash(topVid);
    }
    if (rgxSplitPreview !== prevSplit && rgxEnabled) {
      showOnPageBadge(rgxSplitPreview ? pt('rgxSplitOn') : pt('rgxSplitOff'));
    } else if (rgxEnabled !== prevEnabled) {
      const pr = RGX_PRESETS[rgxPreset] || RGX_PRESETS.std;
      showOnPageBadge(
        rgxEnabled
          ? pt('rgxToastOn', { preset: pr.label, sharp: rgxSharpness })
          : pt('rgxToastOff')
      );
    }
  }
}

ipcRenderer.on('zaslon-page-config', (_e, cfg) => {
  if (typeof cfg.adblock === 'boolean') {
    adblockEnabled = cfg.adblock;
    syncYouTubeAdblockStyle();
  }
  if (typeof cfg.popups === 'boolean') {
    popupsEnabled = cfg.popups;
    syncCookieShieldStyle();
    if (popupsEnabled) cleanCookiePopupsAndEnablePiP();
  }
  if (typeof cfg.sponsorBlock === 'boolean') {
    sponsorBlockEnabled = cfg.sponsorBlock;
    refreshSponsorBlockForPage();
  }
  if (typeof cfg.securityLevel === 'string') securityLevel = cfg.securityLevel;
  if (typeof cfg.lang === 'string' && PAGE_I18N[cfg.lang]) currentLang = cfg.lang;
  applyIncomingRgxConfig(cfg, false);
});

ipcRenderer.on('zaslon-rgx-config', (_e, cfg) => {
  applyIncomingRgxConfig(cfg, Boolean(cfg && cfg.flash));
});

ipcRenderer.on('zaslon-dom-translate', async (_e, opts = {}) => {
  if (opts.action === 'restore') {
    const r = restoreOriginalPageDom();
    ipcRenderer.send('zaslon-dom-translate-done', r);
  } else {
    const r = await translateFullPageInPlace(opts.source || 'auto', opts.target || currentLang || 'tr', opts);
    ipcRenderer.send('zaslon-dom-translate-done', r);
  }
});

ipcRenderer.on('zaslon-video-control', (_e, payload = {}) => {
  const { reqId, action, value } = payload;
  const reply = res => {
    if (reqId) ipcRenderer.send(`zaslon-video-control-res-${reqId}`, res);
  };
  try {
    const videos = [...document.querySelectorAll('video')].sort(
      (a, b) => b.clientWidth * b.clientHeight - a.clientWidth * a.clientHeight
    );
    const v = videos[0];
    if (!v) return reply({ ok: false, error: pt('noVideo') });

    if (action === 'speed') {
      const rate = Math.max(0.25, Math.min(4.0, Number(value) || 1));
      currentPlaybackRate = rate;
      videos.forEach(vid => { vid.playbackRate = rate; });
      return reply({ ok: true, rate: v.playbackRate, loop: v.loop, muted: v.muted });
    }
    if (action === 'loop') {
      v.loop = !v.loop;
      return reply({ ok: true, rate: v.playbackRate, loop: v.loop, muted: v.muted });
    }
    if (action === 'boost') {
      const gainVal = Math.max(0.5, Math.min(3.0, Number(value) || 1));
      try {
        let entry = videoAudioBoostMap.get(v);
        if (!entry) {
          const Ctx = window.AudioContext || window.webkitAudioContext;
          const ctx = new Ctx();
          const src = ctx.createMediaElementSource(v);
          const gain = ctx.createGain();
          src.connect(gain);
          gain.connect(ctx.destination);
          entry = { ctx, gain };
          videoAudioBoostMap.set(v, entry);
        }
        if (entry.ctx.state === 'suspended') entry.ctx.resume();
        entry.gain.gain.value = gainVal;
      } catch {}
      return reply({ ok: true, boost: gainVal });
    }
    if (action === 'status') {
      const entry = videoAudioBoostMap.get(v);
      return reply({
        ok: true,
        hasVideo: true,
        rate: v.playbackRate || 1,
        loop: !!v.loop,
        paused: !!v.paused,
        duration: Number.isFinite(v.duration) ? Math.round(v.duration) : 0,
        currentTime: Math.round(v.currentTime || 0),
        boost: entry ? entry.gain.gain.value : 1
      });
    }
    return reply({ ok: true, rate: v.playbackRate });
  } catch (err) {
    return reply({ ok: false, error: err.message });
  }
});

