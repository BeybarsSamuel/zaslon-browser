/**
 * Zaslon Browser — Seçilebilir Çeviri Motoru & Hibrit Yerel Çevirici (translator.js)
 *
 * Desteklenen Motor Modları:
 *  - local_only    : Yalnızca Yerel NMT / Yerel Sunucu (127.0.0.1) / Çevrimdışı Sözlük (Sıfır İnternet)
 *  - local_server  : Yalnızca 127.0.0.1 Ollama veya LibreTranslate
 *  - lingva        : Açık Kaynak Lingva (Tor/Proxy uyumlu)
 *  - mymemory      : MyMemory API
 *  - google_gtx    : Google Translate GTX (Hızlı / Günlük Okuma — Tor sekmesinde ve gizli modda kilitli)
 *  - auto_private  : Hibrit Yerel -> Lingva -> MyMemory -> Sözlük (Asla Google GTX'e düşmez)
 *  - auto_fast     : Hibrit Yerel -> Google GTX -> Lingva -> MyMemory -> Sözlük (Tor sekmesinde auto_private'a iner)
 */

const { t } = require('../i18n/translations');
const { LocalTranslatorEngine } = require('./local-translator');
const { getUniformBrowserUserAgent } = require('../privacy/chromium-hardening');

const VALID_ENGINES = new Set([
  'local_only',
  'local_server',
  'lingva',
  'mymemory',
  'google_gtx',
  'auto_private',
  'auto_fast'
]);

const DEFAULT_LINGVA_INSTANCES = [
  'https://translate.plausibility.cloud',
  'https://lingva.lunar.icu',
  'https://lingva.ml'
];

class TranslatorService {
  constructor(options = {}) {
    this.fetchFn = options.fetchFn || globalThis.fetch;
    this.localEngine =
      options.localEngine ||
      new LocalTranslatorEngine({
        userDataPath: options.userDataPath || null,
        modelsDir: options.modelsDir || null,
        fetchFn: this.fetchFn
      });
    this.cache = new Map();
  }

  normalizeLang(code, isSource = false) {
    if (!code) return isSource ? 'auto' : 'tr';
    const c = String(code).toLowerCase().trim();
    if (isSource && (c === 'auto' || c === 'detect')) return 'auto';
    return c.slice(0, 8);
  }

  normalizeEngine(engine) {
    const clean = String(engine || 'auto_private').trim().toLowerCase();
    return VALID_ENGINES.has(clean) ? clean : 'auto_private';
  }

  resolveEffectivePolicy(opts = {}) {
    let engine = this.normalizeEngine(opts.engine);
    const routing = String(opts.routing || 'tab').toLowerCase();
    const isTorTab = Boolean(opts.isTorTab);
    const allowGoogle = opts.allowGoogle !== false && !isTorTab && routing !== 'offline';
    const routedVia = opts.routedVia || (routing === 'offline' ? 'offline' : isTorTab || routing === 'tor' ? 'tor' : 'direct');

    if (routing === 'offline') {
      engine = engine === 'local_server' ? 'local_server' : 'local_only';
    } else if (!allowGoogle && engine === 'auto_fast') {
      engine = 'auto_private';
    }

    return {
      engine,
      routing,
      isTorTab,
      allowGoogle,
      routedVia
    };
  }

  async fetchWithTimeout(url, opts = {}, timeoutMs = 6000, fetchOverride = null) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const fn = fetchOverride || this.fetchFn;
    try {
      const headers = {
        'User-Agent': getUniformBrowserUserAgent(),
        'Accept-Language': 'en-US,en;q=0.5',
        'Sec-GPC': '1',
        ...(opts.headers || {})
      };
      delete headers.Referer;
      delete headers.Origin;
      const res = await fn(url, {
        ...opts,
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        headers,
        signal: controller.signal
      });
      clearTimeout(timer);
      return res;
    } catch (err) {
      clearTimeout(timer);
      throw err;
    }
  }

  _buildLingvaList(customUrl) {
    const list = [];
    if (customUrl) {
      try {
        const parsed = new URL(String(customUrl).trim());
        if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
          list.push(parsed.toString().replace(/\/+$/, ''));
        }
      } catch {}
    }
    for (const u of DEFAULT_LINGVA_INSTANCES) {
      if (!list.includes(u)) list.push(u);
    }
    return list;
  }

  async tryLingva(text, sl, tl, opts = {}) {
    const instances = this._buildLingvaList(opts.lingvaUrl);
    const src = sl === 'auto' ? 'auto' : sl;
    for (const base of instances) {
      try {
        const url = `${base}/api/v1/${encodeURIComponent(src)}/${encodeURIComponent(tl)}/${encodeURIComponent(text)}`;
        const res = await this.fetchWithTimeout(
          url,
          { method: 'GET', headers: { Accept: 'application/json' } },
          4500,
          opts.fetchFn
        );
        if (!res.ok) continue;
        const data = await res.json();
        if (data && typeof data.translation === 'string' && data.translation.trim()) {
          return {
            ok: true,
            translatedText: data.translation,
            detectedSource: data.info?.detectedSource || src,
            provider: 'Lingva (Anonim)',
            engineUsed: 'lingva',
            privacyLevel: opts.routedVia === 'tor' ? 'tor' : 'clearnet-anonymous',
            routedVia: opts.routedVia || 'direct'
          };
        }
      } catch {}
    }
    return null;
  }

  async tryAnonymousGtx(text, sl, tl, opts = {}) {
    if (opts.allowGoogle === false) return null;
    try {
      const params = new URLSearchParams({
        client: 'gtx',
        sl: sl || 'auto',
        tl: tl || 'tr',
        dt: 't',
        q: text
      });
      const url = `https://translate.googleapis.com/translate_a/single?${params.toString()}`;
      const res = await this.fetchWithTimeout(
        url,
        { method: 'GET', headers: { Accept: 'application/json' } },
        5000,
        opts.fetchFn
      );
      if (!res.ok) return null;
      const data = await res.json();
      if (Array.isArray(data) && Array.isArray(data[0])) {
        const joined = data[0]
          .map(part => (Array.isArray(part) && typeof part[0] === 'string' ? part[0] : ''))
          .join('');
        if (joined.trim()) {
          return {
            ok: true,
            translatedText: joined,
            detectedSource: typeof data[2] === 'string' ? data[2] : sl,
            provider: t('translator.googleGtx'),
            engineUsed: 'google_gtx',
            privacyLevel: 'clearnet-google',
            routedVia: opts.routedVia || 'direct'
          };
        }
      }
    } catch {}
    return null;
  }

  async tryMyMemory(text, sl, tl, opts = {}) {
    if (text.length > 500) return null;
    try {
      const src = sl === 'auto' ? 'en' : sl;
      if (src === tl) {
        return {
          ok: true,
          translatedText: text,
          detectedSource: src,
          provider: 'MyMemory',
          engineUsed: 'mymemory',
          privacyLevel: opts.routedVia === 'tor' ? 'tor' : 'clearnet-anonymous',
          routedVia: opts.routedVia || 'direct'
        };
      }
      const url = `https://api.mymemory.translated.net/get?q=${encodeURIComponent(text)}&langpair=${encodeURIComponent(`${src}|${tl}`)}`;
      const res = await this.fetchWithTimeout(
        url,
        { method: 'GET', headers: { Accept: 'application/json' } },
        4500,
        opts.fetchFn
      );
      if (!res.ok) return null;
      const data = await res.json();
      const tr = data?.responseData?.translatedText;
      if (typeof tr === 'string' && tr.trim() && !tr.includes('MYMEMORY WARNING')) {
        return {
          ok: true,
          translatedText: tr,
          detectedSource: src,
          provider: 'MyMemory',
          engineUsed: 'mymemory',
          privacyLevel: opts.routedVia === 'tor' ? 'tor' : 'clearnet-anonymous',
          routedVia: opts.routedVia || 'direct'
        };
      }
    } catch {}
    return null;
  }

  async tryLocalNmt(textOrArray, sl, tl) {
    try {
      const res = await this.localEngine.translateWithNmt(textOrArray, sl, tl);
      if (res && res.ok) {
        return {
          ...res,
          routedVia: 'offline'
        };
      }
    } catch {}
    return null;
  }

  async tryLocalServer(textOrArray, sl, tl, localConfig = {}) {
    if (!localConfig || !localConfig.url) return null;
    return await this.localEngine.translateWithLocalServer(textOrArray, sl, tl, localConfig);
  }

  offlineFallback(text, sl, tl, strictNoMatch = false) {
    const d = this.localEngine.translateWithDictionary(text, sl, tl);
    if (strictNoMatch && d.matchedWords === 0) {
      return {
        ok: false,
        translatedText: '',
        error: t('translator.errNoLocalModel'),
        needsLocalModel: true,
        detectedSource: d.detectedSource,
        provider: t('translator.local'),
        engineUsed: 'offline_dict',
        privacyLevel: 'offline',
        routedVia: 'offline'
      };
    }
    return {
      ok: true,
      translatedText: d.translatedText,
      detectedSource: d.detectedSource,
      provider: t('translator.local'),
      engineUsed: 'offline_dict',
      privacyLevel: 'offline',
      routedVia: 'offline',
      needsLocalModel: d.matchedWords === 0
    };
  }

  _cacheKey(policy, sl, tl, raw) {
    return `${policy.engine}:${policy.routedVia}:${policy.allowGoogle ? 1 : 0}:${sl}:${tl}:${raw}`;
  }

  _saveCache(key, value) {
    if (!value || value.ok === false) return;
    if (this.cache.size > 600) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey) this.cache.delete(firstKey);
    }
    this.cache.set(key, value);
  }

  async translateText(body = {}, runtimeOpts = {}) {
    const raw = String(body.q || '').trim();
    if (!raw) return { ok: true, translatedText: '', provider: 'none', privacyLevel: 'offline' };

    const mergedOpts = { ...body, ...runtimeOpts };
    const sl = this.normalizeLang(body.source, true);
    const tl = this.normalizeLang(body.target, false);
    const policy = this.resolveEffectivePolicy(mergedOpts);
    const localConfig = mergedOpts.localConfig || {};
    const fetchOpts = {
      fetchFn: mergedOpts.fetchFn,
      lingvaUrl: mergedOpts.lingvaUrl,
      allowGoogle: policy.allowGoogle,
      routedVia: policy.routedVia
    };

    const key = this._cacheKey(policy, sl, tl, raw);
    if (this.cache.has(key)) {
      return this.cache.get(key);
    }

    if (policy.engine === 'google_gtx' && !policy.allowGoogle) {
      return {
        ok: false,
        blockedByTorLock: true,
        error: t('translator.errGoogleLocked'),
        provider: t('translator.locked'),
        privacyLevel: policy.routedVia === 'tor' ? 'tor' : 'offline',
        routedVia: policy.routedVia
      };
    }

    if (mergedOpts.torNotReadyError) {
      const needsNetwork =
        policy.engine === 'lingva' ||
        policy.engine === 'mymemory' ||
        policy.engine === 'google_gtx' ||
        (policy.engine === 'auto_private' || policy.engine === 'auto_fast');
      if (needsNetwork && policy.routedVia === 'tor') {
        // Yine de yerel NMT / yerel sunucu önce denenebilir; yoksa Tor kilidi döner
        const nmtOnly = await this.tryLocalNmt(raw, sl, tl);
        if (nmtOnly) {
          this._saveCache(key, nmtOnly);
          return nmtOnly;
        }
        return {
          ok: false,
          blockedByTorLock: true,
          error: mergedOpts.torNotReadyError,
          provider: t('translator.locked'),
          privacyLevel: 'tor',
          routedVia: 'tor'
        };
      }
    }

    let res = null;

    if (policy.engine === 'local_only') {
      res = await this.tryLocalNmt(raw, sl, tl);
      if (!res && localConfig.url) {
        try {
          res = await this.tryLocalServer(raw, sl, tl, localConfig);
        } catch {}
      }
      if (!res) {
        res = this.offlineFallback(raw, sl, tl, true);
      }
    } else if (policy.engine === 'local_server') {
      try {
        res = await this.tryLocalServer(raw, sl, tl, {
          ...localConfig,
          url: localConfig.url || (localConfig.type === 'ollama' ? 'http://127.0.0.1:11434' : 'http://127.0.0.1:5000')
        });
      } catch (err) {
        res = {
          ok: false,
          error: err.message,
          provider: t('translator.localServer'),
          privacyLevel: 'offline',
          routedVia: 'offline'
        };
      }
    } else if (policy.engine === 'lingva') {
      res = await this.tryLingva(raw, sl, tl, fetchOpts);
      if (!res) {
        res = {
          ok: false,
          error: t('translator.errProviderUnreach', { name: 'Lingva' }),
          provider: 'Lingva',
          privacyLevel: fetchOpts.routedVia === 'tor' ? 'tor' : 'clearnet-anonymous',
          routedVia: fetchOpts.routedVia
        };
      }
    } else if (policy.engine === 'mymemory') {
      res = await this.tryMyMemory(raw, sl, tl, fetchOpts);
      if (!res) {
        res = {
          ok: false,
          error: t('translator.errProviderUnreach', { name: 'MyMemory' }),
          provider: 'MyMemory',
          privacyLevel: fetchOpts.routedVia === 'tor' ? 'tor' : 'clearnet-anonymous',
          routedVia: fetchOpts.routedVia
        };
      }
    } else if (policy.engine === 'google_gtx') {
      res = await this.tryAnonymousGtx(raw, sl, tl, fetchOpts);
      if (!res) {
        res = {
          ok: false,
          error: t('translator.errProviderUnreach', { name: 'Google GTX' }),
          provider: 'Google GTX',
          privacyLevel: 'clearnet-google',
          routedVia: fetchOpts.routedVia
        };
      }
    } else if (policy.engine === 'auto_private') {
      res = await this.tryLocalNmt(raw, sl, tl);
      if (!res && localConfig.url) {
        try {
          res = await this.tryLocalServer(raw, sl, tl, localConfig);
        } catch {}
      }
      if (!res) res = await this.tryLingva(raw, sl, tl, fetchOpts);
      if (!res) res = await this.tryMyMemory(raw, sl, tl, fetchOpts);
      if (!res) res = this.offlineFallback(raw, sl, tl, false);
    } else {
      // auto_fast (günlük okuma; Tor sekmesinde policy otomatik auto_private olur)
      res = await this.tryLocalNmt(raw, sl, tl);
      if (!res && localConfig.url) {
        try {
          res = await this.tryLocalServer(raw, sl, tl, localConfig);
        } catch {}
      }
      if (!res) res = await this.tryAnonymousGtx(raw, sl, tl, fetchOpts);
      if (!res) res = await this.tryLingva(raw, sl, tl, fetchOpts);
      if (!res) res = await this.tryMyMemory(raw, sl, tl, fetchOpts);
      if (!res) res = this.offlineFallback(raw, sl, tl, false);
    }

    this._saveCache(key, res);
    return res;
  }

  async translateBatch(body = {}, runtimeOpts = {}) {
    const texts = body.texts;
    if (!Array.isArray(texts) || !texts.length) {
      return { ok: true, translations: [], provider: 'none', privacyLevel: 'offline' };
    }

    const mergedOpts = { ...body, ...runtimeOpts };
    const sl = this.normalizeLang(body.source, true);
    const tl = this.normalizeLang(body.target, false);
    const policy = this.resolveEffectivePolicy(mergedOpts);
    const localConfig = mergedOpts.localConfig || {};

    if (policy.engine === 'google_gtx' && !policy.allowGoogle) {
      return {
        ok: false,
        blockedByTorLock: true,
        translations: [],
        error: t('translator.errGoogleLocked')
      };
    }

    // Doğrudan Yerel NMT ile ayırıcı bozulmadan toplu çeviri (local_only, auto_private, auto_fast)
    if (policy.engine !== 'local_server' && policy.engine !== 'lingva' && policy.engine !== 'mymemory' && policy.engine !== 'google_gtx') {
      const nmtBatch = await this.tryLocalNmt(texts, sl, tl);
      if (nmtBatch && nmtBatch.ok) {
        return {
          ok: true,
          translations: nmtBatch.translations,
          provider: nmtBatch.provider,
          engineUsed: nmtBatch.engineUsed,
          privacyLevel: 'offline',
          routedVia: 'offline'
        };
      }
    }

    // Yalnızca yerel sunucu seçiliyse ayırıcı kullanmadan dizi olarak çalıştır
    if (policy.engine === 'local_server') {
      try {
        const srvBatch = await this.tryLocalServer(texts, sl, tl, {
          ...localConfig,
          url: localConfig.url || (localConfig.type === 'ollama' ? 'http://127.0.0.1:11434' : 'http://127.0.0.1:5000')
        });
        return {
          ok: true,
          translations: srvBatch.translations,
          provider: srvBatch.provider,
          engineUsed: 'local_server',
          privacyLevel: 'offline',
          routedVia: 'offline'
        };
      } catch (err) {
        return {
          ok: false,
          translations: [],
          error: err.message,
          provider: t('translator.localServer'),
          privacyLevel: 'offline',
          routedVia: 'offline'
        };
      }
    }

    if (policy.engine === 'local_only') {
      if (localConfig.url) {
        try {
          const srvBatch = await this.tryLocalServer(texts, sl, tl, localConfig);
          return {
            ok: true,
            translations: srvBatch.translations,
            provider: srvBatch.provider,
            engineUsed: 'local_server',
            privacyLevel: 'offline',
            routedVia: 'offline'
          };
        } catch {}
      }
      // Hiç NMT / yerel sunucu yoksa en azından anlamlı hata dön (İngilizce metni sessizce bırakma)
      const probe = this.offlineFallback(texts.slice(0, 5).join(' '), sl, tl, true);
      if (!probe.ok) {
        return {
          ok: false,
          translations: [],
          error: probe.error,
          needsLocalModel: true,
          provider: t('translator.local'),
          privacyLevel: 'offline',
          routedVia: 'offline'
        };
      }
    }

    if (mergedOpts.torNotReadyError && policy.routedVia === 'tor') {
      return {
        ok: false,
        blockedByTorLock: true,
        translations: [],
        error: mergedOpts.torNotReadyError
      };
    }

    const results = new Array(texts.length).fill('');
    let activeProvider = t('translator.dom');
    let activePrivacy = policy.routedVia === 'tor' ? 'tor' : 'clearnet-anonymous';

    const DELIM = '\n⟪ZSL⟫\n';
    const batches = [];
    let currentIndices = [];
    let currentTexts = [];
    let currentLen = 0;

    for (let i = 0; i < texts.length; i++) {
      const txt = String(texts[i] || '').trim();
      if (!txt) {
        results[i] = texts[i];
        continue;
      }
      const key = this._cacheKey(policy, sl, tl, txt);
      if (this.cache.has(key)) {
        const hit = this.cache.get(key);
        results[i] = hit.translatedText;
        if (hit.provider) activeProvider = hit.provider;
        if (hit.privacyLevel) activePrivacy = hit.privacyLevel;
        continue;
      }
      if (currentLen + txt.length > 2200 && currentTexts.length > 0) {
        batches.push({ indices: currentIndices, items: currentTexts });
        currentIndices = [];
        currentTexts = [];
        currentLen = 0;
      }
      currentIndices.push(i);
      currentTexts.push(txt);
      currentLen += txt.length + DELIM.length;
    }
    if (currentTexts.length > 0) {
      batches.push({ indices: currentIndices, items: currentTexts });
    }

    for (const batch of batches) {
      const joined = batch.items.join(DELIM);
      const trRes = await this.translateText({ q: joined, source: sl, target: tl }, mergedOpts);
      if (!trRes || trRes.ok === false) {
        return {
          ok: false,
          translations: [],
          error: trRes?.error || t('translator.errNoLocalModel'),
          blockedByTorLock: trRes?.blockedByTorLock,
          needsLocalModel: trRes?.needsLocalModel
        };
      }
      if (trRes.provider) activeProvider = trRes.provider;
      if (trRes.privacyLevel) activePrivacy = trRes.privacyLevel;

      const splitParts = String(trRes.translatedText || '').split(/\s*⟪\s*ZSL\s*⟫\s*/i);

      if (splitParts.length === batch.items.length) {
        for (let k = 0; k < batch.indices.length; k++) {
          const idx = batch.indices[k];
          const orig = batch.items[k];
          const translated = splitParts[k].trim() || orig;
          results[idx] = translated;
          this._saveCache(this._cacheKey(policy, sl, tl, orig), {
            ok: true,
            translatedText: translated,
            detectedSource: trRes.detectedSource || sl,
            provider: activeProvider,
            privacyLevel: activePrivacy,
            routedVia: policy.routedVia
          });
        }
      } else {
        for (let k = 0; k < batch.indices.length; k++) {
          const idx = batch.indices[k];
          const orig = batch.items[k];
          const single = await this.translateText({ q: orig, source: sl, target: tl }, mergedOpts);
          results[idx] = single?.translatedText || orig;
        }
      }
    }

    return {
      ok: true,
      translations: results,
      provider: activeProvider,
      privacyLevel: activePrivacy,
      routedVia: policy.routedVia
    };
  }
}

module.exports = {
  TranslatorService,
  VALID_ENGINES,
  DEFAULT_LINGVA_INSTANCES
};
