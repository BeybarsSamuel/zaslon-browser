/**
 * Zaslon Browser — Hibrit Yerel / Çevrimdışı Çeviri Motoru (local-translator.js)
 *
 * Katmanlar:
 *  1) İndirilebilir Çevrimdışı NMT (Bergamot WASM + Mozilla CDN SHA-256 doğrulamalı modeller)
 *  2) Yerel Sunucu Bağlayıcısı (Ollama / LibreTranslate — yalnızca 127.0.0.1 / ::1 loopback)
 *  3) Genişletilmiş Çevrimdışı Sözlük (model ve sunucu yokken temel kelime yedeği)
 */

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const { pathToFileURL } = require('node:url');

const MOZILLA_MODELS_API =
  'https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/translations-models-v2/records';
const MOZILLA_CDN_BASE = 'https://firefox-settings-attachments.cdn.mozilla.net/';

const CURATED_PAIRS = [
  { from: 'en', to: 'tr', label: 'English → Türkçe' },
  { from: 'tr', to: 'en', label: 'Türkçe → English' },
  { from: 'en', to: 'de', label: 'English → Deutsch' },
  { from: 'de', to: 'en', label: 'Deutsch → English' },
  { from: 'en', to: 'ru', label: 'English → Русский' },
  { from: 'ru', to: 'en', label: 'Русский → English' },
  { from: 'en', to: 'fr', label: 'English → Français' },
  { from: 'fr', to: 'en', label: 'Français → English' },
  { from: 'en', to: 'es', label: 'English → Español' },
  { from: 'es', to: 'en', label: 'Español → English' },
  { from: 'en', to: 'ar', label: 'English → العربية' },
  { from: 'ar', to: 'en', label: 'العربية → English' },
  { from: 'en', to: 'it', label: 'English → Italiano' },
  { from: 'it', to: 'en', label: 'Italiano → English' },
  { from: 'en', to: 'pt', label: 'English → Português' },
  { from: 'pt', to: 'en', label: 'Português → English' },
  { from: 'en', to: 'nl', label: 'English → Nederlands' },
  { from: 'nl', to: 'en', label: 'Nederlands → English' },
  { from: 'en', to: 'pl', label: 'English → Polski' },
  { from: 'pl', to: 'en', label: 'Polski → English' },
  { from: 'en', to: 'uk', label: 'English → Українська' },
  { from: 'uk', to: 'en', label: 'Українська → English' },
  { from: 'en', to: 'ja', label: 'English → 日本語' },
  { from: 'ja', to: 'en', label: '日本語 → English' }
];

const OFFLINE_DICT_EN_TR = {
  hello: 'merhaba',
  world: 'dünya',
  welcome: 'hoş geldiniz',
  search: 'ara',
  settings: 'ayarlar',
  privacy: 'gizlilik',
  security: 'güvenlik',
  download: 'indir',
  upload: 'yükle',
  login: 'giriş yap',
  logout: 'çıkış yap',
  sign: 'imzala',
  home: 'ana sayfa',
  news: 'haberler',
  article: 'makale',
  read: 'oku',
  more: 'daha fazla',
  about: 'hakkında',
  contact: 'iletişim',
  free: 'ücretsiz',
  open: 'açık',
  source: 'kaynak',
  browser: 'tarayıcı',
  error: 'hata',
  page: 'sayfa',
  not: 'değil',
  found: 'bulunamadı',
  close: 'kapat',
  save: 'kaydet',
  cancel: 'iptal',
  delete: 'sil',
  edit: 'düzenle',
  copy: 'kopyala',
  paste: 'yapıştır',
  file: 'dosya',
  folder: 'klasör',
  document: 'belge',
  data: 'veri',
  network: 'ağ',
  server: 'sunucu',
  local: 'yerel',
  offline: 'çevrimdışı',
  online: 'çevrimiçi',
  encrypted: 'şifreli',
  password: 'şifre',
  key: 'anahtar',
  user: 'kullanıcı',
  account: 'hesap',
  profile: 'profil',
  language: 'dil',
  translate: 'çevir',
  translation: 'çeviri',
  help: 'yardım',
  support: 'destek',
  update: 'güncelle',
  install: 'kur',
  remove: 'kaldır',
  enable: 'etkinleştir',
  disable: 'devre dışı bırak',
  enabled: 'etkin',
  disabled: 'devre dışı',
  active: 'aktif',
  status: 'durum',
  connection: 'bağlantı',
  connected: 'bağlı',
  disconnected: 'bağlantı kesildi',
  warning: 'uyarı',
  success: 'başarılı',
  failed: 'başarısız',
  loading: 'yükleniyor',
  please: 'lütfen',
  wait: 'bekleyin',
  confirm: 'onayla',
  continue: 'devam et',
  back: 'geri',
  next: 'ileri',
  start: 'başlat',
  stop: 'durdur',
  reset: 'sıfırla',
  clear: 'temizle',
  cookie: 'çerez',
  cookies: 'çerezler',
  history: 'geçmiş',
  bookmark: 'yer imi',
  bookmarks: 'yer imleri',
  tab: 'sekme',
  tabs: 'sekmeler',
  window: 'pencere',
  link: 'bağlantı',
  image: 'görsel',
  video: 'video',
  audio: 'ses',
  text: 'metin',
  title: 'başlık',
  description: 'açıklama',
  name: 'ad',
  date: 'tarih',
  time: 'zaman',
  today: 'bugün',
  new: 'yeni',
  old: 'eski',
  fast: 'hızlı',
  slow: 'yavaş',
  safe: 'güvenli',
  private: 'özel',
  anonymous: 'anonim',
  block: 'engelle',
  blocked: 'engellendi',
  allow: 'izin ver',
  allowed: 'izin verildi',
  tracker: 'izleyici',
  ad: 'reklam',
  ads: 'reklamlar',
  permission: 'izin',
  access: 'erişim',
  denied: 'reddedildi',
  yes: 'evet',
  no: 'hayır',
  true: 'doğru',
  false: 'yanlış',
  information: 'bilgi',
  details: 'ayrıntılar',
  report: 'rapor',
  system: 'sistem',
  version: 'sürüm',
  license: 'lisans',
  terms: 'koşullar',
  policy: 'politika',
  right: 'hak',
  rights: 'haklar',
  human: 'insan'
};

const OFFLINE_DICT_TR_EN = Object.fromEntries(
  Object.entries(OFFLINE_DICT_EN_TR)
    .filter(([, tr]) => !tr.includes(' '))
    .map(([en, tr]) => [tr, en])
);

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);

function sanitizeLangTag(code) {
  const clean = String(code || '')
    .trim()
    .replace(/[^a-zA-Z0-9-]/g, '')
    .slice(0, 12);
  return clean || 'en';
}

function pairId(from, to) {
  return `${sanitizeLangTag(from).toLowerCase()}->${sanitizeLangTag(to).toLowerCase()}`;
}

function pairDirName(from, to) {
  return `${sanitizeLangTag(from).toLowerCase()}_${sanitizeLangTag(to).toLowerCase()}`;
}

function isLoopbackUrl(rawUrl) {
  try {
    const parsed = new URL(String(rawUrl || '').trim());
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { ok: false, error: 'Yalnızca HTTP/HTTPS yerel adresi desteklenir' };
    }
    if (!LOOPBACK_HOSTS.has(parsed.hostname.toLowerCase())) {
      return {
        ok: false,
        error: `Yerel sunucu modunda güvenlik nedeniyle yalnızca loopback (127.0.0.1 / localhost / ::1) izinlidir: ${parsed.hostname}`
      };
    }
    return { ok: true, url: parsed.toString().replace(/\/+$/, '') };
  } catch {
    return { ok: false, error: 'Geçersiz yerel sunucu adresi' };
  }
}

function detectSourceLangOffline(text, targetLang = 'tr', availableSources = []) {
  const sample = String(text || '').trim();
  const tl = sanitizeLangTag(targetLang).toLowerCase();
  if (!sample) return tl === 'en' ? 'tr' : 'en';

  if (/[çğıöşüÇĞİÖŞÜ]/.test(sample)) return 'tr';
  if (/[\u0400-\u04FF]/.test(sample)) {
    if (/[іїєґІЇЄҐ]/.test(sample)) return 'uk';
    return 'ru';
  }
  if (/[\u0600-\u06FF]/.test(sample)) return 'ar';
  if (/[\u3040-\u30FF\u4E00-\u9FAF]/.test(sample)) return 'ja';
  if (/[äöüßÄÖÜ]/.test(sample)) return 'de';
  if (/[éèêëàâçîïôûùüÿœ]/i.test(sample)) return 'fr';
  if (/[áéíóúñü¿¡]/i.test(sample)) return 'es';

  const lowerWords = sample.toLowerCase().split(/\s+/).slice(0, 30);
  const trHints = new Set(['ve', 'bir', 'bu', 'için', 'ile', 'gibi', 'olan', 'ama', 'çok', 'daha', 'nasıl', 'merhaba']);
  const deHints = new Set(['der', 'die', 'das', 'und', 'ist', 'nicht', 'ein', 'für', 'mit', 'auf']);
  const frHints = new Set(['le', 'la', 'les', 'et', 'est', 'dans', 'pour', 'une', 'des', 'avec']);
  const esHints = new Set(['el', 'la', 'los', 'las', 'y', 'es', 'para', 'con', 'una', 'que']);

  let trScore = 0, deScore = 0, frScore = 0, esScore = 0;
  for (const w of lowerWords) {
    if (trHints.has(w)) trScore++;
    if (deHints.has(w)) deScore++;
    if (frHints.has(w)) frScore++;
    if (esHints.has(w)) esScore++;
  }
  if (trScore >= 2 && trScore >= deScore) return 'tr';
  if (deScore >= 2 && deScore > trScore) return 'de';
  if (frScore >= 2) return 'fr';
  if (esScore >= 2) return 'es';

  if (tl !== 'en') return 'en';
  if (Array.isArray(availableSources) && availableSources.length) {
    const nonEn = availableSources.find(s => s !== 'en');
    if (nonEn) return nonEn;
  }
  return 'tr';
}

class LocalTranslatorEngine {
  constructor(options = {}) {
    this.userDataPath = options.userDataPath || null;
    this.modelsDir = options.modelsDir || (this.userDataPath ? path.join(this.userDataPath, 'models', 'translation') : null);
    this.fetchFn = options.fetchFn || globalThis.fetch;
    this.manifestPath = this.modelsDir ? path.join(this.modelsDir, 'manifest.json') : null;
    this.workerShimPath = this._resolveWorkerShimPath();
    this._bergamotMod = null;
    this._translator = null;
    this._translatorInitPromise = null;
    this._activeDownloads = new Map();
  }

  _resolveWorkerShimPath() {
    let p = path.join(__dirname, 'bergamot-worker-shim.cjs');
    if (p.includes('app.asar') && !p.includes('app.asar.unpacked')) {
      const unpacked = p.replace('app.asar', 'app.asar.unpacked');
      if (fs.existsSync(unpacked)) p = unpacked;
    }
    return p;
  }

  _readManifest() {
    if (!this.manifestPath || !fs.existsSync(this.manifestPath)) {
      return { version: 1, pairs: {} };
    }
    try {
      const parsed = JSON.parse(fs.readFileSync(this.manifestPath, 'utf8'));
      if (parsed && typeof parsed === 'object' && parsed.pairs) return parsed;
    } catch {}
    return { version: 1, pairs: {} };
  }

  _writeManifest(manifest) {
    if (!this.manifestPath || !this.modelsDir) return;
    fs.mkdirSync(this.modelsDir, { recursive: true });
    fs.writeFileSync(this.manifestPath, JSON.stringify(manifest, null, 2), 'utf8');
  }

  getInstalledPairs() {
    const manifest = this._readManifest();
    const out = [];
    for (const [id, entry] of Object.entries(manifest.pairs || {})) {
      if (!entry || !entry.dir || !entry.files || !entry.files.model) continue;
      const modelPath = path.join(this.modelsDir, entry.dir, entry.files.model.fileName);
      if (fs.existsSync(modelPath)) {
        out.push({
          id,
          from: entry.from,
          to: entry.to,
          totalBytes: entry.totalBytes || 0,
          installedAt: entry.installedAt || 0
        });
      }
    }
    return out;
  }

  getModelsStatus() {
    const installed = this.getInstalledPairs();
    const installedMap = new Map(installed.map(p => [p.id, p]));
    const pairs = CURATED_PAIRS.map(p => {
      const id = pairId(p.from, p.to);
      const hit = installedMap.get(id);
      return {
        id,
        from: p.from,
        to: p.to,
        label: p.label,
        installed: !!hit,
        totalBytes: hit ? hit.totalBytes : 0,
        installedAt: hit ? hit.installedAt : 0,
        downloading: this._activeDownloads.has(id)
      };
    });
    return {
      modelsDir: this.modelsDir || '',
      installedPairs: installed.map(x => x.id),
      pairs
    };
  }

  canTranslateNmt(from, to) {
    const f = sanitizeLangTag(from).toLowerCase();
    const t = sanitizeLangTag(to).toLowerCase();
    if (f === t) return true;
    const installed = new Set(this.getInstalledPairs().map(p => p.id));
    if (installed.has(pairId(f, t))) return true;
    if (f !== 'en' && t !== 'en' && installed.has(pairId(f, 'en')) && installed.has(pairId('en', t))) {
      return true;
    }
    return false;
  }

  async _resetWorker() {
    if (this._translator) {
      try {
        this._translator.delete();
      } catch {}
      this._translator = null;
      this._translatorInitPromise = null;
    }
  }

  async _ensureTranslator() {
    if (this._translator) return this._translator;
    if (this._translatorInitPromise) return this._translatorInitPromise;

    this._translatorInitPromise = (async () => {
      if (!this._bergamotMod) {
        let modPath = require.resolve('@mkljczk/bergamot-translator/translator.js');
        if (modPath.includes('app.asar') && !modPath.includes('app.asar.unpacked')) {
          const unpacked = modPath.replace('app.asar', 'app.asar.unpacked');
          if (fs.existsSync(unpacked)) modPath = unpacked;
        }
        this._bergamotMod = await import(pathToFileURL(modPath).href);
      }

      const { BatchTranslator, TranslatorBacking } = this._bergamotMod;
      const modelsDir = this.modelsDir;
      const selfRef = this;
      const workerHref = pathToFileURL(this.workerShimPath).href;

      class LocalDiskBacking extends TranslatorBacking {
        async loadModelRegistry() {
          const manifest = selfRef._readManifest();
          return Object.values(manifest.pairs || {}).map(entry => ({
            from: entry.from,
            to: entry.to,
            files: entry.files
          }));
        }

        async loadTranslationModel({ from, to }) {
          const manifest = selfRef._readManifest();
          const entry = manifest.pairs?.[pairId(from, to)];
          if (!entry) {
            throw new Error(`Yerel model kurulu değil: ${from} -> ${to}`);
          }
          const readPart = async part => {
            const info = entry.files[part];
            if (!info || !info.fileName) return null;
            const fullPath = path.join(modelsDir, entry.dir, info.fileName);
            const buf = await fsp.readFile(fullPath);
            if (info.sha256) {
              const actual = crypto.createHash('sha256').update(buf).digest('hex');
              if (actual !== info.sha256) {
                throw new Error(`Model bütünlük doğrulaması başarısız: ${info.fileName}`);
              }
            }
            return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
          };

          const [model, lex, vocab, srcvocab, trgvocab, qualityModel] = await Promise.all([
            readPart('model'),
            readPart('lex'),
            readPart('vocab'),
            readPart('srcvocab'),
            readPart('trgvocab'),
            readPart('qualityModel')
          ]);

          if (!model || !lex) {
            throw new Error(`Eksik yerel model dosyası (${from}->${to})`);
          }
          const vocabs = vocab ? [vocab] : srcvocab && trgvocab ? [srcvocab, trgvocab] : [];
          if (!vocabs.length) {
            throw new Error(`Eksik vocab dosyası (${from}->${to})`);
          }

          const config = {};
          if (entry.files.model.fileName.endsWith('intgemm8.bin')) {
            config['gemm-precision'] = 'int8shiftAll';
          }
          return { model, shortlist: lex, vocabs, qualityModel, config };
        }
      }

      const backing = new LocalDiskBacking({ workerUrl: workerHref, pivotLanguage: 'en' });
      this._translator = new BatchTranslator(
        { workerUrl: workerHref, pivotLanguage: 'en', workers: 1, batchSize: 16 },
        backing
      );
      return this._translator;
    })();

    try {
      return await this._translatorInitPromise;
    } catch (err) {
      this._translatorInitPromise = null;
      throw err;
    }
  }

  async translateWithNmt(textsOrText, source = 'auto', target = 'tr') {
    const installed = this.getInstalledPairs();
    if (!installed.length) return null;

    const tl = sanitizeLangTag(target).toLowerCase();
    const isArray = Array.isArray(textsOrText);
    const items = isArray ? textsOrText : [String(textsOrText || '')];
    const sampleText = items.slice(0, 5).join(' ');

    let sl = String(source || 'auto').toLowerCase().trim();
    if (sl === 'auto' || sl === 'detect') {
      sl = detectSourceLangOffline(sampleText, tl, installed.map(p => p.from));
    } else {
      sl = sanitizeLangTag(sl).toLowerCase();
    }

    if (sl === tl) {
      return {
        ok: true,
        translations: items,
        translatedText: items[0] || '',
        detectedSource: sl,
        provider: 'Yerel NMT (Offline)',
        engineUsed: 'local_nmt',
        privacyLevel: 'offline'
      };
    }

    if (!this.canTranslateNmt(sl, tl)) {
      return null;
    }

    const translator = await this._ensureTranslator();
    const translatedItems = await Promise.all(
      items.map(async item => {
        const clean = String(item || '');
        if (!clean.trim()) return clean;
        const out = await translator.translate({ from: sl, to: tl, text: clean, html: false });
        return out?.target?.text || clean;
      })
    );

    return {
      ok: true,
      translations: translatedItems,
      translatedText: translatedItems[0] || '',
      detectedSource: sl,
      provider: 'Yerel NMT (Offline)',
      engineUsed: 'local_nmt',
      privacyLevel: 'offline'
    };
  }

  async installModelPair(pair, opts = {}) {
    const [rawFrom, rawTo] = String(pair || '').split('->');
    const from = sanitizeLangTag(rawFrom).toLowerCase();
    const to = sanitizeLangTag(rawTo).toLowerCase();
    const id = pairId(from, to);

    if (!from || !to || from === to) {
      return { ok: false, error: 'Geçersiz dil çifti' };
    }
    if (!this.modelsDir) {
      return { ok: false, error: 'Model dizini tanımlı değil' };
    }
    if (this._activeDownloads.has(id)) {
      return await this._activeDownloads.get(id);
    }

    const fetchFn = opts.fetchFn || this.fetchFn || globalThis.fetch;
    const onProgress = typeof opts.onProgress === 'function' ? opts.onProgress : () => {};

    const job = (async () => {
      try {
        onProgress({ pair: id, pct: 5, stage: 'registry' });
        const qUrl = `${MOZILLA_MODELS_API}?sourceLanguage=${encodeURIComponent(from)}&targetLanguage=${encodeURIComponent(to)}`;
        const recRes = await fetchFn(qUrl, {
          method: 'GET',
          credentials: 'omit',
          headers: { Accept: 'application/json' }
        });
        if (!recRes.ok) {
          throw new Error(`Mozilla model kataloğuna erişilemedi (HTTP ${recRes.status})`);
        }
        const recJson = await recRes.json();
        let records = (recJson.data || []).filter(
          d => d.sourceLanguage === from && d.targetLanguage === to
        );
        if (!records.length) {
          throw new Error(`Mozilla kataloğunda ${id} modeli bulunamadı`);
        }

        // 'tiny' mimarisi varsa tercih et; yoksa en yüksek sürümü al
        const hasTiny = records.some(r => r.architecture === 'tiny');
        if (hasTiny) {
          const filtered = records.filter(r => !r.architecture || r.architecture === 'tiny');
          if (filtered.some(r => r.fileType === 'model')) records = filtered;
        }

        const pickedByType = new Map();
        for (const rec of records) {
          const ft = rec.fileType;
          if (!ft || !rec.attachment?.location) continue;
          const prev = pickedByType.get(ft);
          if (!prev || Number(rec.last_modified || 0) > Number(prev.last_modified || 0)) {
            pickedByType.set(ft, rec);
          }
        }

        const requiredRecords = [...pickedByType.values()].filter(r =>
          ['model', 'lex', 'vocab', 'srcvocab', 'trgvocab', 'qualityModel'].includes(r.fileType)
        );
        if (!pickedByType.has('model') || !pickedByType.has('lex')) {
          throw new Error(`Eksik model metadata kayıtları (${id})`);
        }

        const dirName = pairDirName(from, to);
        const pairPath = path.join(this.modelsDir, dirName);
        await fsp.mkdir(pairPath, { recursive: true });

        const savedFiles = {};
        let totalBytes = 0;

        for (let idx = 0; idx < requiredRecords.length; idx++) {
          const rec = requiredRecords[idx];
          const pct = Math.round(15 + (idx / requiredRecords.length) * 75);
          onProgress({ pair: id, pct, stage: 'downloading', file: rec.name });

          const dlUrl = rec.attachment.location.startsWith('http')
            ? rec.attachment.location
            : `${MOZILLA_CDN_BASE}${rec.attachment.location.replace(/^\/+/, '')}`;

          // Google sunucularına yönlenmeyi kesin engelle
          const parsedUrl = new URL(dlUrl);
          if (parsedUrl.hostname.includes('google') || parsedUrl.hostname.includes('gstatic')) {
            throw new Error(`Güvenlik politikası: Google CDN reddedildi (${parsedUrl.hostname})`);
          }

          const res = await fetchFn(dlUrl, { method: 'GET', credentials: 'omit' });
          if (!res.ok) {
            throw new Error(`Model dosyası indirilemedi (${rec.name}: HTTP ${res.status})`);
          }
          const compBuf = Buffer.from(await res.arrayBuffer());
          if (rec.attachment.hash) {
            const compHash = crypto.createHash('sha256').update(compBuf).digest('hex');
            if (compHash !== rec.attachment.hash) {
              throw new Error(`SHA-256 doğrulama hatası (sıkıştırılmış): ${rec.name}`);
            }
          }

          const rawBuf = rec.attachment.location.endsWith('.zst')
            ? zlib.zstdDecompressSync(compBuf)
            : compBuf;

          const decompHash = crypto.createHash('sha256').update(rawBuf).digest('hex');
          if (rec.decompressedHash && decompHash !== rec.decompressedHash) {
            throw new Error(`SHA-256 doğrulama hatası (açılmış): ${rec.name}`);
          }

          const safeName = path.basename(rec.name).replace(/[^a-zA-Z0-9._-]/g, '_');
          await fsp.writeFile(path.join(pairPath, safeName), rawBuf);
          savedFiles[rec.fileType] = {
            fileName: safeName,
            sha256: decompHash,
            bytes: rawBuf.length
          };
          totalBytes += rawBuf.length;
        }

        const manifest = this._readManifest();
        manifest.pairs[id] = {
          from,
          to,
          dir: dirName,
          files: savedFiles,
          totalBytes,
          installedAt: Date.now()
        };
        this._writeManifest(manifest);
        await this._resetWorker();

        onProgress({ pair: id, pct: 100, stage: 'done' });
        return { ok: true, pair: id, totalBytes, status: this.getModelsStatus() };
      } catch (err) {
        onProgress({ pair: id, pct: 0, stage: 'error', error: err.message });
        return { ok: false, pair: id, error: err.message, status: this.getModelsStatus() };
      } finally {
        this._activeDownloads.delete(id);
      }
    })();

    this._activeDownloads.set(id, job);
    return await job;
  }

  async deleteModelPair(pair) {
    const [rawFrom, rawTo] = String(pair || '').split('->');
    const id = pairId(rawFrom, rawTo);
    const manifest = this._readManifest();
    const entry = manifest.pairs?.[id];
    if (entry && entry.dir && this.modelsDir) {
      try {
        await fsp.rm(path.join(this.modelsDir, entry.dir), { recursive: true, force: true });
      } catch {}
    }
    if (manifest.pairs && id in manifest.pairs) {
      delete manifest.pairs[id];
      this._writeManifest(manifest);
    }
    await this._resetWorker();
    return { ok: true, pair: id, status: this.getModelsStatus() };
  }

  async translateWithLocalServer(textsOrText, sl, tl, serverCfg = {}) {
    const check = isLoopbackUrl(serverCfg.url || (serverCfg.type === 'ollama' ? 'http://127.0.0.1:11434' : 'http://127.0.0.1:5000'));
    if (!check.ok) {
      throw new Error(check.error);
    }

    const baseUrl = check.url;
    const type = serverCfg.type === 'ollama' ? 'ollama' : 'libretranslate';
    const isArray = Array.isArray(textsOrText);
    const items = isArray ? textsOrText : [String(textsOrText || '')];
    const loopFetch = serverCfg.fetchFn || globalThis.fetch;

    if (type === 'libretranslate') {
      const translatedItems = [];
      for (const item of items) {
        const clean = String(item || '');
        if (!clean.trim()) {
          translatedItems.push(clean);
          continue;
        }
        const res = await loopFetch(`${baseUrl}/translate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
          body: JSON.stringify({
            q: clean,
            source: sl === 'auto' ? 'auto' : sl,
            target: tl,
            format: 'text'
          }),
          signal: AbortSignal.timeout(12000)
        });
        if (!res.ok) {
          throw new Error(`LibreTranslate yanıt vermedi (HTTP ${res.status})`);
        }
        const data = await res.json();
        if (typeof data?.translatedText !== 'string') {
          throw new Error('Geçersiz LibreTranslate yanıtı');
        }
        translatedItems.push(data.translatedText);
      }
      return {
        ok: true,
        translations: translatedItems,
        translatedText: translatedItems[0] || '',
        detectedSource: sl,
        provider: 'LibreTranslate (127.0.0.1)',
        engineUsed: 'local_server',
        privacyLevel: 'offline'
      };
    }

    // Ollama (/api/generate)
    const model = String(serverCfg.model || 'qwen2.5:3b').trim() || 'qwen2.5:3b';
    const translatedItems = [];
    for (const item of items) {
      const clean = String(item || '');
      if (!clean.trim()) {
        translatedItems.push(clean);
        continue;
      }
      const prompt = `Translate the following text ${sl && sl !== 'auto' ? `from ${sl} ` : ''}to ${tl}. Output ONLY the translated text without explanations or quotes:\n\n${clean}`;
      const res = await loopFetch(`${baseUrl}/api/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ model, prompt, stream: false }),
        signal: AbortSignal.timeout(25000)
      });
      if (!res.ok) {
        throw new Error(`Ollama yanıt vermedi (HTTP ${res.status})`);
      }
      const data = await res.json();
      const out = typeof data?.response === 'string' ? data.response.trim() : '';
      if (!out) throw new Error('Ollama boş yanıt döndürdü');
      translatedItems.push(out);
    }

    return {
      ok: true,
      translations: translatedItems,
      translatedText: translatedItems[0] || '',
      detectedSource: sl,
      provider: `Ollama · ${model} (127.0.0.1)`,
      engineUsed: 'local_server',
      privacyLevel: 'offline'
    };
  }

  translateWithDictionary(text, sl, tl) {
    const raw = String(text || '');
    const dict =
      tl === 'tr'
        ? OFFLINE_DICT_EN_TR
        : tl === 'en' && (sl === 'tr' || sl === 'auto')
          ? OFFLINE_DICT_TR_EN
          : null;

    if (!dict) {
      return {
        translatedText: raw,
        detectedSource: sl || 'auto',
        matchedWords: 0,
        engineUsed: 'offline_dict',
        privacyLevel: 'offline'
      };
    }

    let matchedWords = 0;
    const replaced = raw.replace(/\p{L}+/gu, word => {
      const lower = word.toLowerCase();
      if (dict[lower]) {
        matchedWords++;
        const trWord = dict[lower];
        return word[0] === word[0].toUpperCase()
          ? trWord[0].toUpperCase() + trWord.slice(1)
          : trWord;
      }
      return word;
    });

    return {
      translatedText: replaced,
      detectedSource: sl === 'auto' ? (tl === 'tr' ? 'en' : 'tr') : sl,
      matchedWords,
      engineUsed: 'offline_dict',
      privacyLevel: 'offline'
    };
  }

  async destroy() {
    await this._resetWorker();
  }
}

module.exports = {
  LocalTranslatorEngine,
  CURATED_PAIRS,
  OFFLINE_DICT_EN_TR,
  OFFLINE_DICT_TR_EN,
  isLoopbackUrl,
  detectSourceLangOffline
};
