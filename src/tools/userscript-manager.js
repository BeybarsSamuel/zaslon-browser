/**
 * Zaslon Browser — Faz 4: Hafif UserScript Motoru (userscript-manager.js)
 *
 * Tampermonkey / Violentmonkey benzeri eklentisiz .user.js betik yöneticisi.
 * - // ==UserScript== meta başlıklarını (@name, @match, @include, @exclude, @run-at) ayrıştırır.
 * - GM_addStyle, GM_setValue, GM_getValue, GM_deleteValue, GM_log yardımcı API'lerini sağlar.
 * - 4 yerleşik gizlilik/kullanılabilirlik betiği ile hazır gelir; kullanıcı kendi JS/CSS kodlarını ekleyebilir.
 */

const fs = require('fs');
const path = require('path');
const { t } = require('../i18n/translations');

const BUILTIN_I18N_KEYS = {
  'builtin-yt-clean': ['us.ytClean.name', 'us.ytClean.desc'],
  'builtin-copy-unlock': ['us.copyUnlock.name', 'us.copyUnlock.desc'],
  'builtin-redirect-bypass': ['us.redirectBypass.name', 'us.redirectBypass.desc'],
  'builtin-autoplay-stopper': ['us.autoplayStop.name', 'us.autoplayStop.desc']
};

const BUILTIN_SCRIPTS = [
  {
    id: 'builtin-yt-clean',
    builtin: true,
    enabled: true,
    name: 'YouTube Shorts & Algoritma Temizleyici',
    version: '1.2',
    description: 'YouTube ana sayfasındaki Shorts raflarını, anket kutularını ve dikkat dağıtıcı öneri raflarını gizler.',
    matches: ['*://*.youtube.com/*'],
    excludes: [],
    runAt: 'document-end',
    code: `// ==UserScript==
// @name         YouTube Shorts & Algoritma Temizleyici
// @match        *://*.youtube.com/*
// @run-at       document-end
// ==/UserScript==

GM_addStyle(\`
  ytd-rich-shelf-renderer[is-shorts],
  ytd-reel-shelf-renderer,
  ytd-mini-guide-entry-renderer[aria-label="Shorts"],
  ytd-guide-entry-renderer a[title="Shorts"],
  ytd-statement-banner-renderer,
  ytd-Clarification-renderer,
  tp-yt-paper-dialog.ytd-popup-container:has(yt-mealbar-promo-renderer) {
    display: none !important;
  }
\`);`
  },
  {
    id: 'builtin-copy-unlock',
    builtin: true,
    enabled: false,
    name: 'Sağ Tık & Metin Kopyalama Kilidi Açıcı',
    version: '1.1',
    description: 'Sitelerin metin seçmeyi (user-select: none), kopyalamayı (Ctrl+C) ve sağ tıklamayı engellemesini kaldırır.',
    matches: ['*://*/*'],
    excludes: [],
    runAt: 'document-end',
    code: `// ==UserScript==
// @name         Sağ Tık & Metin Kopyalama Kilidi Açıcı
// @match        *://*/*
// @run-at       document-end
// ==/UserScript==

GM_addStyle(\`
  *, *::before, *::after {
    -webkit-user-select: text !important;
    user-select: text !important;
  }
\`);

['copy', 'cut', 'contextmenu', 'selectstart', 'dragstart'].forEach(ev => {
  window.addEventListener(ev, e => e.stopPropagation(), true);
});`
  },
  {
    id: 'builtin-redirect-bypass',
    builtin: true,
    enabled: true,
    name: 'Takipçi Yönlendirme (Redirect) Atlayıcı',
    version: '1.3',
    description: 'YouTube, Reddit, Steam, Facebook ve Instagram üzerindeki ara yönlendirme tuzaklarını doğrudan hedef linke çevirir.',
    matches: ['*://*/*'],
    excludes: [],
    runAt: 'document-idle',
    code: `// ==UserScript==
// @name         Takipçi Yönlendirme (Redirect) Atlayıcı
// @match        *://*/*
// @run-at       document-idle
// ==/UserScript==

function cleanRedirectLinks() {
  document.querySelectorAll('a[href]').forEach(a => {
    try {
      const u = new URL(a.href, location.href);
      const host = u.hostname.replace(/^www\\./, '').toLowerCase();
      let target = null;
      if (host === 'youtube.com' && u.pathname === '/redirect') target = u.searchParams.get('q');
      else if (host === 'out.reddit.com') target = u.searchParams.get('url');
      else if (host === 'steamcommunity.com' && u.pathname.startsWith('/linkfilter')) target = u.searchParams.get('url') || u.searchParams.get('u');
      else if ((host === 'l.facebook.com' || host === 'lm.facebook.com') && u.pathname === '/l.php') target = u.searchParams.get('u');
      else if (host === 'l.instagram.com') target = u.searchParams.get('u');
      if (target && /^https?:\\/\\//i.test(target)) {
        a.href = target;
        a.rel = 'noopener noreferrer';
      }
    } catch {}
  });
}

cleanRedirectLinks();
new MutationObserver(cleanRedirectLinks).observe(document.documentElement, { childList: true, subtree: true });`
  },
  {
    id: 'builtin-autoplay-stopper',
    builtin: true,
    enabled: false,
    name: 'Haber Siteleri Otomatik Video Durdurucu',
    version: '1.0',
    description: 'Haber ve blog sitelerinde kendi kendine başlayan videoları kullanıcı tıklayana kadar duraklatır.',
    matches: ['*://*/*'],
    excludes: ['*://*.youtube.com/*', '*://youtu.be/*', '*://*.twitch.tv/*'],
    runAt: 'document-end',
    code: `// ==UserScript==
// @name         Haber Siteleri Otomatik Video Durdurucu
// @match        *://*/*
// @exclude      *://*.youtube.com/*
// @run-at       document-end
// ==/UserScript==

document.querySelectorAll('video[autoplay]').forEach(v => {
  v.autoplay = false;
  v.removeAttribute('autoplay');
  try { v.pause(); } catch {}
});`
  }
];

function parseUserScriptMeta(code = '') {
  const meta = {
    name: '',
    description: '',
    version: '1.0',
    matches: [],
    excludes: [],
    runAt: 'document-end'
  };

  const blockMatch = String(code).match(/\/\/\s*==UserScript==([\s\S]*?)\/\/\s*==\/UserScript==/i);
  if (!blockMatch) {
    meta.matches = ['*://*/*'];
    return meta;
  }

  const lines = blockMatch[1].split(/\r?\n/);
  for (const line of lines) {
    const m = line.match(/^\s*\/\/\s*@([\w-]+)\s+(.+?)\s*$/);
    if (!m) continue;
    const key = m[1].toLowerCase();
    const val = m[2].trim();
    if (key === 'name' && !meta.name) meta.name = val;
    else if (key === 'description' && !meta.description) meta.description = val;
    else if (key === 'version') meta.version = val;
    else if (key === 'match' || key === 'include') meta.matches.push(val);
    else if (key === 'exclude') meta.excludes.push(val);
    else if (key === 'run-at') {
      if (['document-start', 'document-end', 'document-idle'].includes(val)) {
        meta.runAt = val;
      }
    }
  }

  if (!meta.matches.length) meta.matches.push('*://*/*');
  return meta;
}

function wildcardToRegExp(pattern) {
  const raw = String(pattern || '*://*/*').trim();
  if (raw === '<all_urls>' || raw === '*' || raw === '*://*/*') {
    return /^https?:\/\/.+/i;
  }
  // *://*.youtube.com/* gibi kalıpları güvenli RegExp'e dönüştür
  let p = raw
    .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
    .replace(/^\*:\/\//, 'https?://')
    .replace(/\*\\\./g, '(?:[^/]+\\.)?')
    .replace(/\*/g, '.*');
  return new RegExp(`^${p}$`, 'i');
}

function urlMatchesPatternList(url, patterns = []) {
  if (!url || !Array.isArray(patterns) || !patterns.length) return false;
  return patterns.some(pat => {
    try {
      return wildcardToRegExp(pat).test(url);
    } catch {
      return false;
    }
  });
}

class UserScriptManager {
  constructor(options = {}) {
    this.userDataPath = options.userDataPath || '';
    this.storageFile = this.userDataPath
      ? path.join(this.userDataPath, 'zaslon-userscripts.json')
      : '';
    this.scripts = [];
    this.load();
  }

  load() {
    let saved = [];
    if (this.storageFile && fs.existsSync(this.storageFile)) {
      try {
        saved = JSON.parse(fs.readFileSync(this.storageFile, 'utf8'));
      } catch {
        saved = [];
      }
    }

    const savedMap = new Map(
      Array.isArray(saved) ? saved.map(s => [s.id, s]) : []
    );

    const merged = [];
    for (const def of BUILTIN_SCRIPTS) {
      if (savedMap.has(def.id)) {
        const s = savedMap.get(def.id);
        merged.push({
          ...def,
          enabled: typeof s.enabled === 'boolean' ? s.enabled : def.enabled,
          code: s.code || def.code
        });
        savedMap.delete(def.id);
      } else {
        merged.push({ ...def });
      }
    }

    for (const custom of savedMap.values()) {
      if (custom && custom.id && custom.code) {
        merged.push(custom);
      }
    }

    this.scripts = merged;
  }

  save() {
    if (!this.storageFile) return;
    try {
      fs.mkdirSync(path.dirname(this.storageFile), { recursive: true });
      fs.writeFileSync(this.storageFile, JSON.stringify(this.scripts, null, 2), 'utf8');
    } catch {}
  }

  getAllScripts() {
    return this.scripts.map(sc => {
      const keys = sc.builtin ? BUILTIN_I18N_KEYS[sc.id] : null;
      if (!keys) return sc;
      return {
        ...sc,
        name: t(keys[0]),
        description: t(keys[1])
      };
    });
  }

  upsertScript(scriptData = {}) {
    const code = String(scriptData.code || '').trim();
    if (!code) throw new Error(t('us.emptyCode'));

    const meta = parseUserScriptMeta(code);
    const id = scriptData.id || `us-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const existingIdx = this.scripts.findIndex(s => s.id === id);

    const record = {
      id,
      builtin: existingIdx >= 0 ? !!this.scripts[existingIdx].builtin : false,
      enabled: typeof scriptData.enabled === 'boolean' ? scriptData.enabled : true,
      name: scriptData.name || meta.name || t('us.customName'),
      version: scriptData.version || meta.version || '1.0',
      description: scriptData.description || meta.description || t('us.customDesc'),
      matches: Array.isArray(scriptData.matches) && scriptData.matches.length ? scriptData.matches : meta.matches,
      excludes: Array.isArray(scriptData.excludes) ? scriptData.excludes : meta.excludes,
      runAt: scriptData.runAt || meta.runAt || 'document-end',
      code
    };

    if (existingIdx >= 0) {
      this.scripts[existingIdx] = record;
    } else {
      this.scripts.push(record);
    }

    this.save();
    return record;
  }

  toggleScript(id, enabled) {
    const sc = this.scripts.find(s => s.id === id);
    if (!sc) return null;
    sc.enabled = typeof enabled === 'boolean' ? enabled : !sc.enabled;
    this.save();
    return sc;
  }

  deleteScript(id) {
    const idx = this.scripts.findIndex(s => s.id === id);
    if (idx < 0) return false;
    if (this.scripts[idx].builtin) {
      // Yerleşik betik silinirse varsayılan koduna sıfırla ve kapat
      const orig = BUILTIN_SCRIPTS.find(b => b.id === id);
      if (orig) {
        this.scripts[idx] = { ...orig, enabled: false };
        this.save();
      }
      return true;
    }
    this.scripts.splice(idx, 1);
    this.save();
    return true;
  }

  getMatchingScriptsForUrl(url) {
    if (!url || (!url.startsWith('http://') && !url.startsWith('https://'))) {
      return [];
    }
    return this.scripts.filter(sc => {
      if (!sc.enabled) return false;
      if (sc.excludes && sc.excludes.length && urlMatchesPatternList(url, sc.excludes)) {
        return false;
      }
      return urlMatchesPatternList(url, sc.matches || ['*://*/*']);
    });
  }

  /**
   * Bir sayfa için eşleşen tüm UserScript'leri GM_* yardımcı fonksiyonlarıyla sararak
   * çalıştırılabilir tek bir JS paketine dönüştürür.
   */
  buildInjectionBundleForUrl(url) {
    const matched = this.getMatchingScriptsForUrl(url);
    if (!matched.length) return '';

    const gmPreamble = `
      const _gmStore = new Map();
      const GM_addStyle = (css) => {
        try {
          const st = document.createElement('style');
          st.textContent = String(css || '');
          (document.head || document.documentElement).appendChild(st);
          return st;
        } catch { return null; }
      };
      const GM_setValue = (k, v) => {
        try { _gmStore.set(String(k), JSON.stringify(v)); } catch {}
      };
      const GM_getValue = (k, def) => {
        try {
          const r = _gmStore.get(String(k));
          return r === undefined ? def : JSON.parse(r);
        } catch { return def; }
      };
      const GM_deleteValue = (k) => {
        try { _gmStore.delete(String(k)); } catch {}
      };
      const GM_log = () => {};
    `;

    const wrappedScripts = matched
      .map(
        sc => `
        try {
          (function() {
            ${sc.code}
          })();
        } catch (_err) {}`
      )
      .join('\n');

    return `(function() {
      ${gmPreamble}
      ${wrappedScripts}
    })();`;
  }
}

module.exports = {
  UserScriptManager,
  parseUserScriptMeta,
  wildcardToRegExp
};
