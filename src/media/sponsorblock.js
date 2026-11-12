/**
 * Zaslon Browser — Faz 4: SponsorBlock Otomatik Sponsor Atlama Servisi (sponsorblock.js)
 *
 * YouTube videolarındaki sponsorlu ürün yerleştirmelerini, intro/outro ve
 * "abone ol / beğen" konuşmalarını çerezsiz SponsorBlock API'si üzerinden sorgular
 * ve sayfa içi oynatıcıda otomatik olarak atlar.
 */

const crypto = require('crypto');
const { t } = require('../i18n/translations');
const { getUniformBrowserUserAgent } = require('../privacy/chromium-hardening');

const NEUTRAL_UA = getUniformBrowserUserAgent();

function getVideoIdHashPrefix(videoId) {
  return crypto.createHash('sha256').update(String(videoId || '')).digest('hex').slice(0, 4);
}

const CATEGORY_KEYS = {
  sponsor: 'sb.sponsor',
  selfpromo: 'sb.selfpromo',
  interaction: 'sb.interaction',
  intro: 'sb.intro',
  outro: 'sb.outro',
  preview: 'sb.preview',
  music_offtopic: 'sb.music_offtopic',
  filler: 'sb.filler'
};

const DEFAULT_CATEGORIES = [
  'sponsor',
  'selfpromo',
  'interaction',
  'intro',
  'outro',
  'preview',
  'music_offtopic'
];

function extractYouTubeVideoId(urlOrId) {
  if (!urlOrId) return null;
  const raw = String(urlOrId).trim();
  if (/^[a-zA-Z0-9_-]{11}$/.test(raw)) return raw;
  try {
    const u = new URL(raw);
    const host = u.hostname.replace(/^www\./i, '').toLowerCase();
    if (host === 'youtu.be') {
      const id = u.pathname.split('/').filter(Boolean)[0];
      return id && /^[a-zA-Z0-9_-]{11}$/.test(id) ? id : null;
    }
    if (host.endsWith('youtube.com') || host.endsWith('youtube-nocookie.com')) {
      const v = u.searchParams.get('v');
      if (v && /^[a-zA-Z0-9_-]{11}$/.test(v)) return v;
      const parts = u.pathname.split('/').filter(Boolean);
      if ((parts[0] === 'shorts' || parts[0] === 'embed' || parts[0] === 'live') && parts[1]) {
        return /^[a-zA-Z0-9_-]{11}$/.test(parts[1]) ? parts[1] : null;
      }
    }
  } catch {}
  return null;
}

class SponsorBlockService {
  constructor(options = {}) {
    this.fetchFn = options.fetchFn || global.fetch;
    this.enabled = options.enabled !== false;
    this.categories = Array.isArray(options.categories) ? options.categories : DEFAULT_CATEGORIES;
    this.cache = new Map(); // videoId -> { segments, expiresAt }
    this.stats = {
      skippedCount: 0,
      savedSeconds: 0
    };
  }

  async getSegmentsForVideo(videoIdOrUrl, runtimeOpts = {}) {
    if (!this.enabled) return [];
    if (runtimeOpts.torRequired && !runtimeOpts.torConnected) {
      return [];
    }
    const videoId = extractYouTubeVideoId(videoIdOrUrl);
    if (!videoId) return [];

    const localizeSegments = list =>
      list.map(seg => ({
        ...seg,
        label: t(CATEGORY_KEYS[seg.category] || 'sb.default')
      }));

    const now = Date.now();
    const cached = this.cache.get(videoId);
    if (cached && cached.expiresAt > now) {
      return localizeSegments(cached.segments);
    }

    const fetchFn = runtimeOpts.fetchFn || this.fetchFn;

    try {
      const hashPrefix = getVideoIdHashPrefix(videoId);
      const catsParam = encodeURIComponent(JSON.stringify(this.categories));
      const apiUrl = `https://sponsor.ajay.app/api/skipSegments/${hashPrefix}?categories=${catsParam}`;

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);

      const res = await fetchFn(apiUrl, {
        method: 'GET',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        headers: {
          Accept: 'application/json',
          'User-Agent': NEUTRAL_UA
        },
        signal: controller.signal
      });
      clearTimeout(timer);

      if (res.status === 404) {
        this.cache.set(videoId, { segments: [], expiresAt: now + 10 * 60 * 1000 });
        return [];
      }

      if (!res.ok) return [];
      const data = await res.json();
      if (!Array.isArray(data)) return [];

      // k-Anonymity yanıtı [{ videoID, hash, segments: [...] }, ...] içinden yalnızca hedef videoyu seç
      const matchedEntry = data.find(entry => entry && entry.videoID === videoId && Array.isArray(entry.segments));
      const rawSegments = matchedEntry ? matchedEntry.segments : [];

      const segments = rawSegments
        .filter(item => Array.isArray(item.segment) && item.segment.length === 2 && item.segment[1] > item.segment[0])
        .map(item => ({
          uuid: item.UUID || `${item.segment[0]}-${item.segment[1]}`,
          start: Number(item.segment[0]),
          end: Number(item.segment[1]),
          category: item.category || 'sponsor'
        }))
        .sort((a, b) => a.start - b.start);

      this.cache.set(videoId, {
        segments,
        expiresAt: now + 30 * 60 * 1000
      });

      return localizeSegments(segments);
    } catch {
      return [];
    }
  }

  recordSkip(durationSec = 0) {
    const d = Math.max(0, Number(durationSec) || 0);
    this.stats.skippedCount += 1;
    this.stats.savedSeconds = Math.round((this.stats.savedSeconds + d) * 10) / 10;
    return this.getStats();
  }

  getStats() {
    return {
      enabled: this.enabled,
      skippedCount: this.stats.skippedCount,
      savedSeconds: this.stats.savedSeconds
    };
  }
}

function getCategoryLabel(category) {
  return t(CATEGORY_KEYS[category] || 'sb.default');
}

const CATEGORY_LABELS = new Proxy(CATEGORY_KEYS, {
  get(_, prop) {
    if (typeof prop !== 'string') return undefined;
    if (prop === 'toJSON') return () => Object.fromEntries(Object.entries(CATEGORY_KEYS).map(([k, key]) => [k, t(key)]));
    return t(CATEGORY_KEYS[prop] || 'sb.default');
  },
  ownKeys() {
    return Object.keys(CATEGORY_KEYS);
  },
  getOwnPropertyDescriptor(_, prop) {
    if (!(prop in CATEGORY_KEYS)) return undefined;
    return { enumerable: true, configurable: true, value: t(CATEGORY_KEYS[prop]) };
  }
});

module.exports = {
  SponsorBlockService,
  extractYouTubeVideoId,
  getVideoIdHashPrefix,
  CATEGORY_KEYS,
  getCategoryLabel,
  CATEGORY_LABELS
};
