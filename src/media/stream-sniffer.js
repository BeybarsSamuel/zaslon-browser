/**
 * Zaslon Browser — Faz 4: Evrensel Medya Akış Yakalayıcı (stream-sniffer.js)
 *
 * Siteleri tek tek tanımlamaya gerek kalmadan 3 katmanlı evrensel yakalama yapar:
 * 1) Ağ Katmanı (onHeadersReceived): Hangi site veya gömülü iframe olursa olsun
 *    HLS (.m3u8), DASH (.mpd), MP4, WebM, MKV, MOV, MP3, M4A, AAC, FLAC, OGG akışlarını
 *    (HTTP 206 Partial Content / Content-Range dahil) yakalar.
 * 2) DOM Video Katmanı (recordDomMedia): Sayfada herhangi bir <video> oynatıcısı
 *    (MSE blob: akışları dahil) çalıştığında tekil ve temiz bir sayfa medya öğesi üretir
 *    (aynı sayfa için çift kayıt oluşturmaz).
 * 3) Bilinen Platform Kısayolu (inspectPageNavigation): Video daha başlamadan bile
 *    bilinen video URL'lerini tekil sayfa öğesi olarak hazırlar.
 */

const { t } = require('../i18n/translations');

const MEDIA_EXT_REGEX = /\.(m3u8|mpd|mp4|webm|mkv|m4v|mov|mp3|m4a|aac|flac|ogg|wav)(\?|#|$)/i;
const SEGMENT_EXT_REGEX = /\.(ts|m4s|aac|vtt|srt)(\?|#|$)/i;

const CONTENT_TYPE_MAP = [
  { test: /(application|audio|video)\/(vnd\.apple\.mpegurl|x-mpegurl|mpegurl)/i, labelKey: 'stream.hls', ext: 'm3u8', isManifest: true },
  { test: /application\/dash\+xml/i, labelKey: 'stream.dash', ext: 'mpd', isManifest: true },
  { test: /video\/mp4/i, labelKey: 'stream.mp4', ext: 'mp4', isManifest: false },
  { test: /video\/webm/i, labelKey: 'stream.webm', ext: 'webm', isManifest: false },
  { test: /video\/x-matroska/i, labelKey: 'stream.mkv', ext: 'mkv', isManifest: false },
  { test: /video\/quicktime/i, labelKey: 'stream.mov', ext: 'mov', isManifest: false },
  { test: /audio\/mpeg/i, labelKey: 'stream.mp3', ext: 'mp3', isManifest: false },
  { test: /audio\/(mp4|x-m4a|aac)/i, labelKey: 'stream.m4a', ext: 'm4a', isManifest: false },
  { test: /audio\/(ogg|opus)/i, labelKey: 'stream.ogg', ext: 'ogg', isManifest: false },
  { test: /audio\/flac/i, labelKey: 'stream.flac', ext: 'flac', isManifest: false }
];

const PLATFORM_PATTERNS = [
  { name: 'YouTube', rx: /(?:youtube\.com\/(?:watch\?.*v=|shorts\/|live\/|embed\/)|youtu\.be\/)([a-zA-Z0-9_-]{11})/i },
  { name: 'OK.ru', rx: /(?:ok\.ru|odnoklassniki\.ru)\/(?:video|videoembed|live)\/\d+/i },
  { name: 'VK Video', rx: /(?:vk\.com|vkvideo\.ru)\/.*video-?\d+_\d+/i },
  { name: 'X / Twitter', rx: /(?:twitter\.com|x\.com)\/(?:[^/]+\/status\/\d+|i\/broadcasts\/[a-zA-Z0-9]+)/i },
  { name: 'Instagram', rx: /instagram\.com\/(?:reel|reels|p|tv)\/[a-zA-Z0-9_-]+/i },
  { name: 'TikTok', rx: /tiktok\.com\/(?:@[^/]+\/video\/\d+|t\/[a-zA-Z0-9]+|v\/\d+)/i },
  { name: 'Reddit', rx: /reddit\.com\/r\/[^/]+\/comments\/[a-z0-9]+/i },
  { name: 'Twitch', rx: /twitch\.tv\/(?:videos\/\d+|[^/]+\/clip\/[a-zA-Z0-9_-]+)/i },
  { name: 'Kick', rx: /kick\.com\/[^/]+(?:\/videos\/[a-z0-9-]+)?/i },
  { name: 'Vimeo', rx: /vimeo\.com\/\d+/i },
  { name: 'Dailymotion', rx: /dailymotion\.com\/video\/[a-zA-Z0-9]+/i },
  { name: 'Rutube', rx: /rutube\.ru\/video\/[a-zA-Z0-9]+/i },
  { name: 'SoundCloud', rx: /soundcloud\.com\/[^/]+\/[^/?#]+/i }
];

const IGNORE_URL_PATTERNS = [
  /doubleclick\.net/i,
  /googlesyndication\.com/i,
  /googleadservices\.com/i,
  /googlevideo\.com\/videoplayback/i,
  /\/ptracking\?/i,
  /\/api\/stats\//i,
  /^blob:/i,
  /^data:/i
];

class StreamSniffer {
  constructor(options = {}) {
    this.onUpdate = options.onUpdate || (() => {});
    this.wcToTabId = new Map(); // webContents.id -> tabId
    this.tabStreams = new Map(); // tabId -> Map<normalizedKey, StreamItem>
  }

  registerWebContents(wcId, tabId) {
    this.wcToTabId.set(wcId, tabId);
    if (!this.tabStreams.has(tabId)) {
      this.tabStreams.set(tabId, new Map());
    }
  }

  unregisterTab(tabId) {
    this.tabStreams.delete(tabId);
    for (const [wcId, tId] of this.wcToTabId.entries()) {
      if (tId === tabId) this.wcToTabId.delete(wcId);
    }
  }

  clearTabStreams(tabId) {
    if (this.tabStreams.has(tabId)) {
      this.tabStreams.get(tabId).clear();
      this.emitTabUpdate(tabId);
    }
  }

  clearAll() {
    const allTabs = [...this.tabStreams.keys()];
    this.tabStreams.clear();
    for (const tabId of allTabs) {
      this.onUpdate(tabId, []);
    }
  }

  /**
   * YouTube vb. adreslerde tekil video URL'sini temizler (&list=RD... vb. oynatma listesi
   * takılmalarını ve çift kayıtları önler).
   */
  cleanPageUrl(rawUrl) {
    const str = String(rawUrl || '').trim();
    try {
      const u = new URL(str);
      if (/(^|\.)youtube\.com$/i.test(u.hostname) && u.pathname === '/watch' && u.searchParams.has('v')) {
        return `https://www.youtube.com/watch?v=${u.searchParams.get('v')}`;
      }
      if (/^youtu\.be$/i.test(u.hostname)) {
        const vid = u.pathname.replace(/^\/+/, '').split('/')[0];
        if (vid) return `https://www.youtube.com/watch?v=${vid}`;
      }
      return str;
    } catch {
      return str;
    }
  }

  derivePlatformBadge(urlStr) {
    const matched = PLATFORM_PATTERNS.find(p => p.rx.test(urlStr));
    if (matched) return matched.name;
    try {
      const host = new URL(urlStr).hostname.replace(/^(www|m|player)\./i, '');
      const mainPart = host.split('.')[0] || host;
      return mainPart.toUpperCase();
    } catch {
      return t('stream.videoBadge');
    }
  }

  /**
   * Sayfa URL'si bilinen bir video sayfasıysa daha video oynatılmadan tekil sayfa öğesi olarak ekler.
   */
  inspectPageNavigation(tabId, pageUrl, pageTitle = '') {
    if (!tabId || !pageUrl || !/^https?:\/\//i.test(pageUrl)) return;
    const cleanUrl = this.cleanPageUrl(pageUrl);
    for (const plat of PLATFORM_PATTERNS) {
      if (plat.rx.test(cleanUrl)) {
        const placeholderTitle = t('stream.platformVideo', { platform: plat.name });
        this.addStream(tabId, {
          url: cleanUrl,
          label: pageTitle || placeholderTitle,
          labelKey: pageTitle ? null : 'stream.platformVideo',
          labelParams: pageTitle ? null : { platform: plat.name },
          ext: 'mp4',
          source: 'platform',
          platform: plat.name,
          title: pageTitle || placeholderTitle,
          isPlaceholderTitle: !pageTitle,
          sizeBytes: 0,
          isManifest: false,
          isPlatformPage: true
        });
        break;
      }
    }
  }

  /**
   * Ağ yanıt başlıklarını (onHeadersReceived) inceleyerek tüm sitelerdeki .m3u8, .mpd, .mp4, .webm
   * medya akışlarını (HTTP 206 Content-Range dahil) evrensel olarak yakalar.
   */
  inspectHeadersReceived(details) {
    try {
      const tabId = this.wcToTabId.get(details.webContentsId);
      if (!tabId) return;

      const urlStr = details.url || '';
      if (!urlStr.startsWith('http://') && !urlStr.startsWith('https://')) return;
      if (IGNORE_URL_PATTERNS.some(rx => rx.test(urlStr))) return;
      if (SEGMENT_EXT_REGEX.test(urlStr)) return;

      const headers = details.responseHeaders || {};
      let contentType = '';
      let contentLength = 0;
      let totalRangeLength = 0;

      for (const [k, v] of Object.entries(headers)) {
        const lk = k.toLowerCase();
        const val = Array.isArray(v) ? v[0] : String(v || '');
        if (lk === 'content-type') {
          contentType = val;
        } else if (lk === 'content-length') {
          contentLength = parseInt(val, 10) || 0;
        } else if (lk === 'content-range') {
          const rm = val.match(/\/(\d+)$/);
          if (rm) totalRangeLength = parseInt(rm[1], 10) || 0;
        }
      }

      const effectiveSize = totalRangeLength || contentLength;
      const extMatch = urlStr.match(MEDIA_EXT_REGEX);
      const extFromUrl = extMatch ? extMatch[1].toLowerCase() : '';
      const isManifestUrl = extFromUrl === 'm3u8' || extFromUrl === 'mpd' || /\.m3u8/i.test(urlStr);

      if (!isManifestUrl && effectiveSize > 0 && effectiveSize < 60 * 1024) {
        return;
      }

      let matchedType = null;
      if (contentType) {
        matchedType = CONTENT_TYPE_MAP.find(m => m.test.test(contentType));
      }

      if (!matchedType && (extFromUrl || isManifestUrl)) {
        const extMap = {
          m3u8: { labelKey: 'stream.hls', ext: 'm3u8', isManifest: true },
          mpd: { labelKey: 'stream.dash', ext: 'mpd', isManifest: true },
          mp4: { labelKey: 'stream.mp4', ext: 'mp4', isManifest: false },
          webm: { labelKey: 'stream.webm', ext: 'webm', isManifest: false },
          mkv: { labelKey: 'stream.mkv', ext: 'mkv', isManifest: false },
          mov: { labelKey: 'stream.mov', ext: 'mov', isManifest: false },
          m4v: { labelKey: 'stream.m4v', ext: 'm4v', isManifest: false },
          mp3: { labelKey: 'stream.mp3', ext: 'mp3', isManifest: false },
          m4a: { labelKey: 'stream.m4aShort', ext: 'm4a', isManifest: false },
          aac: { labelKey: 'stream.aac', ext: 'aac', isManifest: false },
          flac: { labelKey: 'stream.flac', ext: 'flac', isManifest: false },
          ogg: { labelKey: 'stream.ogg', ext: 'ogg', isManifest: false },
          wav: { labelKey: 'stream.wav', ext: 'wav', isManifest: false }
        };
        matchedType = extMap[extFromUrl || (isManifestUrl ? 'm3u8' : '')] || null;
      }

      if (!matchedType) return;

      this.addStream(tabId, {
        url: urlStr,
        label: t(matchedType.labelKey),
        labelKey: matchedType.labelKey,
        ext: matchedType.ext,
        contentType: contentType.split(';')[0].trim(),
        sizeBytes: effectiveSize,
        isManifest: !!matchedType.isManifest,
        isPlatformPage: false,
        source: 'network',
        title: this.extractReadableName(urlStr, matchedType.ext)
      });
    } catch {}
  }

  /**
   * Sayfa içindeki <video> veya <audio> etiketlerinden bildirilen medya kaynaklarını kaydeder.
   * Her sekmede en fazla 1 adet ana sayfa videosu (page::main) tutarak çift kayıt oluşmasını engeller.
   */
  recordDomMedia(tabId, mediaInfo = {}) {
    if (!tabId) return;
    const src = String(mediaInfo.src || '').trim();
    const rawPageUrl = String(mediaInfo.pageUrl || '').trim();
    const pageUrl = this.cleanPageUrl(rawPageUrl);
    const pageTitle = String(mediaInfo.title || '').trim();
    const width = Number(mediaInfo.width) || 0;
    const height = Number(mediaInfo.height) || 0;
    const resolution = width && height ? `${height}p` : '';

    // Çok küçük reklam/önizleme videolarını (< 160px) yoksay
    if ((width > 0 && width < 160) || (height > 0 && height < 120)) return;

    if (pageUrl && /^https?:\/\//i.test(pageUrl) && (src.startsWith('blob:') || mediaInfo.hasVideo)) {
      const badgeName = this.derivePlatformBadge(pageUrl);
      const cleanTitle = pageTitle
        ? pageTitle.replace(/\s*[-|·]\s*(YouTube|OK\.ru|VK|Twitch|Vimeo|Dailymotion).*$/i, '').trim()
        : t('stream.platformVideo', { platform: badgeName });

      this.addStream(tabId, {
        url: pageUrl,
        label: `${cleanTitle}${resolution ? ` (${resolution})` : ''}`,
        labelKey: pageTitle ? null : 'stream.platformVideo',
        labelParams: pageTitle ? null : { platform: badgeName },
        resolution,
        ext: 'mp4',
        source: 'platform',
        platform: badgeName,
        title: cleanTitle,
        isPlaceholderTitle: !pageTitle,
        sizeBytes: 0,
        isManifest: false,
        isPlatformPage: true,
        duration: mediaInfo.duration || 0
      });
    }

    if (!src || !/^https?:\/\//i.test(src) || IGNORE_URL_PATTERNS.some(rx => rx.test(src))) return;

    const extMatch = src.match(MEDIA_EXT_REGEX);
    const ext = extMatch ? extMatch[1].toLowerCase() : 'mp4';
    const domLabelKey = ext === 'm3u8' ? 'stream.hls' : ext === 'mp3' ? 'stream.mp3' : 'stream.directVideo';
    this.addStream(tabId, {
      url: src,
      label: `${t(domLabelKey)}${ext !== 'm3u8' && ext !== 'mp3' && resolution ? ` (${resolution})` : ''}`,
      labelKey: domLabelKey,
      ext,
      sizeBytes: 0,
      isManifest: ext === 'm3u8' || ext === 'mpd',
      isPlatformPage: false,
      source: 'dom',
      title: pageTitle || this.extractReadableName(src, ext),
      duration: mediaInfo.duration || 0,
      resolution
    });
  }

  extractReadableName(urlStr, fallbackExt = 'mp4') {
    try {
      const u = new URL(urlStr);
      const base = u.pathname.split('/').filter(Boolean).pop() || u.hostname;
      const decoded = decodeURIComponent(base).replace(/[+_]+/g, ' ').trim();
      if (decoded && decoded.length > 2 && decoded.length <= 90) {
        return decoded;
      }
      return `${u.hostname.replace(/^www\./, '')}.${fallbackExt}`;
    } catch {
      return `medya-akisi.${fallbackExt}`;
    }
  }

  normalizeKey(urlStr) {
    try {
      const u = new URL(urlStr);
      if (/\.(m3u8|mpd|mp4|webm|mp3|m4a)$/i.test(u.pathname)) {
        return `${u.origin}${u.pathname}`;
      }
      return urlStr;
    } catch {
      return urlStr;
    }
  }

  addStream(tabId, item) {
    if (!this.tabStreams.has(tabId)) {
      this.tabStreams.set(tabId, new Map());
    }
    const map = this.tabStreams.get(tabId);
    // Sayfa bazlı ana video için tekil anahtar ('page::main') kullan -> asla çift kayıt oluşmaz!
    const key = item.isPlatformPage ? 'page::main' : this.normalizeKey(item.url);
    const existing = map.get(key);

    if (existing) {
      let changed = false;
      if (item.url && item.url !== existing.url) {
        existing.url = item.url;
        changed = true;
      }
      if (item.sizeBytes && item.sizeBytes > (existing.sizeBytes || 0)) {
        existing.sizeBytes = item.sizeBytes;
        existing.sizeFormatted = item.sizeBytes > 1048576
          ? `${(item.sizeBytes / 1048576).toFixed(1)} MB`
          : `${Math.round(item.sizeBytes / 1024)} KB`;
        changed = true;
      }
      if (item.title && item.title !== existing.title && !item.isPlaceholderTitle) {
        existing.title = item.title;
        existing.isPlaceholderTitle = false;
        existing.labelKey = null;
        existing.label = item.resolution ? `${item.title} (${item.resolution})` : item.title;
        changed = true;
      }
      if (item.resolution && item.resolution !== existing.resolution) {
        existing.resolution = item.resolution;
        existing.label = `${existing.title} (${item.resolution})`;
        changed = true;
      }
      if (item.platform && item.platform !== existing.platform) {
        existing.platform = item.platform;
        existing.badge = item.platform.toUpperCase();
        changed = true;
      }
      if (changed) this.emitTabUpdate(tabId);
      return;
    }

    if (map.size >= 40) {
      const oldestKey = [...map.keys()].find(k => k !== 'page::main');
      if (oldestKey) map.delete(oldestKey);
    }

    let host = '';
    try { host = new URL(item.url).hostname.replace(/^www\./, ''); } catch {}
    const sizeBytes = item.sizeBytes || 0;
    const sizeFormatted = sizeBytes > 1048576
      ? `${(sizeBytes / 1048576).toFixed(1)} MB`
      : sizeBytes > 1024
        ? `${Math.round(sizeBytes / 1024)} KB`
        : '';
    const ext = (item.ext || 'mp4').toLowerCase();
    const kind = ext === 'm3u8' ? 'hls' : ext === 'mpd' ? 'dash' : 'video';

    map.set(key, {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      url: item.url,
      host,
      title: item.title || t('stream.mediaFallback'),
      label: item.label || item.title || t('stream.videoFallback'),
      labelKey: item.labelKey || null,
      labelParams: item.labelParams || null,
      isPlaceholderTitle: !!item.isPlaceholderTitle,
      badge: item.platform ? item.platform.toUpperCase() : ext.toUpperCase(),
      kind,
      ext,
      contentType: item.contentType || '',
      sizeBytes,
      sizeFormatted,
      isManifest: !!item.isManifest,
      isPlatformPage: !!item.isPlatformPage,
      platform: item.platform || '',
      resolution: item.resolution || '',
      source: item.source || 'network',
      timestamp: Date.now()
    });

    this.emitTabUpdate(tabId);
  }

  getTabStreams(tabId) {
    const map = this.tabStreams.get(tabId);
    if (!map) return [];
    return [...map.values()]
      .map(s => {
        if (!s.labelKey) return s;
        const base = t(s.labelKey, s.labelParams || {});
        const lbl = s.resolution && (s.labelKey === 'stream.directVideo' || s.labelKey === 'stream.platformVideo')
          ? `${base} (${s.resolution})`
          : base;
        return {
          ...s,
          title: s.isPlaceholderTitle ? base : s.title,
          label: lbl
        };
      })
      .sort((a, b) => {
        if (a.isPlatformPage !== b.isPlatformPage) return a.isPlatformPage ? -1 : 1;
        if (a.isManifest !== b.isManifest) return a.isManifest ? -1 : 1;
        return b.timestamp - a.timestamp;
      });
  }

  emitTabUpdate(tabId) {
    const streams = this.getTabStreams(tabId);
    this.onUpdate(tabId, streams);
  }
}

module.exports = {
  StreamSniffer
};
