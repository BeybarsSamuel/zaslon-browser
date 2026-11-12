/**
 * Zaslon Browser — Faz 4: Algoritmasız Yerel RSS & YouTube Kanal Okuyucusu (rss-service.js)
 *
 * YouTube kanallarını (@kullaniciadi, /channel/UC..., /playlist?list=...),
 * haber sitelerini ve blogları Google/X algoritmasına, çerezlere ve reklamlara
 * maruz kalmadan doğrudan kronolojik XML beslemeleri üzerinden çeker.
 */

const { t } = require('../i18n/translations');
const { getUniformBrowserUserAgent } = require('../privacy/chromium-hardening');

function decodeXmlEntities(str) {
  if (!str) return '';
  return String(str)
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/gi, '$1')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;|&#39;/g, "'")
    .replace(/&#(\d+);/g, (_, dec) => {
      try { return String.fromCodePoint(parseInt(dec, 10)); } catch { return ''; }
    })
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => {
      try { return String.fromCodePoint(parseInt(hex, 16)); } catch { return ''; }
    })
    .trim();
}

function stripHtmlTags(html) {
  if (!html) return '';
  return decodeXmlEntities(html)
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function extractTagContent(xmlBlock, tagNames) {
  const names = Array.isArray(tagNames) ? tagNames : [tagNames];
  for (const name of names) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const rx = new RegExp(`<${escaped}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${escaped}>`, 'i');
    const m = xmlBlock.match(rx);
    if (m && m[1] !== undefined) {
      return decodeXmlEntities(m[1]);
    }
  }
  return '';
}

function extractAttr(xmlBlock, tagName, attrName) {
  const escapedTag = tagName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const escapedAttr = attrName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const rx = new RegExp(`<${escapedTag}[^>]*?\\s${escapedAttr}=["']([^"']+)["'][^>]*>`, 'i');
  const m = xmlBlock.match(rx);
  return m ? decodeXmlEntities(m[1]) : '';
}

/**
 * Bir XML (RSS 2.0, Atom veya YouTube videos.xml) metnini ayrıştırır.
 */
function parseFeedXml(xmlText, feedUrl = '') {
  const raw = String(xmlText || '');
  if (!raw.includes('<rss') && !raw.includes('<feed') && !raw.includes('<RDF')) {
    return null;
  }

  const isAtom = /<feed[\s>]/i.test(raw);
  let feedTitle = '';
  let feedSiteUrl = '';

  if (isAtom) {
    const headChunk = raw.split(/<entry[\s>]/i)[0] || raw;
    feedTitle = stripHtmlTags(extractTagContent(headChunk, 'title'));
    feedSiteUrl =
      extractAttr(headChunk, 'link[^>]+rel=["\']alternate["\']', 'href') ||
      extractAttr(headChunk, 'link', 'href') ||
      feedUrl;
  } else {
    const headChunk = raw.split(/<item[\s>]/i)[0] || raw;
    feedTitle = stripHtmlTags(extractTagContent(headChunk, 'title'));
    feedSiteUrl = extractTagContent(headChunk, 'link') || feedUrl;
  }

  const items = [];
  const blockRegex = isAtom ? /<entry(?:\s[^>]*)?>([\s\S]*?)<\/entry>/gi : /<item(?:\s[^>]*)?>([\s\S]*?)<\/item>/gi;
  let match;

  while ((match = blockRegex.exec(raw)) !== null && items.length < 40) {
    const block = match[1];
    const title = stripHtmlTags(extractTagContent(block, 'title')) || t('rss.untitled');

    let link = '';
    if (isAtom) {
      const altMatch = block.match(/<link[^>]*rel=["']alternate["'][^>]*href=["']([^"']+)["']/i);
      const anyHref = block.match(/<link[^>]*href=["']([^"']+)["']/i);
      link = decodeXmlEntities((altMatch && altMatch[1]) || (anyHref && anyHref[1]) || '');
    } else {
      link = extractTagContent(block, 'link') || extractTagContent(block, 'guid');
    }

    const ytVideoId = extractTagContent(block, 'yt:videoId');
    if (ytVideoId && !link) {
      link = `https://www.youtube.com/watch?v=${ytVideoId}`;
    }

    const dateRaw =
      extractTagContent(block, ['pubDate', 'published', 'updated', 'dc:date']) || '';
    const parsedTime = dateRaw ? Date.parse(dateRaw) : NaN;
    const timestamp = Number.isFinite(parsedTime) ? parsedTime : Date.now();

    const author =
      stripHtmlTags(extractTagContent(block, ['dc:creator', 'author', 'name'])) || feedTitle || '';

    const rawDesc =
      extractTagContent(block, ['content:encoded', 'content', 'media:description', 'description', 'summary']) || '';
    const summary = stripHtmlTags(rawDesc).slice(0, 360);

    // Küçük resim (Thumbnail) tespiti
    let thumbnail =
      extractAttr(block, 'media:thumbnail', 'url') ||
      extractAttr(block, 'enclosure[^>]+type=["\']image', 'url') ||
      '';
    if (!thumbnail && ytVideoId) {
      thumbnail = `https://i.ytimg.com/vi/${ytVideoId}/hqdefault.jpg`;
    }
    if (!thumbnail && rawDesc) {
      const imgMatch = rawDesc.match(/<img[^>]+src=["']([^"']+)["']/i);
      if (imgMatch && /^https?:\/\//i.test(imgMatch[1])) {
        thumbnail = decodeXmlEntities(imgMatch[1]);
      }
    }

    items.push({
      id: ytVideoId || link || `${feedUrl}-${title}`,
      title,
      link,
      pubDate: dateRaw,
      timestamp,
      author,
      summary,
      contentText: stripHtmlTags(rawDesc).slice(0, 4000),
      thumbnail,
      isYouTube: !!ytVideoId || /youtube\.com\/watch|youtu\.be\//i.test(link),
      isVideo: !!ytVideoId || /youtube\.com\/watch|youtu\.be\//i.test(link),
      videoId: ytVideoId || '',
      feedTitle: feedTitle || t('rss.sourceFallback'),
      feedUrl
    });
  }

  return {
    title: feedTitle || t('rss.feedFallback'),
    siteUrl: feedSiteUrl || feedUrl,
    feedUrl,
    items
  };
}

const NEUTRAL_RSS_UA = getUniformBrowserUserAgent();

class RssService {
  constructor(options = {}) {
    this.fetchFn = options.fetchFn || global.fetch;
  }

  async fetchText(url, timeoutMs = 7000, runtimeOpts = {}) {
    if (runtimeOpts.torRequired && !runtimeOpts.torConnected) {
      throw new Error(runtimeOpts.torBlockedReason || t('err.torTitle'));
    }
    const fetchFn = runtimeOpts.fetchFn || this.fetchFn;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetchFn(url, {
        method: 'GET',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        headers: {
          'User-Agent': NEUTRAL_RSS_UA,
          Accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml, text/html;q=0.9, */*;q=0.8'
        },
        signal: controller.signal
      });
      clearTimeout(timer);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.text();
    } catch (err) {
      clearTimeout(timer);
      throw err;
    }
  }

  /**
   * Kullanıcı bir YouTube kanal linki (@handle, /channel/UC...), YouTube video linki
   * veya düz bir web sitesi adresi girdiğinde gerçek RSS XML adresini otomatik bulur.
   */
  async resolveFeedUrl(inputUrl, runtimeOpts = {}) {
    let raw = String(inputUrl || '').trim();
    if (!raw) throw new Error(t('rss.invalidUrl'));

    // Eğer @kullaniciadi girildiyse YouTube kanalına çevir
    if (raw.startsWith('@') && !raw.includes('/')) {
      raw = `https://www.youtube.com/${raw}`;
    } else if (!/^https?:\/\//i.test(raw)) {
      raw = `https://${raw}`;
    }

    const u = new URL(raw);
    const host = u.hostname.replace(/^www\./i, '').toLowerCase();

    // 1) YouTube özel dönüştürücüsü
    if (host === 'youtube.com' || host === 'm.youtube.com') {
      if (u.pathname.startsWith('/feeds/videos.xml')) {
        return u.toString();
      }
      const chMatch = u.pathname.match(/^\/channel\/(UC[a-zA-Z0-9_-]{20,})/);
      if (chMatch) {
        return `https://www.youtube.com/feeds/videos.xml?channel_id=${chMatch[1]}`;
      }
      const listId = u.searchParams.get('list');
      if (listId && u.pathname.startsWith('/playlist')) {
        return `https://www.youtube.com/feeds/videos.xml?playlist_id=${listId}`;
      }

      // @handle, /c/... veya /watch?v=... sayfasından kanalın RSS adresini çıkar
      const html = await this.fetchText(u.toString(), 8000, runtimeOpts);
      const rssLinkMatch = html.match(/<link[^>]+type=["']application\/rss\+xml["'][^>]+href=["']([^"']+)["']/i);
      if (rssLinkMatch && rssLinkMatch[1]) {
        return decodeXmlEntities(rssLinkMatch[1]);
      }
      const extIdMatch =
        html.match(/"externalId"\s*:\s*"(UC[a-zA-Z0-9_-]{20,})"/) ||
        html.match(/"channelId"\s*:\s*"(UC[a-zA-Z0-9_-]{20,})"/);
      if (extIdMatch && extIdMatch[1]) {
        return `https://www.youtube.com/feeds/videos.xml?channel_id=${extIdMatch[1]}`;
      }
    }

    // 2) Reddit alt dizini (/r/...) ise sonuna .rss ekle
    if ((host === 'reddit.com' || host === 'old.reddit.com') && !u.pathname.endsWith('.rss')) {
      return `https://www.reddit.com${u.pathname.replace(/\/$/, '')}/.rss`;
    }

    // 3) Sayfayı çek; doğrudan XML ise kabul et, HTML ise <link rel="alternate"> ara
    const body = await this.fetchText(u.toString(), 7000, runtimeOpts);
    if (body.includes('<rss') || body.includes('<feed') || body.includes('<RDF')) {
      return u.toString();
    }

    const linkMatch =
      body.match(/<link[^>]+type=["']application\/(?:rss|atom)\+xml["'][^>]+href=["']([^"']+)["']/i) ||
      body.match(/<link[^>]+href=["']([^"']+)["'][^>]+type=["']application\/(?:rss|atom)\+xml["']/i);

    if (linkMatch && linkMatch[1]) {
      return new URL(decodeXmlEntities(linkMatch[1]), u.toString()).toString();
    }

    // 4) Yaygın besleme yollarını dene
    for (const suffix of ['/feed', '/rss', '/rss.xml', '/atom.xml', '/index.xml']) {
      try {
        const candidate = new URL(suffix, u.origin).toString();
        const text = await this.fetchText(candidate, 4000, runtimeOpts);
        if (text.includes('<rss') || text.includes('<feed')) {
          return candidate;
        }
      } catch {}
    }

    return u.toString();
  }

  async fetchSingleFeed(feedUrlInput, runtimeOpts = {}) {
    try {
      const resolvedUrl = await this.resolveFeedUrl(feedUrlInput, runtimeOpts);
      const xml = await this.fetchText(resolvedUrl, 7500, runtimeOpts);
      const parsed = parseFeedXml(xml, resolvedUrl);
      if (!parsed) {
        return { ok: false, feedUrl: resolvedUrl, error: t('rss.invalidXml') };
      }
      return {
        ok: true,
        ...parsed
      };
    } catch (err) {
      return {
        ok: false,
        feedUrl: String(feedUrlInput || ''),
        error: err.message
      };
    }
  }

  async fetchMultipleFeeds(feeds = [], runtimeOpts = {}) {
    const results = await Promise.all(
      feeds.map(async f => {
        const url = typeof f === 'string' ? f : f.url;
        const category = typeof f === 'object' && f.category ? f.category : 'Genel';
        const customTitle = typeof f === 'object' && f.title ? f.title : '';
        const res = await this.fetchSingleFeed(url, runtimeOpts);
        if (res.ok) {
          res.category = category;
          if (customTitle) res.title = customTitle;
          res.items = res.items.map(it => ({
            ...it,
            feedTitle: customTitle || res.title,
            category
          }));
        }
        return res;
      })
    );

    const allItems = results
      .filter(r => r.ok && Array.isArray(r.items))
      .flatMap(r => r.items)
      .sort((a, b) => b.timestamp - a.timestamp);

    return {
      ok: true,
      feeds: results,
      items: allItems
    };
  }
}

module.exports = {
  RssService,
  parseFeedXml
};
