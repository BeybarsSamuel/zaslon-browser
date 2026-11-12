/**
 * Zaslon Browser — Faz 2: Çerezsiz ve Kimliksiz Meta-Arama Motoru (zaslon://search)
 *
 * Arka planda DuckDuckGo, Brave Search, Web İndeksi (Yahoo/Bing organik indeks çözücü),
 * Wikipedia (TR/EN), DuckDuckGo Instant Answer ve isteğe bağlı özel SearXNG sunucusuna
 * çerezsiz (credentials: 'omit') istek atar.
 *
 * Tüm yönlendirme (redirect) sarmalayıcılarını (uddg=, RU=, u=a1...) yerel olarak çözer,
 * reklamları ve takip parametrelerini (ClearURLs) temizler, sonuçları tekilleştirir
 * ve hangi motorların aynı sonucu bulduğunu rozetlerle birleştirir.
 */

const { cleanTrackingUrl } = require('../privacy/url-cleaner');
const { t, getLang, getLangMeta } = require('../i18n/translations');
const { getUniformBrowserUserAgent } = require('../privacy/chromium-hardening');

const NEUTRAL_USER_AGENT = getUniformBrowserUserAgent();

const DEFAULT_PROVIDERS = Object.freeze({
  duckduckgo: true,
  brave: true,
  wikipedia: true,
  instant: true,
  searxng: true,
  yahoo: false
});

const STRIPPED_HEADER_RX = /^(referer|origin|dnt|sec-ch-ua.*)$/i;

function buildAnonHeaders(options = {}) {
  let acceptLang = 'en-US,en;q=0.5';
  if (options && options.regional) {
    const loc = options.locale || getLangMeta().locale || 'en-US';
    const short = options.lang || getLang() || 'en';
    acceptLang = loc === 'en-US' ? 'en-US,en;q=0.5' : `${loc},${short};q=0.8,en-US;q=0.5,en;q=0.3`;
  }
  return {
    'User-Agent': NEUTRAL_USER_AGENT,
    Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': acceptLang,
    'Sec-GPC': '1',
    'Cache-Control': 'no-store'
  };
}

function resolveProviders(customProviders = {}) {
  const merged = { ...DEFAULT_PROVIDERS };
  if (customProviders && typeof customProviders === 'object') {
    for (const key of Object.keys(DEFAULT_PROVIDERS)) {
      if (typeof customProviders[key] === 'boolean') {
        merged[key] = customProviders[key];
      }
    }
  }
  return merged;
}

const AD_URL_PATTERNS = [
  /duckduckgo\.com\/y\.js/i,
  /googleadservices\.com/i,
  /doubleclick\.net/i,
  /bing\.com\/aclick/i,
  /search\.yahoo\.com\/cbclk/i,
  /yandex\.(ru|com\.tr)\/clck\/jsredir/i,
  /ad\.doubleclick/i
];

const NAMED_ENTITIES = {
  '&amp;': '&',
  '&quot;': '"',
  '&#39;': "'",
  '&apos;': "'",
  '&#x27;': "'",
  '&lt;': '<',
  '&gt;': '>',
  '&nbsp;': ' ',
  '&ouml;': 'ö',
  '&Ouml;': 'Ö',
  '&uuml;': 'ü',
  '&Uuml;': 'Ü',
  '&ccedil;': 'ç',
  '&Ccedil;': 'Ç',
  '&ndash;': '–',
  '&mdash;': '—',
  '&rsquo;': '’',
  '&lsquo;': '‘',
  '&ldquo;': '“',
  '&rdquo;': '”',
  '&hellip;': '…',
  '&bull;': '•',
  '&middot;': '·'
};

function decodeHtmlEntities(str) {
  if (!str) return '';
  return String(str)
    .replace(/<[^>]+>/g, ' ')
    .replace(
      /&(?:amp|quot|#39|apos|#x27|lt|gt|nbsp|ouml|Ouml|uuml|Uuml|ccedil|Ccedil|ndash|mdash|rsquo|lsquo|ldquo|rdquo|hellip|bull|middot);/g,
      m => NAMED_ENTITIES[m] || m
    )
    .replace(/&#(\d+);/g, (_m, dec) => String.fromCharCode(Number(dec)))
    .replace(/&#x([0-9a-f]+);/gi, (_m, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Arama motorlarının yönlendirme (redirect) linklerini sunucuya dokunmadan yerelde çözer.
 */
function unwrapSearchRedirect(rawUrl) {
  if (!rawUrl) return '';
  let url = rawUrl.replace(/&amp;/g, '&').trim();
  if (url.startsWith('//')) url = 'https:' + url;

  // 1. DuckDuckGo (/l/?uddg=...)
  if (url.includes('uddg=')) {
    try {
      const u = new URL(url, 'https://html.duckduckgo.com');
      const uddg = u.searchParams.get('uddg');
      if (uddg) url = uddg;
    } catch {}
  }

  // 2. Yahoo Redirect (/RU=https%3a%2f%2f.../RK=...)
  const ruMatch = url.match(/\/RU=([^/]+)\/RK=/i);
  if (ruMatch && ruMatch[1]) {
    try {
      url = decodeURIComponent(ruMatch[1]);
    } catch {}
  }

  // 3. Bing Redirect (bing.com/ck/a?...&u=a1aHR0cHM6Ly9...)
  if (url.includes('bing.com/ck/a')) {
    try {
      const u = new URL(url);
      const enc = u.searchParams.get('u');
      if (enc && enc.startsWith('a1')) {
        const b64 = enc.slice(2).replace(/-/g, '+').replace(/_/g, '/');
        const decoded = Buffer.from(b64, 'base64').toString('utf8');
        if (/^https?:\/\//i.test(decoded)) url = decoded;
      }
    } catch {}
  }

  return url;
}

function normalizeUrlForDedup(rawUrl) {
  try {
    const cleaned = cleanTrackingUrl(unwrapSearchRedirect(rawUrl)).url;
    const u = new URL(cleaned);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return '';
    let pathname = u.pathname.replace(/\/+$/, '') || '/';
    try {
      pathname = decodeURIComponent(pathname);
    } catch {}
    const host = u.hostname.replace(/^www\./i, '').toLowerCase();
    return `${host}${pathname}${u.search}`;
  } catch {
    return '';
  }
}

function isAdUrl(rawUrl) {
  if (!rawUrl) return true;
  return AD_URL_PATTERNS.some(rx => rx.test(rawUrl));
}

async function fetchWithTimeout(fetchFn, url, options = {}, timeoutMs = 4500) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const { headerOpts, headers: customHeaders, ...restOptions } = options || {};
  const mergedHeaders = {
    ...buildAnonHeaders(headerOpts || {}),
    ...(customHeaders || {})
  };
  for (const key of Object.keys(mergedHeaders)) {
    if (STRIPPED_HEADER_RX.test(key)) {
      delete mergedHeaders[key];
    }
  }
  try {
    const res = await fetchFn(url, {
      ...restOptions,
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      signal: controller.signal,
      headers: mergedHeaders
    });
    return res;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * 1. DuckDuckGo HTML Parser (Çerezsiz, Reklamsız)
 */
function parseDuckDuckGoHtml(html) {
  const results = [];
  if (!html) return results;

  const blockRegex =
    /<div[^>]+class="[^"]*\bresult\b(?![^"]*result--ad)[^"]*"[\s\S]*?<\/div>\s*<\/div>/gi;
  const blocks = html.match(blockRegex) || [];

  for (const block of blocks) {
    if (/result--ad|badge--ad/i.test(block)) continue;

    const titleMatch = block.match(
      /<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/i
    );
    if (!titleMatch) continue;

    const originalHref = titleMatch[1];
    const rawHref = unwrapSearchRedirect(originalHref);
    if (!rawHref.startsWith('http') || isAdUrl(rawHref)) continue;
    const cleaned = cleanTrackingUrl(rawHref);

    const title = decodeHtmlEntities(titleMatch[2]);
    if (!title) continue;

    const snippetMatch = block.match(
      /<a[^>]+class="[^"]*result__snippet[^"]*"[^>]*>([\s\S]*?)<\/a>/i
    );
    const snippet = snippetMatch ? decodeHtmlEntities(snippetMatch[1]) : '';

    results.push({
      title,
      url: cleaned.url,
      snippet,
      engine: 'DuckDuckGo',
      stripped: (rawHref !== originalHref ? 1 : 0) + cleaned.removedCount
    });
  }

  return results;
}

async function queryDuckDuckGo(fetchFn, query, opts = {}) {
  let url = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`;
  if (opts && opts.regional) {
    const kl = opts.kl || `${getLang()}-${getLang()}`;
    url += `&kl=${encodeURIComponent(kl)}`;
  }
  const res = await fetchWithTimeout(fetchFn, url, { headerOpts: opts });
  if (!res.ok) return [];
  const html = await res.text();
  return parseDuckDuckGoHtml(html);
}

/**
 * 2. Brave Search HTML Parser (Çerezsiz, Bağımsız İndeks)
 */
function parseBraveHtml(html) {
  const results = [];
  if (!html) return results;

  const blocks = html.split(/data-type="web"/i).slice(1);
  for (const block of blocks) {
    const linkMatch = block.match(/<a[^>]+href="(https?:\/\/[^"]+)"[^>]*>([\s\S]*?)<\/a>/i);
    if (!linkMatch) continue;
    const rawUrl = unwrapSearchRedirect(linkMatch[1]);
    if (
      rawUrl.includes('brave.com') ||
      rawUrl.includes('search.brave.com') ||
      isAdUrl(rawUrl)
    ) {
      continue;
    }

    const titleMatch =
      block.match(/<div[^>]+class="[^"]*title[^"]*"[^>]*>([\s\S]*?)<\/div>/i) || linkMatch;
    const title = decodeHtmlEntities(titleMatch[1] || linkMatch[2]);
    if (!title || title.length < 2) continue;

    const descMatch = block.match(
      /<div[^>]+class="[^"]*(?:snippet-description|snippet-content|generic-snippet)[^"]*"[^>]*>([\s\S]*?)<\/div>/i
    );
    const snippet = descMatch ? decodeHtmlEntities(descMatch[1]) : '';
    const cleaned = cleanTrackingUrl(rawUrl);

    results.push({
      title,
      url: cleaned.url,
      snippet,
      engine: 'Brave',
      stripped: cleaned.removedCount
    });
  }

  return results;
}

async function queryBrave(fetchFn, query, opts = {}) {
  const url = `https://search.brave.com/search?q=${encodeURIComponent(query)}&source=web`;
  const res = await fetchWithTimeout(fetchFn, url, { headerOpts: opts });
  if (!res.ok) return [];
  const html = await res.text();
  return parseBraveHtml(html);
}

/**
 * 3. Yahoo / Bing Organik İndeks Çözücü (Yönlendirme izleyicilerini tamamen soyar)
 */
function parseYahooHtml(html) {
  const results = [];
  if (!html) return results;

  const blocks = html.split(/<div class="dd algo/i).slice(1);
  for (const block of blocks) {
    const aMatch = block.match(/<h3[^>]*>[\s\S]*?<a[^>]+href="([^"]+)"([^>]*)>([\s\S]*?)<\/a>/i);
    if (!aMatch) continue;

    const originalHref = aMatch[1];
    const rawUrl = unwrapSearchRedirect(originalHref);
    if (!rawUrl.startsWith('http') || rawUrl.includes('yahoo.com') || isAdUrl(rawUrl)) continue;

    const ariaMatch = aMatch[2].match(/aria-label="([^"]+)"/i);
    let title = ariaMatch ? decodeHtmlEntities(ariaMatch[1]) : '';
    if (!title) {
      const cleanedInner = aMatch[3].replace(/<span[^>]*>[\s\S]*?<\/span>/gi, '');
      title = decodeHtmlEntities(cleanedInner);
    }
    if (!title) continue;

    const pMatch = block.match(
      /<div[^>]+class="[^"]*compText[^"]*"[^>]*>[\s\S]*?<p[^>]*>([\s\S]*?)<\/p>/i
    );
    const snippet = pMatch ? decodeHtmlEntities(pMatch[1]) : '';
    const cleaned = cleanTrackingUrl(rawUrl);

    results.push({
      title,
      url: cleaned.url,
      snippet,
      engine: t('search.webIndex'),
      stripped: (rawUrl !== originalHref ? 1 : 0) + cleaned.removedCount
    });
  }

  return results;
}

async function queryYahooOrganics(fetchFn, query, opts = {}) {
  const regionalHost = opts.regional
    ? { tr: 'tr.search.yahoo.com', de: 'de.search.yahoo.com' }[opts.lang || getLang()] || 'search.yahoo.com'
    : 'search.yahoo.com';
  const url = `https://${regionalHost}/search?p=${encodeURIComponent(query)}`;
  const res = await fetchWithTimeout(fetchFn, url, { headerOpts: opts });
  if (!res.ok) return [];
  const html = await res.text();
  return parseYahooHtml(html);
}

/**
 * 4. Wikipedia (EN varsayılan / bölgesel açıksa UI dili) Arama & Bilgi Kartı
 */
async function queryWikipedia(fetchFn, query, opts = {}) {
  const wikiLang = opts.wikiLang || (opts.regional ? getLang() : 'en');
  const trUrl = `https://${wikiLang}.wikipedia.org/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(
    query
  )}&srlimit=4&utf8=1&format=json`;
  const res = await fetchWithTimeout(fetchFn, trUrl, {
    headerOpts: opts,
    headers: { Accept: 'application/json' }
  });
  if (!res.ok) return { results: [], instant: null };
  const data = await res.json();
  const items = data?.query?.search || [];

  const results = items.map(item => ({
    title: `${decodeHtmlEntities(item.title)} — ${t('search.wikiSuffix')}`,
    url: `https://${wikiLang}.wikipedia.org/wiki/${encodeURIComponent(item.title.replace(/ /g, '_'))}`,
    snippet: decodeHtmlEntities(item.snippet),
    engine: 'Wikipedia',
    stripped: 0
  }));

  let instant = null;
  if (items.length > 0) {
    const top = items[0];
    const slug = encodeURIComponent(top.title.replace(/ /g, '_'));
    instant = {
      title: decodeHtmlEntities(top.title),
      snippet: decodeHtmlEntities(top.snippet),
      url: `https://${wikiLang}.wikipedia.org/wiki/${slug}`,
      source: t('search.wikiSource')
    };
    if (opts.loadImages) {
      try {
        const sumRes = await fetchWithTimeout(
          fetchFn,
          `https://${wikiLang}.wikipedia.org/api/rest_v1/page/summary/${slug}`,
          { headerOpts: opts, headers: { Accept: 'application/json' } },
          2500
        );
        if (sumRes.ok) {
          const sumData = await sumRes.json();
          if (sumData.extract) instant.snippet = sumData.extract;
          if (sumData.thumbnail?.source) instant.image = sumData.thumbnail.source;
        }
      } catch {}
    }
  }

  return { results, instant };
}

/**
 * 5. DuckDuckGo Instant Answer API (Anlık Bilgi Kartı)
 */
async function queryInstantAnswer(fetchFn, query, opts = {}) {
  const url = `https://api.duckduckgo.com/?q=${encodeURIComponent(
    query
  )}&format=json&no_html=1&skip_disambig=1`;
  const res = await fetchWithTimeout(fetchFn, url, {
    headerOpts: opts,
    headers: { Accept: 'application/json' }
  });
  if (!res.ok) return null;
  const data = await res.json();
  if (data && data.AbstractText && data.AbstractURL) {
    return {
      title: data.Heading || query,
      snippet: data.AbstractText,
      url: data.AbstractURL,
      image: data.Image
        ? data.Image.startsWith('http')
          ? data.Image
          : `https://duckduckgo.com${data.Image}`
        : null,
      source: data.AbstractSource || t('search.infoCard')
    };
  }
  return null;
}

/**
 * 6. Özel SearXNG Sunucusu Desteği (İsteğe Bağlı)
 */
async function queryCustomSearxng(fetchFn, searxngBaseUrl, query, opts = {}) {
  if (!searxngBaseUrl || !/^https?:\/\//i.test(searxngBaseUrl)) return [];
  const base = searxngBaseUrl.replace(/\/+$/, '');
  const url = `${base}/search?q=${encodeURIComponent(query)}&format=json`;
  const res = await fetchWithTimeout(fetchFn, url, {
    headerOpts: opts,
    headers: { Accept: 'application/json' }
  });
  if (!res.ok) return [];
  const data = await res.json();
  if (!Array.isArray(data?.results)) return [];
  return data.results
    .filter(r => r && r.url && !isAdUrl(r.url))
    .slice(0, 15)
    .map(r => {
      const cleaned = cleanTrackingUrl(unwrapSearchRedirect(r.url));
      return {
        title: decodeHtmlEntities(r.title || r.url),
        url: cleaned.url,
        snippet: decodeHtmlEntities(r.content || ''),
        engine: 'SearXNG',
        stripped: cleaned.removedCount
      };
    });
}

/**
 * Sonuçları Birleştirme, Tekilleştirme (Deduplication) ve Puanlama
 */
function mergeAndRankResults(providerLists) {
  const byKey = new Map();
  let strippedAdsAndTrackers = 0;

  for (const list of providerLists) {
    if (!Array.isArray(list)) continue;
    list.forEach((item, index) => {
      if (!item || !item.url || isAdUrl(item.url)) {
        strippedAdsAndTrackers++;
        return;
      }
      const unwrapped = unwrapSearchRedirect(item.url);
      const cleaned = cleanTrackingUrl(unwrapped);
      const itemStripped =
        (item.stripped || 0) +
        (unwrapped !== item.url ? 1 : 0) +
        cleaned.removedCount;
      strippedAdsAndTrackers += itemStripped;

      const key = normalizeUrlForDedup(cleaned.url);
      if (!key) return;

      const rankScore = Math.max(1, 20 - index);
      if (!byKey.has(key)) {
        byKey.set(key, {
          title: item.title,
          url: cleaned.url,
          snippet: item.snippet || '',
          engines: [item.engine],
          score: rankScore
        });
      } else {
        const existing = byKey.get(key);
        if (!existing.engines.includes(item.engine)) {
          existing.engines.push(item.engine);
          existing.score += rankScore + 8; // Birden fazla motorun doğruladığı sonuçlara ekstra öncelik
        }
        if ((!existing.snippet || existing.snippet.length < 40) && item.snippet) {
          existing.snippet = item.snippet;
        }
        if ((!existing.title || existing.title.length < 10) && item.title) {
          existing.title = item.title;
        }
      }
    });
  }

  const merged = [...byKey.values()].sort((a, b) => b.score - a.score);
  return { results: merged, strippedAdsAndTrackers };
}

/**
 * Ana Meta-Arama Orkestratörü
 */
async function performMetaSearch(query, options = {}) {
  const q = String(query || '').trim();
  const fetchFn = options.fetchFn || globalThis.fetch;
  const searxngUrl = options.searxngUrl || '';
  const regional = Boolean(options.regional);
  const providersCfg = resolveProviders(options.providers);
  const routedVia = options.routedVia || (options.requireTor ? 'tor' : 'ephemeral');
  const startedAt = Date.now();

  if (!q) {
    return {
      ok: true,
      query: '',
      tookMs: 0,
      results: [],
      instant: null,
      providers: {},
      activeProviders: [],
      routedVia,
      regional,
      strippedCount: 0
    };
  }

  if (options.requireTor && options.torConnected === false) {
    return {
      ok: false,
      blockedByTor: true,
      routedVia: 'tor',
      regional,
      query: q,
      tookMs: 0,
      results: [],
      instant: null,
      providers: {},
      activeProviders: [],
      strippedCount: 0,
      error: options.torError || t('search.errTorRequired')
    };
  }

  const reqOpts = {
    regional,
    lang: options.lang,
    locale: options.locale,
    kl: options.kl
  };

  const tasks = [];
  const activeProviders = [];

  if (providersCfg.searxng && searxngUrl) {
    activeProviders.push('SearXNG');
    tasks.push(
      queryCustomSearxng(fetchFn, searxngUrl, q, reqOpts).then(
        res => ({ name: 'SearXNG', ok: res.length > 0, results: res }),
        () => ({ name: 'SearXNG', ok: false, results: [] })
      )
    );
  }
  if (providersCfg.duckduckgo) {
    activeProviders.push('DuckDuckGo');
    tasks.push(
      queryDuckDuckGo(fetchFn, q, reqOpts).then(
        res => ({ name: 'DuckDuckGo', ok: true, results: res }),
        () => ({ name: 'DuckDuckGo', ok: false, results: [] })
      )
    );
  }
  if (providersCfg.brave) {
    activeProviders.push('Brave');
    tasks.push(
      queryBrave(fetchFn, q, reqOpts).then(
        res => ({ name: 'Brave', ok: true, results: res }),
        () => ({ name: 'Brave', ok: false, results: [] })
      )
    );
  }
  if (providersCfg.wikipedia) {
    activeProviders.push('Wikipedia');
    tasks.push(
      queryWikipedia(fetchFn, q, reqOpts).then(
        res => ({ name: 'Wikipedia', ok: true, results: res.results, instant: res.instant }),
        () => ({ name: 'Wikipedia', ok: false, results: [], instant: null })
      )
    );
  }
  if (providersCfg.instant) {
    tasks.push(
      queryInstantAnswer(fetchFn, q, reqOpts).then(
        instant => ({ name: 'Instant', ok: !!instant, results: [], instant }),
        () => ({ name: 'Instant', ok: false, results: [], instant: null })
      )
    );
  }
  if (providersCfg.yahoo) {
    activeProviders.push(t('search.webIndex'));
    tasks.push(
      queryYahooOrganics(fetchFn, q, reqOpts).then(
        res => ({ name: t('search.webIndex'), ok: true, results: res }),
        () => ({ name: t('search.webIndex'), ok: false, results: [] })
      )
    );
  }

  const settled = await Promise.all(tasks);

  const providerLists = [];
  const providers = {};
  let instant = null;

  for (const item of settled) {
    if (item.name === 'Instant') {
      if (item.instant) instant = item.instant;
      continue;
    }
    if (item.name === 'Wikipedia' && item.instant && !instant) {
      instant = item.instant;
    }
    providers[item.name] = {
      ok: item.ok && item.results.length > 0,
      count: item.results.length
    };
    providerLists.push(item.results);
  }

  const { results, strippedAdsAndTrackers } = mergeAndRankResults(providerLists);

  return {
    ok: true,
    query: q,
    tookMs: Date.now() - startedAt,
    results,
    instant,
    providers,
    activeProviders,
    routedVia,
    regional,
    strippedCount: strippedAdsAndTrackers
  };
}

module.exports = {
  performMetaSearch,
  buildAnonHeaders,
  resolveProviders,
  DEFAULT_PROVIDERS,
  parseDuckDuckGoHtml,
  parseBraveHtml,
  parseYahooHtml,
  queryDuckDuckGo,
  unwrapSearchRedirect,
  mergeAndRankResults,
  normalizeUrlForDedup
};
