const test = require('node:test');
const assert = require('node:assert/strict');

const { setLang } = require('../src/i18n/translations');
const {
  performMetaSearch,
  buildAnonHeaders,
  DEFAULT_PROVIDERS,
  queryDuckDuckGo,
  unwrapSearchRedirect
} = require('../src/search/meta-search');

test('buildAnonHeaders strips OS/UI-locale/Referer/DNT/sec-ch-ua leaks by default', () => {
  setLang('tr');
  const h = buildAnonHeaders();
  assert.equal(/electron|zaslon/i.test(h['User-Agent']), false);
  assert.match(h['User-Agent'], /Chrome\/131\.0\.0\.0/);
  assert.equal(h['Accept-Language'], 'en-US,en;q=0.5');
  assert.equal(/tr-tr/i.test(h['Accept-Language']), false);
  assert.equal('Referer' in h, false);
  assert.equal('Origin' in h, false);
  assert.equal('DNT' in h, false);
  assert.equal('sec-ch-ua' in h, false);
  assert.equal(h['Sec-GPC'], '1');

  const reg = buildAnonHeaders({ regional: true });
  assert.match(reg['Accept-Language'], /^tr-TR/i);
});

test('DEFAULT_PROVIDERS disables yahoo by default and performMetaSearch skips yahoo.com unless enabled', async () => {
  assert.equal(DEFAULT_PROVIDERS.yahoo, false);
  assert.equal(DEFAULT_PROVIDERS.duckduckgo, true);
  assert.equal(DEFAULT_PROVIDERS.brave, true);

  const visitedUrls = [];
  const recordedInit = [];
  const mockFetch = async (url, init) => {
    visitedUrls.push(url);
    recordedInit.push(init);

    if (url.startsWith('https://html.duckduckgo.com/')) {
      return {
        ok: true,
        async text() {
          return `
            <div class="result results_links_deep web-result">
              <a class="result__a" href="https://html.duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.org%2Fdoc%3Futm_source%3Dddg">Privacy Doc</a>
              <a class="result__snippet">Independent privacy guide</a>
            </div></div>
          `;
        }
      };
    }

    if (url.startsWith('https://search.brave.com/')) {
      return {
        ok: true,
        async text() {
          return `
            <div data-type="web">
              <a href="https://example.org/doc?utm_medium=brave"><div class="title">Privacy Doc</div></a>
              <div class="snippet-description">Matched on Brave too</div>
            </div>
          `;
        }
      };
    }

    if (url.includes('search.yahoo.com')) {
      return {
        ok: true,
        async text() {
          return `
            <div class="dd algo">
              <h3><a href="https://r.search.yahoo.com/RU=https%3A%2F%2Fyahoo-only.example%2Fpage/RK=2/RS=x">Yahoo Extra Hit</a></h3>
              <div class="compText"><p>Opt-in index snippet</p></div>
            </div>
          `;
        }
      };
    }

    return { ok: false, status: 404, async text() { return ''; }, async json() { return {}; } };
  };

  setLang('tr');
  const defaultRes = await performMetaSearch('privacy test', { fetchFn: mockFetch });
  assert.equal(defaultRes.ok, true);
  assert.equal(visitedUrls.some(u => u.includes('yahoo.com')), false);
  assert.equal(visitedUrls.some(u => u.includes('kl=')), false);
  // Wikipedia defaults to 'en' when regional is false
  assert.equal(visitedUrls.some(u => u.startsWith('https://tr.wikipedia.org/')), false);
  assert.ok(visitedUrls.some(u => u.startsWith('https://en.wikipedia.org/')));
  assert.ok(recordedInit.every(i => i.credentials === 'omit' && i.referrerPolicy === 'no-referrer'));
  assert.equal(defaultRes.results.length, 1);
  assert.equal(defaultRes.results[0].url, 'https://example.org/doc');
  assert.deepEqual(defaultRes.results[0].engines.sort(), ['Brave', 'DuckDuckGo']);
  assert.ok(defaultRes.strippedCount >= 2);

  // Explicit opt-in for Yahoo & regional mode
  visitedUrls.length = 0;
  const optInRes = await performMetaSearch('privacy test', {
    fetchFn: mockFetch,
    regional: true,
    providers: { yahoo: true }
  });
  assert.equal(optInRes.ok, true);
  assert.equal(visitedUrls.some(u => u.startsWith('https://tr.search.yahoo.com/')), true);
  assert.equal(visitedUrls.some(u => u.includes('kl=tr-tr')), true);
  assert.equal(optInRes.results.some(r => r.url === 'https://yahoo-only.example/page'), true);
});

test('performMetaSearch with requireTor fails closed with 0 HTTP calls when Tor is not connected', async () => {
  let called = 0;
  const spyFetch = async () => {
    called++;
    throw new Error('Must not hit network when requireTor is active and Tor is disconnected');
  };

  const blocked = await performMetaSearch('sensitive query', {
    fetchFn: spyFetch,
    requireTor: true,
    torConnected: false
  });
  assert.equal(blocked.ok, false);
  assert.equal(blocked.blockedByTor, true);
  assert.equal(blocked.routedVia, 'tor');
  assert.deepEqual(blocked.results, []);
  assert.equal(called, 0);
});

test('performMetaSearch with requireTor false succeeds when Tor is disconnected and allows ephemeral fallback', async () => {
  let called = 0;
  const mockFetch = async () => {
    called++;
    return {
      ok: true,
      async text() {
        return '<div class="result web-result"><a class="result__a" href="https://example.org/clean">Clean</a></div>';
      }
    };
  };

  const res = await performMetaSearch('clearnet query', {
    fetchFn: mockFetch,
    requireTor: false,
    torConnected: false
  });
  assert.equal(res.ok, true);
  assert.equal(res.blockedByTor, undefined);
  assert.equal(res.routedVia, 'ephemeral');
  assert.ok(called > 0);
});

test('queryDuckDuckGo omits kl by default and unwrapSearchRedirect resolves DDG/Yahoo/Bing wrappers locally', async () => {
  const seen = [];
  await queryDuckDuckGo(
    async url => {
      seen.push(url);
      return { ok: true, async text() { return ''; } };
    },
    'zero leak'
  );
  assert.equal(seen[0], 'https://html.duckduckgo.com/html/?q=zero%20leak');

  const bingB64 = Buffer.from('https://target.example/path', 'utf8').toString('base64');
  assert.equal(
    unwrapSearchRedirect(`https://www.bing.com/ck/a?!&&p=1&u=a1${bingB64}`),
    'https://target.example/path'
  );
  assert.equal(
    unwrapSearchRedirect('https://duckduckgo.com/l/?uddg=https%3A%2F%2Fclean.example%2Fok'),
    'https://clean.example/ok'
  );
  assert.equal(
    unwrapSearchRedirect('https://r.search.yahoo.com/_ylt=1/RU=https%3A%2F%2Fy.example%2F1/RK=2/RS=3'),
    'https://y.example/1'
  );
});

test('main.js and ui.html properly synchronize metaSearchRequireTor, metaSearchRouting, and ephemeral container switch', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'main.js'), 'utf8');
  const uiSrc = fs.readFileSync(path.join(__dirname, '..', 'ui.html'), 'utf8');

  // Verify main.js uses tabContainer / container from opts and guards shouldUseTor with (torConnected || requireTor)
  assert.ok(mainSrc.includes('const tabContainer = opts.container || tabRec?.container;'));
  assert.ok(mainSrc.includes('(torConnected || requireTor)'));
  assert.ok(mainSrc.includes('requireTor: Boolean(shouldUseTor && !torConnected)'));

  // Verify ui.html passes container & isTorTab, syncs routing on toggle, and provides switchToIsoBtn
  assert.ok(uiSrc.includes('container:tab.container'));
  assert.ok(uiSrc.includes('isTorTab'));
  assert.ok(uiSrc.includes("p.metaSearchRouting=p.metaSearchRequireTor?'tor':'tab'"));
  assert.ok(uiSrc.includes('zspSwitchNormalBtn'));
  assert.ok(uiSrc.includes('search.switchToIsoBtn'));
});
