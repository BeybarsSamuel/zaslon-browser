/**
 * Zaslon Browser — Faz 1: @ghostery/adblocker-electron Motoru & Canlı İstek Denetçisi
 * - Sıfır başlangıç pingi ile çalışan yerleşik EasyList + EasyPrivacy + Türkçe + d3ward kuralları
 * - İsteğe bağlı çevrimiçi filtre güncelleme ve yerel önbellekleme
 * - Sekme bazlı Canlı Gizlilik Sayacı & İstek Denetçisi (Live Request Inspector)
 */

const fs = require('fs');
const path = require('path');
const { ElectronBlocker, fromElectronDetails } = require('@ghostery/adblocker-electron');
const { isTelemetryHost } = require('./chromium-hardening');
const { getBaseDomain } = require('./url-cleaner');
const { t, MESSAGES } = require('../i18n/translations');

const ADBLOCK_KEY_BY_LABEL = new Map();
for (const dict of Object.values(MESSAGES)) {
  for (const [k, v] of Object.entries(dict)) {
    if (k.startsWith('adblock.')) ADBLOCK_KEY_BY_LABEL.set(v, k);
  }
}

// Yerleşik kapsamlı filtre listesi (EasyList + EasyPrivacy + Türkçe Reklam Ağları + d3ward Test Kapsamı)
const BUILTIN_RULES = [
  // Google Ads, DoubleClick, Analytics, Tag Manager
  '||doubleclick.net^',
  '||googlesyndication.com^',
  '||googleadservices.com^',
  '||google-analytics.com^',
  '||googletagmanager.com^',
  '||googletagservices.com^',
  '||adservice.google.com^',
  '||adservice.google.com.tr^',
  '||pagead2.googlesyndication.com^',
  '||adsensecustomsearchads.com^',
  '||2mdn.net^',
  '||imasdk.googleapis.com^$third-party',
  '||fundingchoicesmessages.google.com^',

  // Meta / Facebook / Instagram / WhatsApp / TikTok / X / LinkedIn / Pinterest / Snapchat / Reddit Ads
  '||connect.facebook.net^$third-party',
  '||pixel.facebook.com^',
  '||an.facebook.com^',
  '||graph.facebook.com/tr^',
  '||ads-twitter.com^',
  '||static.ads-twitter.com^',
  '||analytics.twitter.com^',
  '||t.co/i/adsct^',
  '||ads.linkedin.com^',
  '||px.ads.linkedin.com^',
  '||analytics.tiktok.com^',
  '||ads-api.tiktok.com^',
  '||ads.tiktok.com^',
  '||business-api.tiktok.com^',
  '||log.byteoversea.com^',
  '||tr.snapchat.com^',
  '||sc-static.net/scevent.min.js^',
  '||ads.pinterest.com^',
  '||ct.pinterest.com^',
  '||trn.pinterest.com^',
  '||events.redditmedia.com^',
  '||alb.reddit.com^',
  '||ads.reddit.com^',

  // Amazon, Yahoo, Microsoft / Bing Ads
  '||amazon-adsystem.com^',
  '||aax.amazon-adsystem.com^',
  '||c.amazon-adsystem.com^',
  '||fls-na.amazon-adsystem.com^',
  '||assoc-amazon.com^',
  '||ads.yahoo.com^',
  '||analytics.yahoo.com^',
  '||gemini.yahoo.com^',
  '||udc.yahoo.com^',
  '||udcm.yahoo.com^',
  '||log.fc.yahoo.com^',
  '||adtech.de^',
  '||advertising.com^',
  '||bat.bing.com^',
  '||clarity.ms^',
  '||ads.msn.com^',
  '||rad.msn.com^',

  // Yandex & Rus Reklam / Metrica Ağları
  '||an.yandex.ru^',
  '||mc.yandex.ru^',
  '||mc.yandex.com^',
  '||bs.yandex.ru^',
  '||yabs.yandex.ru^',
  '||awaps.yandex.net^',
  '||adsfox.ru^',
  '||adfox.ru^',
  '||top-fwz1.mail.ru^',
  '||r.mail.ru^',
  '||vk.com/rtrg^',

  // Küresel Programatik Reklam Borsaları (SSP / DSP)
  '||adnxs.com^',
  '||adsrvr.org^',
  '||criteo.com^',
  '||criteo.net^',
  '||taboola.com^',
  '||outbrain.com^',
  '||scorecardresearch.com^',
  '||quantserve.com^',
  '||rubiconproject.com^',
  '||pubmatic.com^',
  '||ads.pubmatic.com^',
  '||openx.net^',
  '||moatads.com^',
  '||smartadserver.com^',
  '||casalemedia.com^',
  '||adform.net^',
  '||mathtag.com^',
  '||bluekai.com^',
  '||krxd.net^',
  '||demdex.net^',
  '||everesttech.net^',
  '||adcolony.com^',
  '||unityads.unity3d.com^',
  '||ads.prd.ie.internal.unity3d.com^',
  '||popads.net^',
  '||propellerads.com^',
  '||exoclick.com^',
  '||juicyads.com^',
  '||revcontent.com^',
  '||mgid.com^',
  '||zedo.com^',
  '||adroll.com^',
  '||yieldmo.com^',
  '||sharethrough.com^',
  '||media.net^',
  '||static.media.net^',
  '||adservetx.media.net^',
  '||bidswitch.net^',
  '||lijit.com^',
  '||sovrn.com^',
  '||teads.tv^',
  '||3lift.com^',
  '||triplelift.com^',
  '||indexww.com^',
  '||gumgum.com^',
  '||rtbhouse.com^',
  '||creativecdn.com^',
  '||adkernel.com^',
  '||admixer.net^',
  '||adition.com^',
  '||adscale.de^',
  '||adsafeprotected.com^',
  '||doubleverify.com^',
  '||serving-sys.com^',
  '||flashtalking.com^',
  '||innovid.com^',
  '||spotxchange.com^',
  '||springserve.com^',
  '||tapjoy.com^',
  '||vungle.com^',
  '||applovin.com^',
  '||chartboost.com^',
  '||inmobi.com^',
  '||ironsrc.com^',
  '||adjust.com^',
  '||appsflyer.com^',
  '||branch.io^$third-party',
  '||kochava.com^',
  '||singular.net^',

  // Analitik, Oturum Kaydı (Session Replay) ve Hata İzleyiciler
  '||hotjar.com^',
  '||hotjar.io^',
  '||static.hotjar.com^',
  '||mixpanel.com^',
  '||cdn.mxpnl.com^',
  '||segment.io^',
  '||segment.com^',
  '||cdn.segment.com^',
  '||amplitude.com^',
  '||api.amplitude.com^',
  '||fullstory.com^',
  '||mouseflow.com^',
  '||crazyegg.com^',
  '||luckyorange.com^',
  '||smartlook.com^',
  '||logrocket.io^',
  '||logrocket.com^',
  '||heapanalytics.com^',
  '||kissmetrics.com^',
  '||matomo.cloud^',
  '||piwik.pro^',
  '||plausible.io^$third-party',
  '||newrelic.com^$third-party',
  '||nr-data.net^',
  '||bam.nr-data.net^',
  '||bugsnag.com^',
  '||notify.bugsnag.com^',
  '||sessions.bugsnag.com^',
  '||sentry.io^$third-party',
  '||browser.sentry-cdn.com^',
  '||rollbar.com^',
  '||trackjs.com^',
  '||raygun.io^',
  '||datadoghq-browser-agent.com^',
  '||browser-intake-datadoghq.com^',
  '||onesignal.com^$third-party',
  '||pushengage.com^',
  '||webpushs.com^',
  '||izooto.com^',
  '||cleverpush.com^',

  // OEM (Xiaomi, Realme, Oppo, Huawei, Samsung, LG, Apple) Telemetri ve Reklam Sunucuları
  '||ad.xiaomi.com^',
  '||data.mistat.xiaomi.com^',
  '||data.mistat.intl.xiaomi.com^',
  '||data.mistat.india.xiaomi.com^',
  '||data.mistat.rus.xiaomi.com^',
  '||sdkconfig.ad.xiaomi.com^',
  '||sdkconfig.ad.intl.xiaomi.com^',
  '||tracking.rus.miui.com^',
  '||adsfs.oppomobile.com^',
  '||adx.ads.oppomobile.com^',
  '||bdapi.ads.oppomobile.com^',
  '||ck.ads.oppomobile.com^',
  '||data.ads.oppomobile.com^',
  '||iot-eu-logser.realme.com^',
  '||iot-logser.realme.com^',
  '||bdapi-ads.realmemobile.com^',
  '||bdapi-in-ads.realmemobile.com^',
  '||metrics.data.hicloud.com^',
  '||metrics2.data.hicloud.com^',
  '||grs.hicloud.com^',
  '||logservice.hicloud.com^',
  '||logservice1.hicloud.com^',
  '||logbak.hicloud.com^',
  '||samsungads.com^',
  '||smetrics.samsung.com^',
  '||nmetrics.samsung.com^',
  '||samsung-com.112.2o7.net^',
  '||analytics-api.samsunghealthcn.com^',
  '||iadsdk.apple.com^',
  '||metrics.icloud.com^',
  '||metrics.mzstatic.com^',
  '||api-adservices.apple.com^',
  '||books-analytics-events.apple.com^',
  '||weather-analytics-events.apple.com^',
  '||notes-analytics-events.apple.com^',

  // Türkiye Yerel Reklam, Bildirim ve Analitik Ağları (TR Filter)
  '||reklamstore.com^',
  '||admost.com^',
  '||medyanet.com.tr^',
  '||ad.medyanet.com.tr^',
  '||virgul.com^',
  '||enhencer.com^',
  '||segmentify.com^',
  '||cdn.segmentify.com^',
  '||useinsider.com^',
  '||api.useinsider.com^',
  '||netmera.com^',
  '||relateddigital.com^',
  '||euromsg.com^',
  '||dengage.com^',
  '||setrow.com^',
  '||efilli.com^',
  '||gemius.pl^',
  '||hit.gemius.pl^',
  '||tr.hit.gemius.pl^',
  '||adocean.pl^',
  '||rek.turkmedya.com.tr^',
  '||adsp.haberturk.com^',
  '||reklam.milliyet.com.tr^',
  '||reklam.hurriyet.com.tr^',
  '||reklam.sabah.com.tr^',
  '||reklam.sozcu.com.tr^',

  // Kozmetik Filtreler (Sayfa içi reklam kutuları ve boşlukları)
  '##.adsbygoogle',
  '##ins.adsbygoogle',
  '##[id^="google_ads_"]',
  '##[id^="div-gpt-ad"]',
  '##.ad-banner',
  '##.ad-container',
  '##.ad-wrapper',
  '##.ad-slot',
  '##.advertisement',
  '##.sponsored-content',
  '##.taboola-widget',
  '##.OUTBRAIN'
].join('\n');

const COSMETIC_BASE_CSS = `
  .adsbygoogle, ins.adsbygoogle, [id^="google_ads_"], [id^="div-gpt-ad"],
  .taboola-widget, .OUTBRAIN, [class*="sponsored-banner"],
  iframe[src*="doubleclick.net"], iframe[src*="googlesyndication.com"],
  iframe[src*="adnxs.com"], iframe[src*="criteo.com"] {
    display: none !important;
    height: 0 !important;
    min-height: 0 !important;
    visibility: hidden !important;
    pointer-events: none !important;
  }
`;

class AdblockAndInspectorEngine {
  constructor({ userDataPath, resourcesPath, onStatsIncrement, onInspectorUpdate }) {
    this.userDataPath = userDataPath;
    this.resourcesPath = resourcesPath || '';
    this.cachePath = path.join(userDataPath, 'zaslon-adblock-cache.bin');
    this.bundledSnapshotPath = [
      this.resourcesPath ? path.join(this.resourcesPath, 'adblock-snapshot.bin') : '',
      path.join(__dirname, '..', '..', 'resources', 'adblock-snapshot.bin')
    ].find(p => p && fs.existsSync(p)) || path.join(__dirname, '..', '..', 'resources', 'adblock-snapshot.bin');
    this.rulesConfigPath = path.join(userDataPath, 'zaslon-shield-rules.json');
    this.onStatsIncrement = onStatsIncrement || (() => {});
    this.onInspectorUpdate = onInspectorUpdate || (() => {});

    // Her sekme (tabId) için canlı istek kaydı
    this.tabReports = new Map();
    // webContents.id -> tabId eşlemesi
    this.wcToTabId = new Map();

    // Kullanıcı özel kuralları: siteWhitelist (Kalkan kapalı siteler) & domainRules (block/allow)
    this.siteWhitelist = new Set();
    this.customDomainRules = {}; // hostname -> 'block' | 'allow'
    this._loadCustomRules();

    // @ghostery/adblocker-electron motorunu sıfır ağ isteğiyle başlat (kullanıcı önbelleği -> yerel gömülü snapshot -> BUILTIN_RULES)
    this.blocker = this._initBlockerOffline();
    this._notifyTimer = null;
  }

  _initBlockerOffline() {
    for (const candidate of [this.cachePath, this.bundledSnapshotPath]) {
      try {
        if (candidate && fs.existsSync(candidate)) {
          const buf = fs.readFileSync(candidate);
          return ElectronBlocker.deserialize(new Uint8Array(buf));
        }
      } catch {}
    }
    return ElectronBlocker.parse(BUILTIN_RULES, { enableCompression: true });
  }

  _loadCustomRules() {
    try {
      if (fs.existsSync(this.rulesConfigPath)) {
        const data = JSON.parse(fs.readFileSync(this.rulesConfigPath, 'utf8'));
        if (Array.isArray(data.siteWhitelist)) {
          this.siteWhitelist = new Set(data.siteWhitelist);
        }
        if (data.customDomainRules && typeof data.customDomainRules === 'object') {
          this.customDomainRules = data.customDomainRules;
        }
      }
    } catch {}
  }

  _saveCustomRules() {
    try {
      fs.writeFileSync(
        this.rulesConfigPath,
        JSON.stringify(
          {
            siteWhitelist: [...this.siteWhitelist],
            customDomainRules: this.customDomainRules
          },
          null,
          2
        ),
        'utf8'
      );
    } catch {}
  }

  /**
   * Kullanıcı isterse (manuel butonla) EasyList + EasyPrivacy + uBlock listelerini indirip önbelleğe alır.
   */
  async updateFilterListsOnline(fetchFn) {
    const lists = [
      'https://easylist.to/easylist/easylist.txt',
      'https://easylist.to/easylist/easyprivacy.txt',
      'https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt',
      'https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt'
    ];
    const texts = [BUILTIN_RULES];
    for (const url of lists) {
      try {
        const res = await fetchFn(url);
        if (res.ok) texts.push(await res.text());
      } catch {}
    }
    const merged = texts.join('\n');
    this.blocker = ElectronBlocker.parse(merged, { enableCompression: true });
    try {
      const serialized = this.blocker.serialize();
      fs.writeFileSync(this.cachePath, Buffer.from(serialized));
    } catch {}
    return { ok: true, count: merged.split('\n').length };
  }

  registerWebContents(wcId, tabId) {
    this.wcToTabId.set(wcId, tabId);
    if (!this.tabReports.has(tabId)) {
      this._resetTabReport(tabId, '');
    }
  }

  unregisterTab(tabId) {
    this.tabReports.delete(tabId);
    for (const [wcId, tId] of this.wcToTabId.entries()) {
      if (tId === tabId) this.wcToTabId.delete(wcId);
    }
  }

  clearAllReports() {
    this.tabReports.clear();
  }

  _resetTabReport(tabId, pageUrl) {
    let pageHost = '';
    try {
      pageHost = new URL(pageUrl).hostname.replace(/^www\./, '');
    } catch {}
    this.tabReports.set(tabId, {
      tabId,
      pageUrl: pageUrl || '',
      pageHost,
      blockedCount: 0,
      allowedCount: 0,
      thirdPartyCount: 0,
      strippedParamsCount: 0,
      domains: new Map() // host -> { host, status, reason, count, types: Set, isThirdParty }
    });
  }

  onMainFrameNavigate(tabId, url) {
    this._resetTabReport(tabId, url);
    this._scheduleNotify(tabId);
  }

  recordStrippedParams(tabId, count) {
    if (!tabId || !count) return;
    const rep = this.tabReports.get(tabId);
    if (rep) {
      rep.strippedParamsCount += count;
      this._scheduleNotify(tabId);
    }
  }

  isSiteWhitelisted(pageHost) {
    if (!pageHost) return false;
    const base = getBaseDomain(pageHost);
    return this.siteWhitelist.has(pageHost) || this.siteWhitelist.has(base);
  }

  toggleSiteWhitelist(pageHost) {
    if (!pageHost) return false;
    const clean = pageHost.replace(/^www\./, '').toLowerCase();
    if (this.siteWhitelist.has(clean)) {
      this.siteWhitelist.delete(clean);
    } else {
      this.siteWhitelist.add(clean);
    }
    this._saveCustomRules();
    return this.siteWhitelist.has(clean);
  }

  setCustomDomainRule(domain, action) {
    if (!domain) return;
    const clean = domain.replace(/^www\./, '').toLowerCase();
    if (!action || action === 'reset') {
      delete this.customDomainRules[clean];
    } else if (action === 'block' || action === 'allow') {
      this.customDomainRules[clean] = action;
    }
    this._saveCustomRules();
  }

  _checkCustomDomainRule(hostname) {
    let h = (hostname || '').toLowerCase();
    while (h) {
      if (this.customDomainRules[h]) return this.customDomainRules[h];
      const dot = h.indexOf('.');
      if (dot < 0) break;
      h = h.slice(dot + 1);
    }
    return null;
  }

  /**
   * Electron webRequest.onBeforeRequest içinden her ağ isteğini değerlendirir.
   * Dönen değer: { cancel: boolean, reason: string }
   */
  evaluateRequest(details, prefs) {
    const urlStr = details.url || '';
    if (
      !urlStr.startsWith('http://') &&
      !urlStr.startsWith('https://') &&
      !urlStr.startsWith('ws://') &&
      !urlStr.startsWith('wss://')
    ) {
      return { cancel: false, reason: 'internal' };
    }

    let reqUrl;
    try {
      reqUrl = new URL(urlStr);
    } catch {
      return { cancel: false, reason: 'invalid' };
    }

    const reqHost = reqUrl.hostname.toLowerCase();
    const resType = details.resourceType || 'other';
    const tabId = this.wcToTabId.get(details.webContentsId);

    // Ana çerçeve (mainFrame) geçişiyse sekme raporunu sıfırla
    if (resType === 'mainFrame' && tabId) {
      this.onMainFrameNavigate(tabId, urlStr);
    }

    const rep = tabId ? this.tabReports.get(tabId) : null;
    const pageHost = rep?.pageHost || (() => {
      try {
        return new URL(details.referrer || urlStr).hostname.replace(/^www\./, '');
      } catch {
        return reqHost.replace(/^www\./, '');
      }
    })();

    const isThirdParty =
      Boolean(pageHost) && getBaseDomain(reqHost) !== getBaseDomain(pageHost);
    const siteWhitelisted = this.isSiteWhitelisted(pageHost);
    const securityLevel = prefs.securityLevel || 'standard';

    // 1. Zırh: Telemetri Güvenlik Duvarı (Her zaman çalışır, site beyaz listede olsa bile)
    if (prefs.tele !== false && isTelemetryHost(reqHost)) {
      const rTelemetry = t('adblock.telemetry');
      this._recordDomainEvent(rep, reqHost, 'blocked', rTelemetry, resType, isThirdParty);
      this.onStatsIncrement('ads', 1);
      return { cancel: true, reason: rTelemetry };
    }

    // 2. Zırh: 3 Kademeli Güvenlik Seviyesi (Tor Security Slider)
    if (resType !== 'mainFrame') {
      if (securityLevel === 'safest' && (resType === 'script' || resType === 'font')) {
        this._recordDomainEvent(rep, reqHost, 'blocked', t('adblock.paranoidJsFont'), resType, isThirdParty);
        return { cancel: true, reason: t('adblock.paranoid') };
      }
      if (
        securityLevel === 'safer' &&
        resType === 'script' &&
        (reqUrl.protocol === 'http:' || reqUrl.protocol === 'ws:' || (rep?.pageUrl && rep.pageUrl.startsWith('http://')))
      ) {
        this._recordDomainEvent(rep, reqHost, 'blocked', t('adblock.saferHttpJs'), resType, isThirdParty);
        return { cancel: true, reason: t('adblock.safer') };
      }
    }

    // 3. Zırh: Kullanıcının Canlı İstek Denetçisinden verdiği özel Alan Adı Kuralı (ana çerçeve dahil)
    const customRule = this._checkCustomDomainRule(reqHost);
    if (customRule === 'block') {
      const rRule = t('adblock.userRule');
      this._recordDomainEvent(rep, reqHost, 'blocked', rRule, resType, isThirdParty);
      this.onStatsIncrement('ads', 1);
      return { cancel: true, reason: rRule };
    }
    if (customRule === 'allow') {
      const rAllow = t('adblock.userAllow');
      this._recordDomainEvent(rep, reqHost, 'allowed', rAllow, resType, isThirdParty);
      return { cancel: false, reason: rAllow };
    }

    // 4. Zırh: @ghostery/adblocker-electron (EasyList + EasyPrivacy + Türkçe Filtreler + ana çerçeve reklam/yönlendirme engeli)
    if (prefs.adblock !== false && !siteWhitelisted) {
      try {
        const adReq = fromElectronDetails({
          url: urlStr,
          resourceType: resType,
          referrer: details.referrer || rep?.pageUrl || ''
        });
        const matchResult = this.blocker.match(adReq);
        if (matchResult && matchResult.match) {
          const rAd = t('adblock.adTracker');
          this._recordDomainEvent(rep, reqHost, 'blocked', rAd, resType, isThirdParty);
          this.onStatsIncrement('ads', 1);
          return { cancel: true, reason: rAd };
        }
      } catch {}
    }

    // İzin verilen isteği Canlı İstek Denetçisine kaydet
    this._recordDomainEvent(
      rep,
      reqHost,
      'allowed',
      isThirdParty ? t('adblock.thirdParty') : t('adblock.firstParty'),
      resType,
      isThirdParty
    );
    return { cancel: false, reason: 'allowed' };
  }

  _recordDomainEvent(rep, host, status, reason, resType, isThirdParty) {
    if (!rep) return;
    const cleanHost = host.replace(/^www\./, '');
    if (status === 'blocked') {
      rep.blockedCount++;
    } else {
      rep.allowedCount++;
    }

    let entry = rep.domains.get(cleanHost);
    if (!entry) {
      entry = {
        host: cleanHost,
        status,
        reason,
        count: 0,
        types: new Set(),
        isThirdParty,
        customRule: this._checkCustomDomainRule(cleanHost)
      };
      rep.domains.set(cleanHost, entry);
      if (isThirdParty) rep.thirdPartyCount++;
    }
    entry.count++;
    entry.types.add(resType);
    if (status === 'blocked') {
      entry.status = 'blocked';
      entry.reason = reason;
    }
    entry.customRule = this._checkCustomDomainRule(cleanHost);
    this._scheduleNotify(rep.tabId);
  }

  _scheduleNotify(tabId) {
    if (this._notifyTimer) return;
    this._notifyTimer = setTimeout(() => {
      this._notifyTimer = null;
      this.onInspectorUpdate(tabId, this.getTabInspectorReport(tabId));
    }, 250);
  }

  getTabInspectorReport(tabId) {
    const rep = this.tabReports.get(tabId);
    if (!rep) {
      return {
        tabId,
        pageUrl: '',
        pageHost: '',
        siteWhitelisted: false,
        blockedCount: 0,
        allowedCount: 0,
        thirdPartyCount: 0,
        strippedParamsCount: 0,
        domains: []
      };
    }
    const domainsList = [...rep.domains.values()]
      .map(d => {
        const rk = ADBLOCK_KEY_BY_LABEL.get(d.reason);
        return {
          host: d.host,
          status: d.status,
          reason: rk ? t(rk) : d.reason,
          count: d.count,
          types: [...d.types].slice(0, 4),
          isThirdParty: d.isThirdParty,
          customRule: this._checkCustomDomainRule(d.host)
        };
      })
      .sort((a, b) => {
        if (a.status !== b.status) return a.status === 'blocked' ? -1 : 1;
        if (a.isThirdParty !== b.isThirdParty) return a.isThirdParty ? -1 : 1;
        return b.count - a.count;
      });

    return {
      tabId: rep.tabId,
      pageUrl: rep.pageUrl,
      pageHost: rep.pageHost,
      siteWhitelisted: this.isSiteWhitelisted(rep.pageHost),
      blockedCount: rep.blockedCount,
      allowedCount: rep.allowedCount,
      thirdPartyCount: rep.thirdPartyCount,
      strippedParamsCount: rep.strippedParamsCount,
      domains: domainsList
    };
  }

  getCosmeticCssForPage() {
    return COSMETIC_BASE_CSS;
  }
}

module.exports = {
  AdblockAndInspectorEngine,
  COSMETIC_BASE_CSS
};
