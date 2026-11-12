/**
 * Zaslon Browser — Faz 3/D: Şifreli DNS (DNS-over-HTTPS / DoH) Yöneticisi
 * - Electron/Chromium yerleşik HostResolver üzerinden Quad9, Mullvad, AdGuard, Cloudflare veya Özel DoH yapılandırması
 * - RFC 8484 ikili DNS wireformat (application/dns-message) tabanlı sıfır sızıntılı çözümleyici
 * - Canlı DoH bağlantı ve gecikme (ms) testi
 */

const http2 = require('http2');
const net = require('net');
const tls = require('tls');
const { t } = require('../i18n/translations');

const DOH_PROVIDERS = {
  quad9: {
    id: 'quad9',
    nameKey: 'doh.quad9.name',
    name: 'Quad9 (9.9.9.9 — İsviçre)',
    template: 'https://dns.quad9.net/dns-query',
    dohEndpoint: 'https://dns.quad9.net/dns-query',
    bootstrapIps: ['9.9.9.9', '149.112.112.112'],
    descKey: 'doh.quad9.desc',
    desc: 'İsviçre gizlilik yasaları korumalı, zararlı alan adı ve oltalama engelleyici.'
  },
  mullvad: {
    id: 'mullvad',
    nameKey: 'doh.mullvad.name',
    name: 'Mullvad Privacy DNS',
    template: 'https://dns.mullvad.net/dns-query',
    dohEndpoint: 'https://dns.mullvad.net/dns-query',
    bootstrapIps: ['194.242.2.2'],
    descKey: 'doh.mullvad.desc',
    desc: 'İsveç merkezli, %100 anonim ve sıfır telemetri odaklı şifreli DNS.'
  },
  adguard: {
    id: 'adguard',
    nameKey: 'doh.adguard.name',
    name: 'AdGuard DNS',
    template: 'https://dns.adguard-dns.com/dns-query',
    dohEndpoint: 'https://dns.adguard-dns.com/dns-query',
    bootstrapIps: ['94.140.14.14', '94.140.15.15'],
    descKey: 'doh.adguard.desc',
    desc: 'DNS katmanında reklam, izleyici ve telemetri sunucularını keser.'
  },
  cloudflare: {
    id: 'cloudflare',
    nameKey: 'doh.cloudflare.name',
    name: 'Cloudflare (1.1.1.1)',
    template: 'https://cloudflare-dns.com/dns-query',
    dohEndpoint: 'https://cloudflare-dns.com/dns-query',
    bootstrapIps: ['1.1.1.1', '1.0.0.1'],
    descKey: 'doh.cloudflare.desc',
    desc: 'Hızlı, sıfır kayıt politikası ve DNSSEC destekli şifreli DNS.'
  },
  custom: {
    id: 'custom',
    nameKey: 'doh.custom.name',
    name: 'Özel DoH Sunucusu',
    template: '',
    dohEndpoint: '',
    bootstrapIps: [],
    descKey: 'doh.custom.desc',
    desc: 'Kendi belirlediğiniz RFC 8484 uyumlu https://.../dns-query şablonu.'
  }
};

/**
 * Saf JS RFC 1035 / RFC 8484 DNS sorgu paketi oluşturur (ID=0x0000).
 */
function buildDnsQueryPacket(hostname, qtype = 1) {
  const cleanHost = String(hostname || '').trim().replace(/\.+$/, '');
  const labels = cleanHost.split('.').filter(Boolean);
  if (!labels.length) {
    throw new Error('Invalid DNS hostname');
  }
  const labelBuffers = labels.map(label => {
    const b = Buffer.from(label, 'utf8');
    if (b.length === 0 || b.length > 63) {
      throw new Error('Invalid DNS label length');
    }
    return Buffer.concat([Buffer.from([b.length]), b]);
  });

  const header = Buffer.from([
    0x00, 0x00, // ID: RFC 8484 recommends 0
    0x01, 0x00, // Flags: standard query, RD=1
    0x00, 0x01, // QDCOUNT = 1
    0x00, 0x00, // ANCOUNT = 0
    0x00, 0x00, // NSCOUNT = 0
    0x00, 0x00  // ARCOUNT = 0
  ]);
  const questionFooter = Buffer.from([
    0x00, // Root label
    (qtype >> 8) & 0xff,
    qtype & 0xff, // QTYPE (1 = A)
    0x00,
    0x01 // QCLASS = IN
  ]);

  return Buffer.concat([header, ...labelBuffers, questionFooter]);
}

function skipDnsName(buf, offset) {
  let pos = offset;
  let hops = 0;
  while (pos < buf.length && hops < 64) {
    const len = buf[pos];
    if (len === 0) return pos + 1;
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) return -1;
      return pos + 2;
    }
    pos += 1 + len;
    hops++;
  }
  return -1;
}

/**
 * RFC 8484 DNS wireformat yanıtından ilk geçerli IPv4 (A) kaydını ve TTL değerini okur.
 */
function parseDnsResponsePacket(buf) {
  const packet = Buffer.isBuffer(buf) ? buf : Buffer.from(buf || []);
  if (packet.length < 12) return null;

  const qdCount = packet.readUInt16BE(4);
  const anCount = packet.readUInt16BE(6);
  let pos = 12;

  for (let i = 0; i < qdCount; i++) {
    pos = skipDnsName(packet, pos);
    if (pos < 0 || pos + 4 > packet.length) return null;
    pos += 4; // QTYPE + QCLASS
  }

  for (let i = 0; i < anCount; i++) {
    pos = skipDnsName(packet, pos);
    if (pos < 0 || pos + 10 > packet.length) return null;
    const type = packet.readUInt16BE(pos);
    const cls = packet.readUInt16BE(pos + 2);
    const ttl = packet.readUInt32BE(pos + 4);
    const rdLength = packet.readUInt16BE(pos + 8);
    pos += 10;
    if (pos + rdLength > packet.length) return null;

    if (type === 1 && cls === 1 && rdLength === 4) {
      const ip = `${packet[pos]}.${packet[pos + 1]}.${packet[pos + 2]}.${packet[pos + 3]}`;
      return { ip, ttl };
    }
    pos += rdLength;
  }
  return null;
}

function findBootstrapIpsForEndpoint(epUrl) {
  for (const prov of Object.values(DOH_PROVIDERS)) {
    if ((prov.dohEndpoint === epUrl || prov.template === epUrl) && Array.isArray(prov.bootstrapIps)) {
      return prov.bootstrapIps;
    }
  }
  return [];
}

/**
 * Tek bir TLS ClientHello kaydini TCP katmaninda kucuk parcalara ayirarak SNI DPI engellerini asar.
 */
function splitTlsClientHelloForBootstrap(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 10 || buf[0] !== 0x16 || buf[1] !== 0x03) {
    return [buf];
  }
  const recVersionMinor = buf[2];
  const recLen = buf.readUInt16BE(3);
  if (buf.length < 5 + recLen || recLen < 8) {
    return [buf.subarray(0, 2), buf.subarray(2, 5), buf.subarray(5)];
  }
  const payload = buf.subarray(5, 5 + recLen);
  const trailing = buf.subarray(5 + recLen);
  const pts = [...new Set([2, Math.min(24, Math.floor(payload.length / 2))])].filter(
    x => x > 0 && x < payload.length
  );
  pts.sort((a, b) => a - b);

  const records = [];
  let prev = 0;
  for (const pt of pts) {
    const part = payload.subarray(prev, pt);
    records.push(Buffer.from([0x16, 0x03, recVersionMinor, (part.length >> 8) & 0xff, part.length & 0xff]), part);
    prev = pt;
  }
  const lastPart = payload.subarray(prev);
  records.push(
    Buffer.from([0x16, 0x03, recVersionMinor, (lastPart.length >> 8) & 0xff, lastPart.length & 0xff]),
    lastPart
  );
  if (trailing.length > 0) records.push(trailing);
  return [Buffer.concat(records.slice(0, 2)), Buffer.concat(records.slice(2))];
}

function createBootstrapTcpSocket(host, port, fragmentTls) {
  const sock = net.connect({ host, port, noDelay: true });
  if (!fragmentTls) return sock;
  let firstWriteDone = false;
  const origWrite = sock.write.bind(sock);
  sock.write = function (chunk, encoding, cb) {
    if (!firstWriteDone) {
      firstWriteDone = true;
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, typeof encoding === 'string' ? encoding : undefined);
      if (buf[0] === 0x16 && buf[1] === 0x03) {
        const parts = splitTlsClientHelloForBootstrap(buf);
        let idx = 0;
        const doneCb = typeof encoding === 'function' ? encoding : cb;
        const sendNext = () => {
          if (sock.destroyed) return;
          if (idx >= parts.length - 1) {
            return origWrite(parts[idx], doneCb);
          }
          origWrite(parts[idx++], () => setTimeout(sendNext, 2));
        };
        sendNext();
        return true;
      }
    }
    return origWrite(chunk, encoding, cb);
  };
  return sock;
}

/**
 * RFC 8484 DoH POST istegini HTTP/2 uzerinden (ve varsa bootstrap IP'ye dogrudan) gonderir.
 * Quad9 (HTTP/2 zorunlu) ve Mullvad ile tam uyumludur; İSS DNS'ine basvurmaz.
 */
function postDnsViaHttp2(epUrl, queryPacket, { bootstrapIp = '', fragmentTls = false, timeoutMs = 3500 } = {}) {
  return new Promise((resolve, reject) => {
    let u;
    try {
      u = new URL(epUrl);
    } catch (err) {
      return reject(err);
    }

    const targetHost = bootstrapIp || u.hostname;
    const targetPort = Number(u.port) || 443;
    let settled = false;
    let client = null;
    let tlsSock = null;
    let tcpSock = null;

    const finish = (err, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        if (client && !client.destroyed) client.close();
      } catch {}
      if (err) {
        try {
          if (client && !client.destroyed) client.destroy();
          if (tlsSock && !tlsSock.destroyed) tlsSock.destroy();
          if (tcpSock && !tcpSock.destroyed) tcpSock.destroy();
        } catch {}
        reject(err);
      } else {
        resolve(result);
      }
    };

    const timer = setTimeout(() => finish(new Error('DoH HTTP/2 timeout')), timeoutMs);

    try {
      client = http2.connect(u.origin, {
        createConnection: () => {
          tcpSock = createBootstrapTcpSocket(targetHost, targetPort, fragmentTls);
          tcpSock.on('error', err => finish(err));
          tlsSock = tls.connect({
            socket: tcpSock,
            servername: u.hostname,
            ALPNProtocols: ['h2'],
            rejectUnauthorized: true
          });
          tlsSock.on('error', err => finish(err));
          return tlsSock;
        }
      });
    } catch (err) {
      return finish(err);
    }

    client.on('error', err => finish(err));

    let req;
    try {
      req = client.request({
        ':method': 'POST',
        ':path': `${u.pathname || '/dns-query'}${u.search || ''}`,
        ':authority': u.host,
        accept: 'application/dns-message',
        'content-type': 'application/dns-message',
        'content-length': queryPacket.length
      });
    } catch (err) {
      return finish(err);
    }

    let status = 0;
    const chunks = [];
    req.on('response', headers => {
      status = Number(headers[':status'] || 0);
    });
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      finish(null, {
        ok: status >= 200 && status < 300,
        status,
        buffer: Buffer.concat(chunks)
      });
    });
    req.on('error', err => finish(err));
    req.end(queryPacket);
  });
}

class DohManager {
  constructor({ app, fetchFn, fallbackFetchFn } = {}) {
    this.app = app;
    this.customFetchFn = typeof fetchFn === 'function' ? fetchFn : null;
    this.fallbackFetchFn = typeof fallbackFetchFn === 'function' ? fallbackFetchFn : null;
    this.fetchFn = this.customFetchFn || global.fetch;
    this.enabled = true;
    this.provider = 'quad9';
    this.customUrl = '';
    this.strictMode = true; // secure-only veya automatic
    this.dnsCache = new Map(); // hostname -> { ip, expiresAt }
    this.inflightQueries = new Map(); // hostname -> Promise<string|null>
    this.lastStatus = {
      active: false,
      provider: 'quad9',
      template: DOH_PROVIDERS.quad9.template,
      mode: 'secure',
      lastLatencyMs: null
    };
  }

  getActiveTemplate() {
    if (!this.enabled) return '';
    if (this.provider === 'custom') {
      const cleaned = this.customUrl.trim();
      return /^https:\/\//i.test(cleaned) ? cleaned : '';
    }
    const p = DOH_PROVIDERS[this.provider] || DOH_PROVIDERS.quad9;
    return p.template;
  }

  _getEndpointCandidates() {
    if (!this.enabled) return [];
    const primary = this.getActiveTemplate();
    const list = [];
    if (primary && /^https:\/\//i.test(primary)) {
      list.push(primary);
    }
    if (!this.strictMode) {
      for (const id of ['quad9', 'mullvad']) {
        const ep = DOH_PROVIDERS[id].dohEndpoint;
        if (ep && !list.includes(ep)) list.push(ep);
      }
    }
    return list;
  }

  /**
   * Electron app.configureHostResolver ile Chromium seviyesinde Şifreli DNS uygular
   */
  applyConfig({ enabled, provider, customUrl, strictMode } = {}) {
    const prevKey = `${this.enabled}|${this.provider}|${this.customUrl}|${this.strictMode}`;
    if (typeof enabled === 'boolean') this.enabled = enabled;
    if (provider && (DOH_PROVIDERS[provider] || provider === 'off')) {
      if (provider === 'off') {
        this.enabled = false;
      } else {
        this.provider = provider;
      }
    }
    if (typeof customUrl === 'string') this.customUrl = customUrl.trim();
    if (typeof strictMode === 'boolean') this.strictMode = strictMode;

    const nextKey = `${this.enabled}|${this.provider}|${this.customUrl}|${this.strictMode}`;
    if (prevKey !== nextKey) {
      this.dnsCache.clear();
    }

    const template = this.getActiveTemplate();
    const mode = !this.enabled || !template ? 'off' : this.strictMode ? 'secure' : 'automatic';

    if (this.app && typeof this.app.configureHostResolver === 'function') {
      try {
        if (mode === 'off') {
          this.app.configureHostResolver({
            enableBuiltInResolver: true,
            secureDnsMode: 'off'
          });
        } else {
          this.app.configureHostResolver({
            enableBuiltInResolver: true,
            secureDnsMode: mode,
            secureDnsServers: [template],
            enableAdditionalDnsQueryTypes: true
          });
        }
      } catch {}
    }

    const activeProv = DOH_PROVIDERS[this.provider] || DOH_PROVIDERS.quad9;
    this.lastStatus = {
      active: mode !== 'off',
      provider: this.provider,
      providerName: t(activeProv.nameKey),
      template,
      mode,
      lastLatencyMs: this.lastStatus.lastLatencyMs
    };

    return this.getStatus();
  }

  getStatus() {
    const activeProv = DOH_PROVIDERS[this.provider] || DOH_PROVIDERS.quad9;
    return {
      enabled: this.enabled,
      provider: this.provider,
      customUrl: this.customUrl,
      strictMode: this.strictMode,
      ...this.lastStatus,
      providerName: t(activeProv.nameKey),
      providers: Object.values(DOH_PROVIDERS).map(p => ({
        id: p.id,
        name: t(p.nameKey),
        template: p.template,
        desc: t(p.descKey)
      }))
    };
  }

  async _fetchDnsViaFetchFn(fetchFn, ep, queryPacket) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 3500);
    try {
      const res = await fetchFn(ep, {
        method: 'POST',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        headers: {
          Accept: 'application/dns-message',
          'Content-Type': 'application/dns-message'
        },
        body: queryPacket,
        signal: ctrl.signal
      });
      if (!res || !res.ok) return null;
      return Buffer.from(await res.arrayBuffer());
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  async _queryEndpoint(ep, queryPacket) {
    if (this.customFetchFn) {
      return await this._fetchDnsViaFetchFn(this.customFetchFn, ep, queryPacket);
    }

    const bootstrapIps = findBootstrapIpsForEndpoint(ep);
    if (bootstrapIps.length > 0) {
      for (const ip of bootstrapIps) {
        for (const fragmentTls of [false, true]) {
          try {
            const res = await postDnsViaHttp2(ep, queryPacket, {
              bootstrapIp: ip,
              fragmentTls,
              timeoutMs: 3500
            });
            if (res.ok && res.buffer.length > 0) {
              return res.buffer;
            }
          } catch {}
        }
      }
      return null;
    }

    // Özel DoH şablonu (bootstrapIps yok): önce HTTP/2 (gerekirse TLS parçalama), sonra fallbackFetchFn
    for (const fragmentTls of [false, true]) {
      try {
        const res = await postDnsViaHttp2(ep, queryPacket, {
          fragmentTls,
          timeoutMs: 3500
        });
        if (res.ok && res.buffer.length > 0) {
          return res.buffer;
        }
      } catch {}
    }

    if (this.fallbackFetchFn) {
      return await this._fetchDnsViaFetchFn(this.fallbackFetchFn, ep, queryPacket);
    }
    return null;
  }

  /**
   * İSS DNS zehirlemesini aşmak için seçili sağlayıcının RFC 8484 ikili DoH API'si üzerinden IPv4 çözümler.
   * Yerleşik Anti-DPI Proxy tarafından kullanılır. Cloudflare'e sessiz sızıntı yapmaz.
   */
  async resolveHostViaDoH(hostname) {
    const cleanHost = String(hostname || '').trim().toLowerCase();
    if (!cleanHost) return null;
    if (net.isIP(cleanHost) !== 0 || cleanHost === 'localhost') {
      return cleanHost;
    }

    const now = Date.now();
    const cached = this.dnsCache.get(cleanHost);
    if (cached && cached.expiresAt > now) {
      return cached.ip;
    }

    if (this.inflightQueries.has(cleanHost)) {
      return await this.inflightQueries.get(cleanHost);
    }

    const endpoints = this._getEndpointCandidates();
    if (!endpoints.length) return null;

    let queryPacket;
    try {
      queryPacket = buildDnsQueryPacket(cleanHost, 1);
    } catch {
      return null;
    }

    const lookupPromise = (async () => {
      for (const ep of endpoints) {
        const buf = await this._queryEndpoint(ep, queryPacket);
        if (!buf) continue;
        const parsed = parseDnsResponsePacket(buf);
        if (parsed && /^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.ip)) {
          const ttlMs = Math.max(60, Math.min(3600, Number(parsed.ttl) || 300)) * 1000;
          this.dnsCache.set(cleanHost, { ip: parsed.ip, expiresAt: Date.now() + ttlMs });
          return parsed.ip;
        }
      }
      return null;
    })();

    this.inflightQueries.set(cleanHost, lookupPromise);
    try {
      return await lookupPromise;
    } finally {
      this.inflightQueries.delete(cleanHost);
    }
  }

  /**
   * Aktif Şifreli DNS bağlantısını test eder ve gecikme süresini (ms) döndürür.
   */
  async testConnection() {
    const start = Date.now();
    try {
      const ip = await this.resolveHostViaDoH('example.com');
      const tookMs = Date.now() - start;
      if (ip) {
        this.lastStatus.lastLatencyMs = tookMs;
        return {
          ok: true,
          resolvedIp: ip,
          latencyMs: tookMs,
          providerName: t((DOH_PROVIDERS[this.provider] || DOH_PROVIDERS.quad9).nameKey),
          template: this.getActiveTemplate()
        };
      }
      return { ok: false, error: t('doh.noResponse') };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }
}

module.exports = {
  DOH_PROVIDERS,
  DohManager,
  buildDnsQueryPacket,
  parseDnsResponsePacket
};
