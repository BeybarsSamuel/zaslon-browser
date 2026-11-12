const http = require('http');
const dgram = require('dgram');
const os = require('os');
const crypto = require('crypto');
const { t, getLang } = require('../i18n/translations');

const DEFAULT_HTTP_PORT = 49440;
const DISCOVERY_UDP_PORT = 49441;
const BEACON_MAGIC = 'ZASLON_LAN_V1';

/* ============================================================================
 * Saf JS ISO/IEC 18004 QR Code SVG Üretici (Sürüm 1–6, ECC Seviye L, Byte Modu)
 * Harici paket gerektirmeden Android/iOS kameralarıyla %100 taranabilir SVG üretir.
 * ============================================================================ */
const QR_VERSIONS = [
  null,
  { size: 21, totalCodewords: 26, ecCodewords: 7, align: [] },
  { size: 25, totalCodewords: 44, ecCodewords: 10, align: [6, 18] },
  { size: 29, totalCodewords: 70, ecCodewords: 15, align: [6, 22] },
  { size: 33, totalCodewords: 100, ecCodewords: 20, align: [6, 26] },
  { size: 37, totalCodewords: 134, ecCodewords: 26, align: [6, 30] },
  { size: 41, totalCodewords: 172, ecCodewords: 18, blocks: 2, align: [6, 34] }
];

const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) {
    GF_EXP[i] = GF_EXP[i - 255];
  }
})();

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function rsGeneratorPoly(degree) {
  let poly = new Uint8Array([1]);
  for (let i = 0; i < degree; i++) {
    const next = new Uint8Array(poly.length + 1);
    const root = GF_EXP[i];
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], root);
    }
    poly = next;
  }
  return poly;
}

function rsEncode(dataBytes, ecLen) {
  const gen = rsGeneratorPoly(ecLen);
  const msg = new Uint8Array(dataBytes.length + ecLen);
  msg.set(dataBytes, 0);
  for (let i = 0; i < dataBytes.length; i++) {
    const coef = msg[i];
    if (coef !== 0) {
      for (let j = 0; j < gen.length; j++) {
        msg[i + j] ^= gfMul(gen[j], coef);
      }
    }
  }
  return msg.slice(dataBytes.length);
}

function generateQrCodeSvg(text, boxSize = 188) {
  try {
    const utf8 = Buffer.from(String(text || ''), 'utf8');
    let ver = 1;
    while (ver <= 6) {
      const info = QR_VERSIONS[ver];
      const blocks = info.blocks || 1;
      const dataCap = info.totalCodewords - info.ecCodewords * blocks;
      if (utf8.length + 2 <= dataCap) break;
      ver++;
    }
    if (ver > 6) ver = 6;
    const info = QR_VERSIONS[ver];
    const blocks = info.blocks || 1;
    const dataCap = info.totalCodewords - info.ecCodewords * blocks;
    const payload = utf8.slice(0, dataCap - 2);

    // Bit akışı: 0100 (Byte mode) + 8-bit uzunluk + veri + 0000 sonlandırıcı
    const bits = [];
    const pushBits = (val, len) => {
      for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1);
    };
    pushBits(0b0100, 4);
    pushBits(payload.length, 8);
    for (const b of payload) pushBits(b, 8);
    const maxBits = dataCap * 8;
    for (let i = 0; i < 4 && bits.length < maxBits; i++) bits.push(0);
    while (bits.length % 8 !== 0) bits.push(0);

    const dataCodewords = new Uint8Array(dataCap);
    for (let i = 0; i < bits.length / 8; i++) {
      let byte = 0;
      for (let b = 0; b < 8; b++) byte = (byte << 1) | bits[i * 8 + b];
      dataCodewords[i] = byte;
    }
    let padToggle = true;
    for (let i = bits.length / 8; i < dataCap; i++) {
      dataCodewords[i] = padToggle ? 0xec : 0x11;
      padToggle = !padToggle;
    }

    let finalCodewords = [];
    if (blocks === 1) {
      const ec = rsEncode(dataCodewords, info.ecCodewords);
      finalCodewords = [...dataCodewords, ...ec];
    } else {
      const half = dataCap / 2;
      const b1 = dataCodewords.slice(0, half);
      const b2 = dataCodewords.slice(half);
      const ec1 = rsEncode(b1, info.ecCodewords);
      const ec2 = rsEncode(b2, info.ecCodewords);
      for (let i = 0; i < half; i++) finalCodewords.push(b1[i], b2[i]);
      for (let i = 0; i < info.ecCodewords; i++) finalCodewords.push(ec1[i], ec2[i]);
    }

    const size = info.size;
    const grid = Array.from({ length: size }, () => new Int8Array(size).fill(-1));
    const reserved = Array.from({ length: size }, () => new Uint8Array(size));

    const setMod = (r, c, val, res = true) => {
      if (r < 0 || c < 0 || r >= size || c >= size) return;
      grid[r][c] = val ? 1 : 0;
      if (res) reserved[r][c] = 1;
    };

    const placeFinder = (row, col) => {
      for (let r = -1; r <= 7; r++) {
        for (let c = -1; c <= 7; c++) {
          const rr = row + r;
          const cc = col + c;
          if (rr < 0 || cc < 0 || rr >= size || cc >= size) continue;
          const inOuter = r >= 0 && r <= 6 && c >= 0 && c <= 6;
          const inBorder = r === 0 || r === 6 || c === 0 || c === 6;
          const inCenter = r >= 2 && r <= 4 && c >= 2 && c <= 4;
          setMod(rr, cc, inOuter && (inBorder || inCenter), true);
        }
      }
    };

    placeFinder(0, 0);
    placeFinder(0, size - 7);
    placeFinder(size - 7, 0);

    // Alignment deseni
    if (info.align.length) {
      for (const ar of info.align) {
        for (const ac of info.align) {
          if (reserved[ar][ac]) continue;
          for (let r = -2; r <= 2; r++) {
            for (let c = -2; c <= 2; c++) {
              const dark = Math.max(Math.abs(r), Math.abs(c)) !== 1;
              setMod(ar + r, ac + c, dark, true);
            }
          }
        }
      }
    }

    // Timing çizgileri
    for (let i = 8; i < size - 8; i++) {
      if (!reserved[6][i]) setMod(6, i, i % 2 === 0, true);
      if (!reserved[i][6]) setMod(i, 6, i % 2 === 0, true);
    }

    // Dark modül ve Format alanları rezervasyonu
    setMod(size - 8, 8, 1, true);
    for (let i = 0; i < 9; i++) {
      if (!reserved[8][i]) reserved[8][i] = 1;
      if (!reserved[i][8]) reserved[i][8] = 1;
    }
    for (let i = 0; i < 8; i++) {
      if (!reserved[8][size - 1 - i]) reserved[8][size - 1 - i] = 1;
      if (!reserved[size - 1 - i][8]) reserved[size - 1 - i][8] = 1;
    }

    // Veri bitlerini zikzak yerleştir + Maske 0 ((r + c) % 2 === 0)
    const allBits = [];
    for (const cw of finalCodewords) {
      for (let b = 7; b >= 0; b--) allBits.push((cw >> b) & 1);
    }
    let bitIdx = 0;
    let upward = true;
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vert = 0; vert < size; vert++) {
        const r = upward ? size - 1 - vert : vert;
        for (let j = 0; j < 2; j++) {
          const c = right - j;
          if (!reserved[r][c]) {
            const bit = bitIdx < allBits.length ? allBits[bitIdx++] : 0;
            const masked = (r + c) % 2 === 0 ? bit ^ 1 : bit;
            grid[r][c] = masked;
          }
        }
      }
      upward = !upward;
    }

    // Format bilgisi: ECC Seviye L (01) + Maske 0 (000) => BCH(15,5) = 0x77c4
    const fmtBits = 0x77c4;
    const fBit = i => (fmtBits >> i) & 1;
    const fmtCoords1 = [
      [8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8],
      [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8]
    ];
    for (let i = 0; i < 15; i++) {
      const [r, c] = fmtCoords1[i];
      grid[r][c] = fBit(14 - i);
    }
    for (let i = 0; i < 7; i++) {
      grid[size - 1 - i][8] = fBit(14 - i);
    }
    for (let i = 7; i < 15; i++) {
      grid[8][size - 15 + i] = fBit(14 - i);
    }

    // SVG çıktısı
    const quiet = 2;
    const total = size + quiet * 2;
    let paths = '';
    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        if (grid[r][c] === 1) {
          paths += `M${c + quiet},${r + quiet}h1v1h-1z`;
        }
      }
    }
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${total}" width="${boxSize}" height="${boxSize}" shape-rendering="crispEdges" style="border-radius:12px;background:#fff;display:block;margin:0 auto"><rect width="${total}" height="${total}" fill="#ffffff"/><path d="${paths}" fill="#08101f"/></svg>`;
  } catch {
    return '';
  }
}

/**
 * Faz 5.2: Bulutsuz Yerel Ağ (LAN Wi-Fi) Cihazlar Arası Eşitleme & Aktarım Yöneticisi
 * - Google/Mozilla bulut sunucusu kullanmadan aynı ev Wi-Fi ağı üzerinden PC <-> Android / PC
 *   sekme, yer imi, okuma listesi, RSS ve metin/not aktarımı sağlar.
 * - 6 Haneli Oturum PIN Kodu + QR Token doğrulaması + AES-256-GCM uçtan uca paket şifrelemesi.
 * - UDP Broadcast (Port 49441) ile aynı ağdaki diğer Zaslon cihazlarını otomatik keşfeder.
 */
class LanSyncManager {
  constructor(options = {}) {
    this.onStateRequest = options.onStateRequest || (() => ({}));
    this.onReceiveItem = options.onReceiveItem || (() => {});
    this.onStatusChange = options.onStatusChange || (() => {});

    this.deviceId = 'zaslon-' + crypto.randomBytes(4).toString('hex');
    this.deviceName = t('lan.defaultDevice') || 'Zaslon Desktop';
    this.pin = this._generatePin();
    this.pairToken = crypto.randomBytes(12).toString('hex');
    this.usedAuthNonces = new Map();

    this.running = false;
    this.discoveryActive = false;
    this.httpPort = DEFAULT_HTTP_PORT;
    this.server = null;
    this.udpSocket = null;
    this.beaconTimer = null;
    this.discoveryTimer = null;

    this.peers = new Map(); // deviceId -> { deviceId, deviceName, ip, port, platform, lastSeen }
    this.transferLog = []; // [{ id, dir: 'in'|'out', type, summary, peer, timestamp }]
    this.latestSharedState = { tabs: [], bms: [], notes: '', rssFeeds: [] };
    this.failedAuthAttempts = 0;
    this.authLockedUntil = 0;
  }

  _generatePin() {
    return String(crypto.randomInt(100000, 999999));
  }

  regeneratePin() {
    this.pin = this._generatePin();
    this.pairToken = crypto.randomBytes(12).toString('hex');
    this.failedAuthAttempts = 0;
    this.authLockedUntil = 0;
    this._emitStatus();
    return this.getStatus();
  }

  updateSharedState(partial = {}) {
    if (Array.isArray(partial.tabs)) this.latestSharedState.tabs = partial.tabs;
    if (Array.isArray(partial.bms)) this.latestSharedState.bms = partial.bms;
    if (typeof partial.notes === 'string') this.latestSharedState.notes = partial.notes;
    if (Array.isArray(partial.rssFeeds)) this.latestSharedState.rssFeeds = partial.rssFeeds;
  }

  getLocalLanAddresses() {
    const nets = os.networkInterfaces();
    const candidates = [];
    for (const [ifName, addrs] of Object.entries(nets)) {
      if (!Array.isArray(addrs)) continue;
      const isVirtual = /vethernet|wsl|docker|vbox|vmware|hyper-v|loopback|tailscale|tun|tap/i.test(ifName);
      for (const a of addrs) {
        if ((a.family === 'IPv4' || a.family === 4) && !a.internal && a.address) {
          const isPrivateLan =
            a.address.startsWith('192.168.') ||
            a.address.startsWith('10.') ||
            /^172\.(1[6-9]|2\d|3[0-1])\./.test(a.address);
          candidates.push({
            ifName,
            address: a.address,
            score: (isPrivateLan ? 10 : 1) + (isVirtual ? 0 : 20)
          });
        }
      }
    }
    candidates.sort((a, b) => b.score - a.score);
    return candidates.length ? candidates.map(c => c.address) : ['127.0.0.1'];
  }

  _deriveKeyFromPin(pinStr, saltBuf) {
    const cleanPin = String(pinStr || '').replace(/\D/g, '');
    return crypto.scryptSync(`zaslon-lan-pin:${cleanPin}`, saltBuf, 32, { N: 4096, r: 8, p: 1 });
  }

  encryptLanPacket(payloadObj, pinStr) {
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(12);
    const key = this._deriveKeyFromPin(pinStr, salt);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const plain = Buffer.from(JSON.stringify(payloadObj), 'utf8');
    const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
      encrypted: true,
      cipher: 'AES-256-GCM',
      salt: salt.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      ciphertext: ct.toString('base64')
    };
  }

  decryptLanPacket(envelope, pinStr) {
    const salt = Buffer.from(envelope.salt, 'base64');
    const iv = Buffer.from(envelope.iv, 'base64');
    const tag = Buffer.from(envelope.tag, 'base64');
    const ct = Buffer.from(envelope.ciphertext, 'base64');
    const key = this._deriveKeyFromPin(pinStr, salt);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
    return JSON.parse(plain.toString('utf8'));
  }

  async start(preferredPort = DEFAULT_HTTP_PORT, opts = {}) {
    if (this.running && this.server) {
      if (opts && opts.discover === true) {
        this.startDiscovery(opts.discoveryMs);
      }
      return this.getStatus();
    }

    await new Promise(resolve => {
      const srv = http.createServer((req, res) => this._handleHttpRequest(req, res));
      srv.on('error', () => {
        // Tercih edilen port doluysa otomatik boş port ata
        srv.listen(0, '0.0.0.0', () => {
          this.httpPort = srv.address().port;
          this.server = srv;
          this.running = true;
          resolve();
        });
      });
      srv.listen(preferredPort, '0.0.0.0', () => {
        this.httpPort = srv.address().port;
        this.server = srv;
        this.running = true;
        resolve();
      });
    });

    // UDP keşif yayını yalnızca kullanıcı eşleştirme ekranını açıkça açtığında başlatılır
    if (opts && opts.discover === true) {
      this.startDiscovery(opts.discoveryMs);
    }
    this._emitStatus();
    return this.getStatus();
  }

  startDiscovery(maxDurationMs = 120000) {
    if (!this.running) return false;
    if (!this.udpSocket) {
      this._startUdpDiscovery();
    }
    this.discoveryActive = true;
    if (this.discoveryTimer) {
      clearTimeout(this.discoveryTimer);
      this.discoveryTimer = null;
    }
    if (maxDurationMs > 0) {
      this.discoveryTimer = setTimeout(() => {
        this.stopDiscovery();
      }, maxDurationMs);
      if (typeof this.discoveryTimer.unref === 'function') {
        this.discoveryTimer.unref();
      }
    }
    this._emitStatus();
    return true;
  }

  stopDiscovery() {
    this.discoveryActive = false;
    if (this.discoveryTimer) {
      clearTimeout(this.discoveryTimer);
      this.discoveryTimer = null;
    }
    if (this.beaconTimer) {
      clearInterval(this.beaconTimer);
      this.beaconTimer = null;
    }
    if (this.udpSocket) {
      try {
        this.udpSocket.close();
      } catch {}
      this.udpSocket = null;
    }
    this._emitStatus();
    return true;
  }

  async stop() {
    this.running = false;
    this.stopDiscovery();
    if (this.server) {
      if (typeof this.server.closeAllConnections === 'function') {
        this.server.closeAllConnections();
      }
      await new Promise(r => this.server.close(() => r()));
      this.server = null;
    }
    this._emitStatus();
    return this.getStatus();
  }

  _startUdpDiscovery() {
    try {
      const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
      sock.on('error', () => {});
      sock.on('message', (msg, rinfo) => {
        try {
          const data = JSON.parse(msg.toString('utf8'));
          if (data && data.magic === BEACON_MAGIC && data.deviceId && data.deviceId !== this.deviceId) {
            this.peers.set(data.deviceId, {
              deviceId: data.deviceId,
              deviceName: data.deviceName || t('lan.deviceFallback'),
              ip: rinfo.address,
              port: Number(data.port) || DEFAULT_HTTP_PORT,
              platform: data.platform || 'unknown',
              lastSeen: Date.now()
            });
            this._emitStatus();
          }
        } catch {}
      });

      sock.bind(DISCOVERY_UDP_PORT, () => {
        try {
          sock.setBroadcast(true);
        } catch {}
      });
      this.udpSocket = sock;

      const sendBeacon = () => {
        if (!this.running || !this.udpSocket) return;
        const packet = Buffer.from(
          JSON.stringify({
            magic: BEACON_MAGIC,
            deviceId: this.deviceId,
            deviceName: this.deviceName,
            platform: process.platform,
            port: this.httpPort,
            timestamp: Date.now()
          }),
          'utf8'
        );
        const targets = new Set(['255.255.255.255']);
        for (const ip of this.getLocalLanAddresses()) {
          const parts = ip.split('.');
          if (parts.length === 4) {
            parts[3] = '255';
            targets.add(parts.join('.'));
          }
        }
        for (const addr of targets) {
          try {
            this.udpSocket.send(packet, 0, packet.length, DISCOVERY_UDP_PORT, addr);
          } catch {}
        }
        // Eski peer kayıtlarını temizle (>30 sn)
        const now = Date.now();
        for (const [id, p] of this.peers.entries()) {
          if (now - p.lastSeen > 30000) this.peers.delete(id);
        }
      };

      sendBeacon();
      this.beaconTimer = setInterval(sendBeacon, 5000);
    } catch {}
  }

  _safeEqualStr(a, b) {
    const sa = String(a || '');
    const sb = String(b || '');
    if (!sa || sa.length !== sb.length) return false;
    return crypto.timingSafeEqual(Buffer.from(sa, 'utf8'), Buffer.from(sb, 'utf8'));
  }

  _buildPinAuthHeader(pinStr, method = 'POST', reqPath = '/api/sync/pull') {
    const cleanPin = String(pinStr || '').replace(/\D/g, '');
    const ts = String(Date.now());
    const nonce = crypto.randomBytes(8).toString('hex');
    const payload = `${ts}:${nonce}:${String(method).toUpperCase()}:${reqPath}`;
    const sig = crypto
      .createHmac('sha256', `zaslon-lan-auth:${cleanPin}`)
      .update(payload)
      .digest('hex');
    return `${ts}.${nonce}.${sig}`;
  }

  _verifyRequestAuth(req, parsedUrl, _bodyObj = null) {
    const authHeader = String(req.headers['x-zaslon-auth'] || '').trim();
    const parts = authHeader.split('.');
    if (parts.length !== 3) return false;

    const [tsStr, nonce, sigHex] = parts;
    const ts = Number(tsStr);
    const now = Date.now();
    if (!Number.isFinite(ts) || !nonce || nonce.length < 8 || Math.abs(now - ts) > 120_000) {
      return false;
    }

    for (const [k, exp] of this.usedAuthNonces) {
      if (exp < now) this.usedAuthNonces.delete(k);
    }
    if (this.usedAuthNonces.has(nonce)) {
      return false;
    }

    const method = String(req.method || 'GET').toUpperCase();
    const payload = `${tsStr}:${nonce}:${method}:${parsedUrl.pathname}`;
    const expected = crypto
      .createHmac('sha256', `zaslon-lan-auth:${this.pin}`)
      .update(payload)
      .digest('hex');
    if (this._safeEqualStr(sigHex.toLowerCase(), expected)) {
      this.usedAuthNonces.set(nonce, now + 125_000);
      if (this.usedAuthNonces.size > 512) {
        const oldestKey = this.usedAuthNonces.keys().next().value;
        this.usedAuthNonces.delete(oldestKey);
      }
      return true;
    }

    return false;
  }

  _handleAuthFailure(res, errMsg) {
    this.failedAuthAttempts++;
    if (this.failedAuthAttempts >= 5) {
      this.regeneratePin();
      this.authLockedUntil = Date.now() + 30_000;
      res.writeHead(429, {
        'Content-Type': 'application/json; charset=utf-8',
        'Retry-After': '30'
      });
      return res.end(JSON.stringify({ ok: false, error: 'Too many failed attempts; PIN rotated', rotated: true }));
    }
    res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' });
    return res.end(JSON.stringify({ ok: false, error: errMsg }));
  }

  _readJsonBody(req) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      let size = 0;
      req.on('data', ch => {
        size += ch.length;
        if (size > 5 * 1024 * 1024) {
          req.destroy();
          return reject(new Error('Payload too large'));
        }
        chunks.push(ch);
      });
      req.on('end', () => {
        try {
          const str = Buffer.concat(chunks).toString('utf8');
          resolve(str ? JSON.parse(str) : {});
        } catch (e) {
          reject(e);
        }
      });
      req.on('error', reject);
    });
  }

  _isAllowedOrigin(req) {
    const secFetchSite = String(req.headers['sec-fetch-site'] || '').toLowerCase();
    if (secFetchSite === 'cross-site') return false;

    const origin = req.headers.origin;
    if (!origin) return true;
    try {
      const parsed = new URL(origin);
      const reqHost = String(req.headers.host || '').toLowerCase();
      if (!reqHost) return false;
      return parsed.protocol === 'http:' && parsed.host.toLowerCase() === reqHost;
    } catch {
      return false;
    }
  }

  async _handleHttpRequest(req, res) {
    // Çapraz kökenli web isteklerini (Origin / CSRF / port taraması) engelle
    if (!this._isAllowedOrigin(req)) {
      res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' });
      return res.end(JSON.stringify({ ok: false, error: 'Cross-origin request denied' }));
    }

    if (req.method === 'OPTIONS') {
      res.writeHead(405);
      return res.end();
    }

    const parsedUrl = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const pathname = parsedUrl.pathname;

    const isApi = pathname.startsWith('/api/');
    if (isApi && Date.now() < this.authLockedUntil) {
      const retrySec = Math.max(1, Math.ceil((this.authLockedUntil - Date.now()) / 1000));
      res.writeHead(429, {
        'Content-Type': 'application/json; charset=utf-8',
        'Retry-After': String(retrySec)
      });
      return res.end(JSON.stringify({ ok: false, error: 'Auth temporarily locked', retryAfter: retrySec }));
    }

    if (pathname === '/api/ping') {
      if (!this._verifyRequestAuth(req, parsedUrl)) {
        return this._handleAuthFailure(res, t('lan.errInvalidAuth'));
      }
      this.failedAuthAttempts = 0;
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      return res.end(
        JSON.stringify({
          ok: true,
          app: 'Zaslon Browser',
          deviceId: this.deviceId,
          deviceName: this.deviceName,
          platform: process.platform,
          cipher: 'AES-256-GCM'
        })
      );
    }

    if (pathname === '/api/sync/pull') {
      let body = {};
      if (req.method === 'POST') {
        try {
          body = await this._readJsonBody(req);
        } catch {}
      }
      if (!this._verifyRequestAuth(req, parsedUrl, body)) {
        return this._handleAuthFailure(res, t('lan.errInvalidAuth'));
      }
      this.failedAuthAttempts = 0;
      if (body && body.wantEncrypted === false) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        return res.end(JSON.stringify({ ok: false, error: 'Plaintext sync mode is disabled; AES-256-GCM envelope required' }));
      }

      const fresh = this.onStateRequest() || this.latestSharedState;
      const statePayload = {
        deviceName: this.deviceName,
        timestamp: Date.now(),
        tabs: fresh.tabs || this.latestSharedState.tabs || [],
        bms: fresh.bms || this.latestSharedState.bms || [],
        notes: fresh.notes ?? this.latestSharedState.notes ?? '',
        rssFeeds: fresh.rssFeeds || this.latestSharedState.rssFeeds || []
      };

      // Şifresiz düz metin modu kaldırıldı: Her zaman AES-256-GCM şifreli zarf döndür
      const out = { ok: true, envelope: this.encryptLanPacket(statePayload, this.pin) };

      this._recordLog('out', 'pull', t('lan.stateShared', { tabs: statePayload.tabs.length, bms: statePayload.bms.length }), req.socket.remoteAddress);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      return res.end(JSON.stringify(out));
    }

    if (pathname === '/api/sync/push' && req.method === 'POST') {
      if (!this._verifyRequestAuth(req, parsedUrl)) {
        return this._handleAuthFailure(res, t('lan.errInvalidAuth'));
      }
      try {
        const body = await this._readJsonBody(req);
        if (!body || !body.envelope || !body.envelope.encrypted) {
          res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
          return res.end(JSON.stringify({ ok: false, error: 'Encrypted AES-256-GCM envelope required' }));
        }

        let itemPayload;
        try {
          itemPayload = this.decryptLanPacket(body.envelope, this.pin);
        } catch {
          return this._handleAuthFailure(res, t('lan.errDecryptPin'));
        }
        this.failedAuthAttempts = 0;

        const peerLabel = itemPayload.deviceName || req.socket.remoteAddress || t('lan.peerFallback');
        const summary = this._describeIncoming(itemPayload);
        this._recordLog('in', itemPayload.type || 'sync', summary, peerLabel);
        this.onReceiveItem({ ...itemPayload, fromPeer: peerLabel });

        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        return res.end(JSON.stringify({ ok: true, receivedAt: Date.now() }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        return res.end(JSON.stringify({ ok: false, error: err.message }));
      }
    }

    // Mobil / Tarayıcı Web Köprüsü Arayüzü (QR okutulduğunda açılan bulutsuz LAN arayüzü)
    const rawToken = parsedUrl.searchParams.get('t') || '';
    const prefillToken = this._safeEqualStr(rawToken, this.pairToken) ? rawToken : '';
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(this._renderMobileCompanionHtml(prefillToken));
  }

  _describeIncoming(p) {
    if (!p) return t('lan.inData');
    if (p.type === 'tab') return t('lan.inTab', { target: p.title || p.url || '' });
    if (p.type === 'tabs') return t('lan.inTabs', { count: (p.tabs || []).length });
    if (p.type === 'bookmarks') return t('lan.inBms', { count: (p.bms || []).length });
    if (p.type === 'note') return t('lan.inNote', { preview: String(p.text || '').slice(0, 32) });
    if (p.type === 'bundle') return t('lan.inBundle', { bms: (p.bms || []).length, tabs: (p.tabs || []).length });
    return t('lan.inSync');
  }

  _recordLog(dir, type, summary, peer) {
    this.transferLog.unshift({
      id: Date.now() + '-' + Math.random().toString(36).slice(2, 6),
      dir,
      type,
      summary,
      peer: String(peer || '').replace(/^::ffff:/, ''),
      timestamp: Date.now()
    });
    if (this.transferLog.length > 40) this.transferLog.length = 40;
    this._emitStatus();
  }

  /**
   * Başka bir Zaslon cihazına (PC veya Android) doğrudan AES-256-GCM şifreli paket gönderir
   */
  async pushToPeer(targetHost, targetPort, peerPin, payloadObj) {
    const cleanHost = String(targetHost || '').trim().replace(/^https?:\/\//, '').split('/')[0];
    const [hostOnly, portInHost] = cleanHost.split(':');
    const port = Number(targetPort || portInHost || DEFAULT_HTTP_PORT);
    const pin = String(peerPin || this.pin).replace(/\D/g, '');

    if (!hostOnly) return { ok: false, error: t('lan.errIpRequired') };
    if (!pin || pin.length < 4) return { ok: false, error: t('lan.errPinRequired') };

    const packet = {
      ...payloadObj,
      deviceName: this.deviceName,
      deviceId: this.deviceId,
      timestamp: Date.now()
    };
    const envelope = this.encryptLanPacket(packet, pin);
    const bodyStr = JSON.stringify({ envelope });

    return await new Promise(resolve => {
      const req = http.request(
        {
          hostname: hostOnly,
          port,
          path: '/api/sync/push',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Zaslon-Auth': this._buildPinAuthHeader(pin, 'POST', '/api/sync/push'),
            'Content-Length': Buffer.byteLength(bodyStr)
          },
          timeout: 6000
        },
        res => {
          const chunks = [];
          res.on('data', c => chunks.push(c));
          res.on('end', () => {
            try {
              const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
              if (res.statusCode === 200 && parsed.ok) {
                this._recordLog('out', payloadObj.type || 'push', t('lan.sentTo', { target: `${hostOnly}:${port}` }), `${hostOnly}:${port}`);
                resolve({ ok: true });
              } else {
                resolve({ ok: false, error: parsed.error || `HTTP ${res.statusCode}` });
              }
            } catch {
              resolve({ ok: false, error: t('lan.errInvalidResp') });
            }
          });
        }
      );
      req.on('timeout', () => {
        req.destroy();
        resolve({ ok: false, error: t('lan.errTimeoutWifi') });
      });
      req.on('error', err => resolve({ ok: false, error: err.message }));
      req.write(bodyStr);
      req.end();
    });
  }

  /**
   * Başka bir Zaslon cihazından (PC veya Android) açık sekmeleri, yer imlerini ve notları AES-256-GCM ile çeker
   */
  async pullFromPeer(targetHost, targetPort, peerPin) {
    const cleanHost = String(targetHost || '').trim().replace(/^https?:\/\//, '').split('/')[0];
    const [hostOnly, portInHost] = cleanHost.split(':');
    const port = Number(targetPort || portInHost || DEFAULT_HTTP_PORT);
    const pin = String(peerPin || this.pin).replace(/\D/g, '');

    if (!hostOnly) return { ok: false, error: t('lan.errIpRequired') };
    if (!pin || pin.length < 4) return { ok: false, error: t('lan.errPinRequired') };

    const bodyStr = JSON.stringify({ wantEncrypted: true });

    return await new Promise(resolve => {
      const req = http.request(
        {
          hostname: hostOnly,
          port,
          path: '/api/sync/pull',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Zaslon-Auth': this._buildPinAuthHeader(pin, 'POST', '/api/sync/pull'),
            'Content-Length': Buffer.byteLength(bodyStr)
          },
          timeout: 6000
        },
        res => {
          const chunks = [];
          res.on('data', c => chunks.push(c));
          res.on('end', () => {
            try {
              const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
              if (res.statusCode !== 200 || !parsed.ok) {
                return resolve({ ok: false, error: parsed.error || `HTTP ${res.statusCode}` });
              }
              const data = parsed.envelope
                ? this.decryptLanPacket(parsed.envelope, pin)
                : parsed;
              this._recordLog('in', 'pull', t('lan.pulledFrom', { name: data.deviceName || hostOnly }), `${hostOnly}:${port}`);
              this.onReceiveItem({
                type: 'bundle',
                tabs: data.tabs || [],
                bms: data.bms || [],
                notes: data.notes || '',
                rssFeeds: data.rssFeeds || [],
                fromPeer: data.deviceName || `${hostOnly}:${port}`
              });
              resolve({ ok: true, data });
            } catch (err) {
              resolve({ ok: false, error: t('lan.errDecryptResp', { msg: err.message }) });
            }
          });
        }
      );
      req.on('timeout', () => {
        req.destroy();
        resolve({ ok: false, error: t('lan.errTimeout') });
      });
      req.on('error', err => resolve({ ok: false, error: err.message }));
      req.write(bodyStr);
      req.end();
    });
  }

  _emitStatus() {
    try {
      this.onStatusChange(this.getStatus());
    } catch {}
  }

  getStatus() {
    const ips = this.getLocalLanAddresses();
    const primaryIp = ips[0] || '127.0.0.1';
    const pairUrl = `http://${primaryIp}:${this.httpPort}/?t=${this.pairToken}`;
    const qrSvg = this.running ? generateQrCodeSvg(pairUrl, 176) : '';

    return {
      running: this.running,
      discoveryActive: this.discoveryActive,
      deviceId: this.deviceId,
      deviceName: this.deviceName,
      ips,
      primaryIp,
      port: this.httpPort,
      pin: this.pin,
      formattedPin: `${this.pin.slice(0, 3)}-${this.pin.slice(3)}`,
      pairUrl,
      qrSvg,
      cipher: 'AES-256-GCM + 6 Haneli PIN',
      peers: [...this.peers.values()],
      transferLog: this.transferLog.slice(0, 20)
    };
  }

  _renderMobileCompanionHtml(prefillToken) {
    return `<!DOCTYPE html>
<html lang="${getLang()}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${t('lan.mob.title')}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#08101f;color:#e6ecfa;font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:18px;max-width:640px;margin:0 auto}
  .head{display:flex;align-items:center;gap:12px;margin-bottom:16px}
  .logo{width:38px;height:38px;border-radius:11px;background:linear-gradient(145deg,#60a5fa,#3b82f6);display:grid;place-items:center;font-weight:800;font-size:20px;color:#fff}
  .card{background:#0d182e;border:1px solid #1d2f54;border-radius:14px;padding:15px;margin-bottom:14px}
  h3{font-size:15px;margin-bottom:8px;color:#60a5fa}
  input,textarea{width:100%;background:#12203d;border:1px solid #1d2f54;color:#e6ecfa;padding:10px 12px;border-radius:10px;font:inherit;margin-bottom:8px;outline:0}
  button{background:#3b82f6;color:#fff;border:0;padding:10px 16px;border-radius:10px;font-weight:600;cursor:pointer;width:100%}
  button.alt{background:#192a4d;margin-top:6px}
  .item{display:flex;justify-content:space-between;align-items:center;padding:9px 10px;background:#12203d;border-radius:9px;margin-bottom:6px;gap:10px}
  .item a{color:#e6ecfa;text-decoration:none;font-weight:500;word-break:break-all;flex:1}
  .badge{display:inline-block;padding:2px 8px;border-radius:6px;background:#10b98128;color:#34d399;font-size:11px;font-weight:700}
  #msg{margin:8px 0;color:#34d399;font-weight:600;text-align:center}
</style>
</head>
<body>
  <div class="head">
    <div class="logo">Z</div>
    <div>
      <b style="font-size:17px;display:block">${t('lan.mob.title')}</b>
      <span class="badge">${t('lan.mob.badge', { device: this.deviceName })}</span>
    </div>
  </div>

  <div class="card" id="authCard">
    <h3>${t('lan.mob.pinTitle')}</h3>
    <input id="pinIn" type="tel" maxlength="7" placeholder="${t('lan.mob.pinPh')}">
    <button onclick="loadState()">${t('lan.mob.connectBtn')}</button>
  </div>

  <div id="msg"></div>

  <div class="card">
    <h3>${t('lan.mob.sendTitle')}</h3>
    <input id="sendUrl" placeholder="${t('lan.mob.urlPh')}">
    <button onclick="sendTab()">${t('lan.mob.sendTabBtn')}</button>
    <textarea id="sendNote" rows="3" style="margin-top:10px" placeholder="${t('lan.mob.notePh')}"></textarea>
    <button class="alt" onclick="sendNoteText()">${t('lan.mob.sendNoteBtn')}</button>
  </div>

  <div class="card">
    <h3>${t('lan.mob.tabsTitle')} (<span id="tabCnt">0</span>)</h3>
    <div id="tabList"><span style="color:#8394b8">${t('lan.mob.loading')}</span></div>
  </div>

  <div class="card">
    <h3>${t('lan.mob.bmsTitle')} (<span id="bmCnt">0</span>)</h3>
    <div id="bmList"><span style="color:#8394b8">${t('lan.mob.loading')}</span></div>
  </div>

  <div class="card">
    <h3>${t('lan.mob.notesTitle')}</h3>
    <pre id="noteBox" style="white-space:pre-wrap;color:#93a9d3;font-family:inherit">${t('lan.mob.noNotes')}</pre>
  </div>

<script>
  const TOKEN = ${JSON.stringify(prefillToken)};
  const M = ${JSON.stringify({
    pinNeeded: t('lan.mob.pinNeeded'),
    noOpenTabs: t('lan.mob.noOpenTabs'),
    noBms: t('lan.mob.noBms'),
    noNotes: t('lan.mob.noNotes'),
    connected: t('lan.mob.connected'),
    connErr: t('lan.mob.connErr'),
    enterLink: t('lan.mob.enterLink'),
    tabOpened: t('lan.mob.tabOpened'),
    sendFailed: t('lan.mob.sendFailed'),
    enterText: t('lan.mob.enterText'),
    noteSent: t('lan.mob.noteSent'),
    mobileDevice: t('lan.mob.mobileDevice')
  })};

  // Saf JS Kriptografi Paketi (http:// yerel ağda window.crypto.subtle olmadan da çalışır)
  const TE = new TextEncoder(), TD = new TextDecoder();
  function randBytes(n) {
    const out = new Uint8Array(n);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) crypto.getRandomValues(out);
    else for (let i = 0; i < n; i++) out[i] = (Math.random() * 256) | 0;
    return out;
  }
  function b64Enc(u8) {
    let s = '';
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return btoa(s);
  }
  function b64Dec(str) {
    const bin = atob(str);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function hexEnc(u8) {
    let s = '';
    for (let i = 0; i < u8.length; i++) s += (u8[i] < 16 ? '0' : '') + u8[i].toString(16);
    return s;
  }

  const SHA256_K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ]);
  function sha256(data) {
    const msg = data instanceof Uint8Array ? data : new Uint8Array(data);
    const l = msg.length, bitLen = l * 8;
    const padLen = ((l + 9 + 63) & ~63);
    const buf = new Uint8Array(padLen);
    buf.set(msg);
    buf[l] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false);
    dv.setUint32(padLen - 4, bitLen >>> 0, false);
    let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    const w = new Uint32Array(64);
    for (let i = 0; i < padLen; i += 64) {
      for (let t = 0; t < 16; t++) w[t] = dv.getUint32(i + t * 4, false);
      for (let t = 16; t < 64; t++) {
        const s0 = ((w[t-15]>>>7)|(w[t-15]<<25))^((w[t-15]>>>18)|(w[t-15]<<14))^(w[t-15]>>>3);
        const s1 = ((w[t-2]>>>17)|(w[t-2]<<15))^((w[t-2]>>>19)|(w[t-2]<<13))^(w[t-2]>>>10);
        w[t] = (w[t-16] + s0 + w[t-7] + s1) >>> 0;
      }
      let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
      for (let t = 0; t < 64; t++) {
        const S1 = ((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7));
        const ch = (e&f)^((~e)&g);
        const t1 = (h + S1 + ch + SHA256_K[t] + w[t]) >>> 0;
        const S0 = ((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10));
        const maj = (a&b)^(a&c)^(b&c);
        const t2 = (S0 + maj) >>> 0;
        h=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
      }
      h0=(h0+a)>>>0; h1=(h1+b)>>>0; h2=(h2+c)>>>0; h3=(h3+d)>>>0;
      h4=(h4+e)>>>0; h5=(h5+f)>>>0; h6=(h6+g)>>>0; h7=(h7+h)>>>0;
    }
    const out = new Uint8Array(32), ov = new DataView(out.buffer);
    ov.setUint32(0,h0,false); ov.setUint32(4,h1,false); ov.setUint32(8,h2,false); ov.setUint32(12,h3,false);
    ov.setUint32(16,h4,false); ov.setUint32(20,h5,false); ov.setUint32(24,h6,false); ov.setUint32(28,h7,false);
    return out;
  }
  function hmacSha256(key, msg) {
    const k0 = key.length > 64 ? sha256(key) : key;
    const ipad = new Uint8Array(64), opad = new Uint8Array(64);
    ipad.fill(0x36); opad.fill(0x5c);
    for (let i = 0; i < k0.length; i++) { ipad[i] ^= k0[i]; opad[i] ^= k0[i]; }
    const inner = new Uint8Array(64 + msg.length);
    inner.set(ipad); inner.set(msg, 64);
    const ih = sha256(inner);
    const outer = new Uint8Array(64 + 32);
    outer.set(opad); outer.set(ih, 64);
    return sha256(outer);
  }
  function pbkdf2Sha256_1iter(passBytes, saltBytes, dkLen) {
    const out = new Uint8Array(dkLen);
    const blkCount = Math.ceil(dkLen / 32);
    const sb = new Uint8Array(saltBytes.length + 4);
    sb.set(saltBytes);
    let off = 0;
    for (let idx = 1; idx <= blkCount; idx++) {
      sb[saltBytes.length] = (idx >>> 24) & 0xff;
      sb[saltBytes.length + 1] = (idx >>> 16) & 0xff;
      sb[saltBytes.length + 2] = (idx >>> 8) & 0xff;
      sb[saltBytes.length + 3] = idx & 0xff;
      const u = hmacSha256(passBytes, sb);
      const take = Math.min(32, dkLen - off);
      out.set(u.subarray(0, take), off);
      off += take;
    }
    return out;
  }
  function rotl32(v, c) { return (v << c) | (v >>> (32 - c)); }
  function salsa20_8(b) {
    const x = new Int32Array(b);
    for (let i = 0; i < 4; i++) {
      x[4] ^= rotl32((x[0]+x[12])|0, 7); x[8] ^= rotl32((x[4]+x[0])|0, 9); x[12] ^= rotl32((x[8]+x[4])|0, 13); x[0] ^= rotl32((x[12]+x[8])|0, 18);
      x[9] ^= rotl32((x[5]+x[1])|0, 7); x[13] ^= rotl32((x[9]+x[5])|0, 9); x[1] ^= rotl32((x[13]+x[9])|0, 13); x[5] ^= rotl32((x[1]+x[13])|0, 18);
      x[14] ^= rotl32((x[10]+x[6])|0, 7); x[2] ^= rotl32((x[14]+x[10])|0, 9); x[6] ^= rotl32((x[2]+x[14])|0, 13); x[10] ^= rotl32((x[6]+x[2])|0, 18);
      x[3] ^= rotl32((x[15]+x[11])|0, 7); x[7] ^= rotl32((x[3]+x[15])|0, 9); x[11] ^= rotl32((x[7]+x[3])|0, 13); x[15] ^= rotl32((x[11]+x[7])|0, 18);
      x[1] ^= rotl32((x[0]+x[3])|0, 7); x[2] ^= rotl32((x[1]+x[0])|0, 9); x[3] ^= rotl32((x[2]+x[1])|0, 13); x[0] ^= rotl32((x[3]+x[2])|0, 18);
      x[6] ^= rotl32((x[5]+x[4])|0, 7); x[7] ^= rotl32((x[6]+x[5])|0, 9); x[4] ^= rotl32((x[7]+x[6])|0, 13); x[5] ^= rotl32((x[4]+x[7])|0, 18);
      x[11] ^= rotl32((x[10]+x[9])|0, 7); x[8] ^= rotl32((x[11]+x[10])|0, 9); x[9] ^= rotl32((x[8]+x[11])|0, 13); x[10] ^= rotl32((x[9]+x[8])|0, 18);
      x[12] ^= rotl32((x[15]+x[14])|0, 7); x[13] ^= rotl32((x[12]+x[15])|0, 9); x[14] ^= rotl32((x[13]+x[12])|0, 13); x[15] ^= rotl32((x[14]+x[13])|0, 18);
    }
    for (let i = 0; i < 16; i++) b[i] = (b[i] + x[i]) | 0;
  }
  function blockMixSalsa8(by, bOff, yOff, r) {
    const x = new Int32Array(16);
    for (let i = 0; i < 16; i++) x[i] = by[bOff + (2 * r - 1) * 16 + i];
    for (let i = 0; i < 2 * r; i++) {
      for (let j = 0; j < 16; j++) x[j] ^= by[bOff + i * 16 + j];
      salsa20_8(x);
      const dest = yOff + ((i >> 1) + (i & 1 ? r : 0)) * 16;
      for (let j = 0; j < 16; j++) by[dest + j] = x[j];
    }
  }
  function scryptPinKey(pinStr, saltBytes) {
    const cleanPin = String(pinStr || '').replace(/\D/g, '');
    const passBytes = TE.encode('zaslon-lan-pin:' + cleanPin);
    const r = 8, n = 4096, intCount = 32 * r;
    const b = pbkdf2Sha256_1iter(passBytes, saltBytes, 128 * r);
    const v = new Int32Array(intCount * n);
    const xy = new Int32Array(64 * r);
    for (let i = 0; i < intCount; i++) {
      const p = i * 4;
      xy[i] = (b[p]) | (b[p+1] << 8) | (b[p+2] << 16) | (b[p+3] << 24);
    }
    for (let i = 0; i < n; i++) {
      v.set(xy.subarray(0, intCount), i * intCount);
      blockMixSalsa8(xy, 0, intCount, r);
      xy.copyWithin(0, intCount, intCount * 2);
    }
    for (let i = 0; i < n; i++) {
      const j = xy[intCount - 16] & (n - 1);
      const vOff = j * intCount;
      for (let k = 0; k < intCount; k++) xy[k] ^= v[vOff + k];
      blockMixSalsa8(xy, 0, intCount, r);
      xy.copyWithin(0, intCount, intCount * 2);
    }
    for (let i = 0; i < intCount; i++) {
      const p = i * 4, w = xy[i];
      b[p] = w & 0xff; b[p+1] = (w >>> 8) & 0xff; b[p+2] = (w >>> 16) & 0xff; b[p+3] = (w >>> 24) & 0xff;
    }
    return pbkdf2Sha256_1iter(passBytes, b, 32);
  }

  // Saf JS AES-256-GCM (NIST FIPS 197 + SP 800-38D)
  const AES_SBOX = new Uint8Array([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
  ]);
  const AES_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];
  function aesExpandKey256(key) {
    const rk = new Uint8Array(240);
    rk.set(key);
    let bytes = 32, rconIdx = 0;
    const t = new Uint8Array(4);
    while (bytes < 240) {
      for (let i = 0; i < 4; i++) t[i] = rk[bytes - 4 + i];
      if (bytes % 32 === 0) {
        const tmp = t[0]; t[0] = AES_SBOX[t[1]] ^ AES_RCON[rconIdx++]; t[1] = AES_SBOX[t[2]]; t[2] = AES_SBOX[t[3]]; t[3] = AES_SBOX[tmp];
      } else if (bytes % 32 === 16) {
        for (let i = 0; i < 4; i++) t[i] = AES_SBOX[t[i]];
      }
      for (let i = 0; i < 4; i++) { rk[bytes] = rk[bytes - 32] ^ t[i]; bytes++; }
    }
    return rk;
  }
  function xtime(a) { return ((a << 1) ^ ((a & 0x80) ? 0x1b : 0)) & 0xff; }
  function aesEncryptBlock(block, rk) {
    const s = new Uint8Array(block);
    for (let i = 0; i < 16; i++) s[i] ^= rk[i];
    for (let rnd = 1; rnd <= 14; rnd++) {
      for (let i = 0; i < 16; i++) s[i] = AES_SBOX[s[i]];
      let tmp = s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=tmp;
      tmp = s[2]; s[2]=s[10]; s[10]=tmp; tmp = s[6]; s[6]=s[14]; s[14]=tmp;
      tmp = s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=tmp;
      if (rnd < 14) {
        for (let c = 0; c < 16; c += 4) {
          const a0=s[c],a1=s[c+1],a2=s[c+2],a3=s[c+3],t=a0^a1^a2^a3;
          s[c]^=t^xtime(a0^a1); s[c+1]^=t^xtime(a1^a2); s[c+2]^=t^xtime(a2^a3); s[c+3]^=t^xtime(a3^a0);
        }
      }
      const off = rnd * 16;
      for (let i = 0; i < 16; i++) s[i] ^= rk[off + i];
    }
    return s;
  }
  function gf128Mul(x, y) {
    const z = new Uint8Array(16), v = new Uint8Array(y);
    for (let i = 0; i < 128; i++) {
      if ((x[i >> 3] >> (7 - (i & 7))) & 1) {
        for (let j = 0; j < 16; j++) z[j] ^= v[j];
      }
      const lsb = v[15] & 1;
      for (let j = 15; j > 0; j--) v[j] = (v[j] >>> 1) | ((v[j - 1] & 1) << 7);
      v[0] >>>= 1;
      if (lsb) v[0] ^= 0xe1;
    }
    return z;
  }
  function ghash(h, ct) {
    let y = new Uint8Array(16);
    for (let off = 0; off < ct.length; off += 16) {
      const blk = new Uint8Array(16);
      blk.set(ct.subarray(off, Math.min(off + 16, ct.length)));
      for (let j = 0; j < 16; j++) y[j] ^= blk[j];
      y = gf128Mul(y, h);
    }
    const lenBlk = new Uint8Array(16);
    const bitLen = ct.length * 8;
    const dv = new DataView(lenBlk.buffer);
    dv.setUint32(8, Math.floor(bitLen / 0x100000000), false);
    dv.setUint32(12, bitLen >>> 0, false);
    for (let j = 0; j < 16; j++) y[j] ^= lenBlk[j];
    return gf128Mul(y, h);
  }
  function gcmCtrCrypt(rk, iv, input) {
    const j0 = new Uint8Array(16);
    j0.set(iv, 0); j0[15] = 1;
    const out = new Uint8Array(input.length);
    const cb = new Uint8Array(j0);
    const dv = new DataView(cb.buffer);
    for (let off = 0, ctr = 2; off < input.length; off += 16, ctr++) {
      dv.setUint32(12, ctr >>> 0, false);
      const ks = aesEncryptBlock(cb, rk);
      const take = Math.min(16, input.length - off);
      for (let j = 0; j < take; j++) out[off + j] = input[off + j] ^ ks[j];
    }
    const h = aesEncryptBlock(new Uint8Array(16), rk);
    const s0 = aesEncryptBlock(j0, rk);
    return { out, h, s0 };
  }
  function encryptEnvelope(obj, pin) {
    const salt = randBytes(16), iv = randBytes(12);
    const rk = aesExpandKey256(scryptPinKey(pin, salt));
    const plain = TE.encode(JSON.stringify(obj));
    const { out: ct, h, s0 } = gcmCtrCrypt(rk, iv, plain);
    const tag = ghash(h, ct);
    for (let i = 0; i < 16; i++) tag[i] ^= s0[i];
    return { encrypted: true, cipher: 'AES-256-GCM', salt: b64Enc(salt), iv: b64Enc(iv), tag: b64Enc(tag), ciphertext: b64Enc(ct) };
  }
  function decryptEnvelope(env, pin) {
    const salt = b64Dec(env.salt), iv = b64Dec(env.iv), tag = b64Dec(env.tag), ct = b64Dec(env.ciphertext);
    const rk = aesExpandKey256(scryptPinKey(pin, salt));
    const { out: plain, h, s0 } = gcmCtrCrypt(rk, iv, ct);
    const expected = ghash(h, ct);
    let diff = 0;
    for (let i = 0; i < 16; i++) diff |= (expected[i] ^ s0[i] ^ tag[i]);
    if (diff !== 0) throw new Error('Invalid PIN or tampered AES-GCM envelope');
    return JSON.parse(TD.decode(plain));
  }

  function getActivePin() {
    return (document.getElementById('pinIn')?.value || '').replace(/\D/g, '');
  }
  function buildPinAuthHeader(pin, method, reqPath) {
    const cleanPin = String(pin || '').replace(/\D/g, '');
    const ts = String(Date.now());
    const nonce = hexEnc(randBytes(8));
    const payload = ts + ':' + nonce + ':' + method.toUpperCase() + ':' + reqPath;
    const sig = hexEnc(hmacSha256(TE.encode('zaslon-lan-auth:' + cleanPin), TE.encode(payload)));
    return ts + '.' + nonce + '.' + sig;
  }
  function getHeaders(method, reqPath, pin) {
    const h = { 'Content-Type': 'application/json' };
    if (TOKEN) h['X-Zaslon-Token'] = TOKEN;
    if (pin) h['X-Zaslon-Auth'] = buildPinAuthHeader(pin, method, reqPath);
    return h;
  }
  function flash(t, bad) {
    const el = document.getElementById('msg');
    el.style.color = bad ? '#fb7185' : '#34d399';
    el.textContent = t;
    setTimeout(() => { if (el.textContent === t) el.textContent = ''; }, 3500);
  }
  function renderSafeList(container, items, titleKey, urlKey, emptyMsg) {
    container.textContent = '';
    if (!items || !items.length) {
      const sp = document.createElement('span');
      sp.style.color = '#8394b8';
      sp.textContent = emptyMsg;
      container.appendChild(sp);
      return;
    }
    for (const item of items) {
      const rawUrl = String((item && item[urlKey]) || '');
      let safeHref = '#';
      try {
        const parsed = new URL(rawUrl);
        if (parsed.protocol === 'http:' || parsed.protocol === 'https:') safeHref = parsed.href;
      } catch {}
      const row = document.createElement('div');
      row.className = 'item';
      const link = document.createElement('a');
      link.href = safeHref;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      link.textContent = String((item && item[titleKey]) || rawUrl);
      row.appendChild(link);
      container.appendChild(row);
    }
  }
  async function loadState() {
    const pin = getActivePin();
    if (!pin || pin.length < 4) {
      document.getElementById('authCard').style.display = 'block';
      return flash(M.pinNeeded, true);
    }
    try {
      const r = await fetch('/api/sync/pull', {
        method: 'POST',
        headers: getHeaders('POST', '/api/sync/pull', pin),
        body: JSON.stringify({ wantEncrypted: true })
      });
      const j = await r.json();
      if (!j.ok || !j.envelope) {
        document.getElementById('authCard').style.display = 'block';
        return flash(j.error || M.pinNeeded, true);
      }
      const data = decryptEnvelope(j.envelope, pin);
      document.getElementById('authCard').style.display = 'none';
      const tabs = data.tabs || [];
      const bms = data.bms || [];
      document.getElementById('tabCnt').textContent = String(tabs.length);
      document.getElementById('bmCnt').textContent = String(bms.length);
      renderSafeList(document.getElementById('tabList'), tabs, 'title', 'url', M.noOpenTabs);
      renderSafeList(document.getElementById('bmList'), bms, 't', 'u', M.noBms);
      document.getElementById('noteBox').textContent = data.notes || M.noNotes;
      flash(M.connected + ' (AES-256-GCM)');
    } catch (e) {
      document.getElementById('authCard').style.display = 'block';
      flash(e.message || M.connErr, true);
    }
  }
  async function sendTab() {
    const pin = getActivePin();
    if (!pin || pin.length < 4) return flash(M.pinNeeded, true);
    const u = document.getElementById('sendUrl').value.trim();
    if (!u) return flash(M.enterLink, true);
    const env = encryptEnvelope({ type: 'tab', url: u, title: u, deviceName: M.mobileDevice, timestamp: Date.now() }, pin);
    const r = await fetch('/api/sync/push', {
      method: 'POST',
      headers: getHeaders('POST', '/api/sync/push', pin),
      body: JSON.stringify({ envelope: env })
    }).then(x => x.json());
    if (r.ok) { document.getElementById('sendUrl').value = ''; flash(M.tabOpened); }
    else flash(r.error || M.sendFailed, true);
  }
  async function sendNoteText() {
    const pin = getActivePin();
    if (!pin || pin.length < 4) return flash(M.pinNeeded, true);
    const txt = document.getElementById('sendNote').value.trim();
    if (!txt) return flash(M.enterText, true);
    const env = encryptEnvelope({ type: 'note', text: txt, deviceName: M.mobileDevice, timestamp: Date.now() }, pin);
    const r = await fetch('/api/sync/push', {
      method: 'POST',
      headers: getHeaders('POST', '/api/sync/push', pin),
      body: JSON.stringify({ envelope: env })
    }).then(x => x.json());
    if (r.ok) { document.getElementById('sendNote').value = ''; flash(M.noteSent); loadState(); }
    else flash(r.error || M.sendFailed, true);
  }
</script>
</body>
</html>`;
  }
}

module.exports = {
  LanSyncManager,
  generateQrCodeSvg
};
