/**
 * Zaslon Browser — Faz 3: Tor Zırhlı Oturum & Domain Bazlı Devre İzolasyonu (Stream Isolation)
 *
 * Özellikler:
 * 1) Otomatik Tor Algılama & Başlatma (9050 / 9150 port kontrolü veya gömülü tor.exe başlatma).
 * 2) Tek Tıkla Resmi Tor Expert Bundle İndirici & Kurucu (tor.exe sistemde yoksa).
 * 3) Domain Bazlı Devre İzolasyonu (Tor Stream Isolation — RFC 1929 SOCKS5 Auth):
 *    - Her farklı kök alan adı (örn: duckduckgo.com, bbc.com, *.onion) için Tor SOCKS5 portuna
 *      benzersiz "zaslon-<domain>:<epoch>" kimlik bilgisi iletir.
 *    - Tor'un IsolateSOCKSAuth özelliği sayesinde her site farklı bir Tor devresi ve çıkış IP'si kullanır.
 * 4) %100 Uzak DNS & .onion Çözümleme (SOCKS5 ATYP=0x03 DOMAINNAME / socks5h):
 *    - DNS sorguları yerel ağa asla sızmaz; .onion gizli servisleri doğrudan açılır.
 * 5) Sızıntı Kilidi (Fail-Closed Kill-Switch):
 *    - Tor bağlı değilken "🧅 Tor Zırhlı" konteynerindeki hiçbir istek normal internete çıkamaz.
 */

const net = require('net');
const tls = require('tls');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { t } = require('../i18n/translations');

const TOR_BUNDLE_VERSION = '14.0.4';
const TOR_BUNDLE_SHA256 = '2d8cd74b24cd87ba7a797b989cff7d6cd7c22ee55ab0a9ee3e99cba637af48e4';

/**
 * Buffers an incoming HTTP proxy request head until "\r\n\r\n" across split TCP chunks.
 */
function readHttpProxyHead(socket, maxBytes = 65536, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalLen = 0;
    let settled = false;

    const cleanup = () => {
      socket.removeListener('data', onData);
      socket.removeListener('error', onErr);
      socket.removeListener('end', onEnd);
      socket.removeListener('close', onClose);
      if (timer) clearTimeout(timer);
    };

    const fail = err => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(err);
    };

    const finish = (headerBuf, extraPayload) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve({ headerBuf, extraPayload });
    };

    const timer = setTimeout(() => fail(new Error('HTTP proxy header timeout')), timeoutMs);
    const onErr = err => fail(err);
    const onEnd = () => fail(new Error('EOF before HTTP proxy header end'));
    const onClose = () => fail(new Error('Closed before HTTP proxy header end'));

    const onData = chunk => {
      chunks.push(chunk);
      totalLen += chunk.length;
      if (totalLen > maxBytes) {
        fail(new Error('HTTP proxy header too large'));
        return;
      }
      const combined = chunks.length === 1 ? chunks[0] : Buffer.concat(chunks, totalLen);
      const headerEnd = combined.indexOf('\r\n\r\n');
      if (headerEnd !== -1) {
        finish(combined.subarray(0, headerEnd), combined.subarray(headerEnd + 4));
      }
    };

    socket.on('data', onData);
    socket.on('error', onErr);
    socket.on('end', onEnd);
    socket.on('close', onClose);
  });
}

/**
 * Verifies a local port actually speaks SOCKS5 greeting (0x05 + auth method).
 */
function verifySocks5Listener(port, host = '127.0.0.1', timeoutMs = 1000) {
  return new Promise(resolve => {
    const sock = net.connect({ host, port });
    let done = false;
    const finish = ok => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve(ok);
    };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => sock.write(Buffer.from([0x05, 0x02, 0x00, 0x02])));
    sock.once('data', chunk => {
      finish(Buffer.isBuffer(chunk) && chunk.length >= 2 && chunk[0] === 0x05 && chunk[1] !== 0xff);
    });
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));
  });
}

/**
 * Alan adından kök etki alanını (eTLD+1 veya .onion) çıkarır
 */
function extractRootDomain(hostname) {
  if (!hostname) return 'default';
  const clean = hostname.toLowerCase().replace(/^www\./, '').trim();
  if (clean.endsWith('.onion')) return clean;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(clean)) return clean;
  const parts = clean.split('.');
  if (parts.length <= 2) return clean;
  const lastTwo = parts.slice(-2).join('.');
  if (/^(com|org|net|gov|edu|co)\.[a-z]{2}$/.test(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return lastTwo;
}

/**
 * Bir TCP portunun açık olup olmadığını hızlıca kontrol eder
 */
function checkPortOpen(host, port, timeoutMs = 900) {
  return new Promise(resolve => {
    const sock = new net.Socket();
    let done = false;
    const finish = ok => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve(ok);
    };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => finish(true));
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));
    sock.connect(port, host);
  });
}

/**
 * Tor SOCKS5 sunucusuna RFC 1929 (Username/Password Stream Isolation) ve
 * ATYP=0x03 (Uzak Domain/Onion Çözümleme) ile bağlanır.
 */
function connectViaTorSocks5({ socksHost = '127.0.0.1', socksPort = 9050, targetHost, targetPort, username, password }) {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host: socksHost, port: socksPort, noDelay: true });
    let stage = 'greeting';
    let buf = Buffer.alloc(0);

    const fail = err => {
      sock.destroy();
      reject(err instanceof Error ? err : new Error(String(err)));
    };

    const isOnion = String(targetHost || '').trim().toLowerCase().endsWith('.onion');
    sock.setTimeout(isOnion ? 45000 : 20000, () => fail(new Error(t('tor.socksTimeout'))));
    sock.once('error', fail);

    sock.once('connect', () => {
      // SOCKS5 Greeting: Version 5, 2 Auth Methods (0x00 NoAuth, 0x02 User/Pass)
      if (username && password) {
        sock.write(Buffer.from([0x05, 0x02, 0x00, 0x02]));
      } else {
        sock.write(Buffer.from([0x05, 0x01, 0x00]));
      }
    });

    const sendConnectCommand = () => {
      stage = 'connect';
      const hostBuf = Buffer.from(targetHost, 'utf8');
      if (hostBuf.length > 255) {
        return fail(new Error(t('tor.hostTooLong')));
      }
      const req = Buffer.alloc(4 + 1 + hostBuf.length + 2);
      req[0] = 0x05; // SOCKS5
      req[1] = 0x01; // CONNECT
      req[2] = 0x00; // RSV
      req[3] = 0x03; // ATYP = DOMAINNAME (socks5h — .onion ve uzak DNS çözümleme)
      req[4] = hostBuf.length;
      hostBuf.copy(req, 5);
      req.writeUInt16BE(targetPort, 5 + hostBuf.length);
      sock.write(req);
    };

    const onData = chunk => {
      buf = Buffer.concat([buf, chunk]);

      if (stage === 'greeting') {
        if (buf.length < 2) return;
        const ver = buf[0];
        const method = buf[1];
        buf = buf.subarray(2);
        if (ver !== 0x05) return fail(new Error(t('tor.invalidSocks')));

        if (method === 0x02) {
          // RFC 1929 Username/Password Auth (Tor IsolateSOCKSAuth için)
          stage = 'auth';
          const uBuf = Buffer.from(String(username).slice(0, 250), 'utf8');
          const pBuf = Buffer.from(String(password).slice(0, 250), 'utf8');
          const authPacket = Buffer.concat([
            Buffer.from([0x01, uBuf.length]),
            uBuf,
            Buffer.from([pBuf.length]),
            pBuf
          ]);
          sock.write(authPacket);
          return;
        } else if (method === 0x00) {
          sendConnectCommand();
          return;
        } else {
          return fail(new Error(t('tor.authRejected')));
        }
      }

      if (stage === 'auth') {
        if (buf.length < 2) return;
        const status = buf[1];
        buf = buf.subarray(2);
        if (status !== 0x00) return fail(new Error(t('tor.authFailed')));
        sendConnectCommand();
        return;
      }

      if (stage === 'connect') {
        if (buf.length < 4) return;
        const rep = buf[1];
        const atyp = buf[3];
        if (rep !== 0x00) {
          return fail(new Error(t('tor.connectError', { rep })));
        }
        let headerLen = 4;
        if (atyp === 0x01) headerLen += 4 + 2; // IPv4
        else if (atyp === 0x04) headerLen += 16 + 2; // IPv6
        else if (atyp === 0x03) {
          if (buf.length < 5) return;
          headerLen += 1 + buf[4] + 2;
        }
        if (buf.length < headerLen) return;

        const remaining = buf.subarray(headerLen);
        sock.removeListener('data', onData);
        sock.setTimeout(0);
        if (remaining.length > 0) {
          sock.unshift(remaining);
        }
        resolve(sock);
      }
    };

    sock.on('data', onData);
  });
}

function sanitizeBridgeLine(raw) {
  const s = String(raw || '').split(/[\r\n\0]/)[0].replace(/\s+/g, ' ').trim();
  if (!s || s.length > 512) return '';
  // Yalnızca güvenli bridge satırı karakterlerine izin ver (komut enjeksiyonunu önle)
  if (/[^\x20-\x7E]/.test(s)) return '';
  return s.replace(/^bridge\s+/i, '');
}

class TorManager {
  constructor({
    userDataPath,
    resourcesPath,
    fetchFn,
    onStatusChange,
    allowExternalTor = false,
    clearTorDataOnExit = false,
    bridges = []
  } = {}) {
    this.userDataPath = userDataPath || '';
    this.resourcesPath = resourcesPath || path.join(__dirname, '../../resources');
    this.fetchFn = fetchFn || global.fetch;
    this.onStatusChange = onStatusChange || (() => {});

    this.allowExternalTor = !!allowExternalTor;
    this.clearTorDataOnExit = !!clearTorDataOnExit;
    this.bridges = Array.isArray(bridges) ? bridges.map(sanitizeBridgeLine).filter(Boolean) : [];
    this.dataDir = this.userDataPath ? path.join(this.userDataPath, 'tor-data') : '';
    this.state = 'stopped'; // 'stopped' | 'starting' | 'connected' | 'installing' | 'error'
    this.bootstrapPct = 0;
    this.summaryKey = 'tor.disabled';
    this.summaryParams = {};
    this.rawSummary = null;
    this.socksPort = 9050;
    this.controlPort = 9051;
    this.gatewayServer = null;
    this.gatewayPort = 0;
    this.firstPartyGateways = new Map(); // fpRoot -> { server, port, host }
    this.torProc = null;
    this.circuitEpoch = 1;
    this.exitIp = null;
    this.isolatedDomains = new Map(); // firstPartyHost -> { domain, circuitId, requests, lastUsed }
    this.lastError = '';
    this._startPromise = null;
    this._installPromise = null;
  }

  /**
   * Sistemde veya uygulama dizininde tor.exe ikilisini arar
   */
  findTorBinary() {
    const isWin = process.platform === 'win32';
    const binName = isWin ? 'tor.exe' : 'tor';
    const candidates = [
      path.join(this.resourcesPath, 'bin', binName),
      path.join(this.resourcesPath, 'bin', 'tor', binName),
      path.join(__dirname, '../../resources/bin', binName),
      path.join(__dirname, '../../resources/bin/tor', binName),
      this.userDataPath ? path.join(this.userDataPath, 'bin', 'tor', 'tor', binName) : '',
      this.userDataPath ? path.join(this.userDataPath, 'bin', 'tor', binName) : '',
      isWin && process.env.LOCALAPPDATA
        ? path.join(process.env.LOCALAPPDATA, 'Tor Browser', 'Browser', 'TorBrowser', 'Tor', 'tor.exe')
        : '',
      isWin && process.env.USERPROFILE
        ? path.join(process.env.USERPROFILE, 'Desktop', 'Tor Browser', 'Browser', 'TorBrowser', 'Tor', 'tor.exe')
        : ''
    ].filter(Boolean);

    for (const p of candidates) {
      if (fs.existsSync(p)) return p;
    }
    return null;
  }

  /**
   * Pluggable Transport ikilisini (lyrebird / obfs4proxy / snowflake-client) arar.
   */
  findPluggableTransport(torBin = '') {
    const ext = process.platform === 'win32' ? '.exe' : '';
    const baseDirs = [
      torBin ? path.dirname(torBin) : '',
      torBin ? path.join(path.dirname(torBin), 'pluggable_transports') : '',
      path.join(this.resourcesPath, 'bin', 'tor', 'pluggable_transports'),
      this.userDataPath ? path.join(this.userDataPath, 'bin', 'tor', 'tor', 'pluggable_transports') : ''
    ].filter(Boolean);

    const names = ['lyrebird', 'obfs4proxy', 'snowflake-client', 'webtunnel-client'];
    const found = {};
    for (const dir of baseDirs) {
      for (const n of names) {
        if (found[n]) continue;
        const p = path.join(dir, n + ext);
        try {
          if (fs.existsSync(p)) found[n] = p;
        } catch {}
      }
    }
    return found;
  }

  setBridges(bridges = []) {
    this.bridges = Array.isArray(bridges) ? bridges.map(sanitizeBridgeLine).filter(Boolean) : [];
    this.emitStatus();
    return this.bridges;
  }

  buildTorSpawnArgs(dataDir, torBin = '') {
    const args = [
      '--DataDirectory',
      dataDir,
      '--SocksPort',
      `127.0.0.1:${this.socksPort} IsolateSOCKSAuth`,
      '--ControlPort',
      `127.0.0.1:${this.controlPort}`,
      '--CookieAuthentication',
      '1',
      '--SafeSocks',
      '1',
      '--ClientOnly',
      '1',
      '--AvoidDiskWrites',
      '1',
      '--ConnectionPadding',
      '1',
      '--ReducedConnectionPadding',
      '0'
    ];

    if (Array.isArray(this.bridges) && this.bridges.length > 0) {
      args.push('--UseBridges', '1');
      const pt = this.findPluggableTransport(torBin);
      const lyrebird = pt.lyrebird || '';
      const obfs4 = lyrebird || pt.obfs4proxy || '';
      const snowflake = lyrebird || pt['snowflake-client'] || '';
      const webtunnel = lyrebird || pt['webtunnel-client'] || '';
      if (obfs4) args.push('--ClientTransportPlugin', `obfs4 exec ${obfs4}`);
      if (snowflake) args.push('--ClientTransportPlugin', `snowflake exec ${snowflake}`);
      if (webtunnel) args.push('--ClientTransportPlugin', `webtunnel exec ${webtunnel}`);
      for (const line of this.bridges) {
        args.push('--Bridge', line);
      }
    }

    return args;
  }

  /**
   * Verilen First-Party kaynak (veya varsayılan genel geçit) için HTTP/CONNECT -> Tor SOCKS5 geçit sunucusu başlatır.
   */
  _createGatewayServer(fixedFirstPartyHost = '') {
    const fixedFpRoot = fixedFirstPartyHost ? extractRootDomain(fixedFirstPartyHost) : '';
    return new Promise((resolve, reject) => {
      const server = net.createServer({ allowHalfOpen: false }, async clientSocket => {
        clientSocket.setNoDelay(true);
        clientSocket.on('error', () => {});

        const sendKillSwitch503 = () => {
          try {
            clientSocket.end(
              'HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nZaslon Tor Sizinti Kilidi: Tor agi henuz bagli degil. Gercek IP adresinizin sizmamasi icin baglanti durduruldu.'
            );
          } catch {}
          clientSocket.destroy();
        };

        // Sızıntı Kilidi (Kill-Switch): Tor bağlı değilse bağlantıyı anında reddet
        if (this.state !== 'connected') {
          clientSocket.once('data', sendKillSwitch503);
          return;
        }

        try {
          const { headerBuf, extraPayload } = await readHttpProxyHead(clientSocket);
          if (this.state !== 'connected') {
            sendKillSwitch503();
            return;
          }

          const headerText = headerBuf.toString('latin1');
          const firstLine = headerText.split('\r\n')[0] || '';

          // 1) HTTPS CONNECT veya .onion Tüneli
          const connectMatch = firstLine.match(/^CONNECT\s+(?:\[([^\]]+)\]|([^:\s]+)):(\d+)\s+HTTP\/1\.[01]/i);
          if (connectMatch) {
            const targetHost = connectMatch[1] || connectMatch[2];
            const targetPort = parseInt(connectMatch[3], 10) || 443;
            const fpRoot = fixedFpRoot || extractRootDomain(targetHost);
            const circuitTag = `FP${this.circuitEpoch}-${Buffer.from(fpRoot).toString('hex').slice(0, 8)}`;

            this.recordDomainCircuit(fpRoot, circuitTag);

            const torSock = await connectViaTorSocks5({
              socksHost: '127.0.0.1',
              socksPort: this.socksPort,
              targetHost,
              targetPort,
              username: `zaslon-fp-${fpRoot}`,
              password: `epoch-${this.circuitEpoch}`
            });

            if (clientSocket.destroyed) {
              torSock.destroy();
              return;
            }

            clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
            if (extraPayload.length > 0) torSock.write(extraPayload);
            clientSocket.pipe(torSock);
            torSock.pipe(clientSocket);

            torSock.on('error', () => {
              if (!clientSocket.destroyed) clientSocket.destroy();
            });
            clientSocket.on('close', () => {
              if (!torSock.destroyed) torSock.destroy();
            });
            return;
          }

          // 2) Düz HTTP veya http://*.onion İsteği
          const httpMatch = firstLine.match(
            /^([A-Z]+)\s+http:\/\/(?:\[([^\]]+)\]|([^/:\s]+))(?::(\d+))?(\/[^\s]*)?\s+(HTTP\/1\.[01])/i
          );
          if (httpMatch) {
            const method = httpMatch[1];
            const targetHost = httpMatch[2] || httpMatch[3];
            const targetPort = parseInt(httpMatch[4], 10) || 80;
            const pathPart = httpMatch[5] || '/';
            const httpVer = httpMatch[6];
            const fpRoot = fixedFpRoot || extractRootDomain(targetHost);
            const circuitTag = `FP${this.circuitEpoch}-${Buffer.from(fpRoot).toString('hex').slice(0, 8)}`;

            this.recordDomainCircuit(fpRoot, circuitTag);

            const torSock = await connectViaTorSocks5({
              socksHost: '127.0.0.1',
              socksPort: this.socksPort,
              targetHost,
              targetPort,
              username: `zaslon-fp-${fpRoot}`,
              password: `epoch-${this.circuitEpoch}`
            });

            if (clientSocket.destroyed) {
              torSock.destroy();
              return;
            }

            const lines = headerText
              .split('\r\n')
              .slice(1)
              .filter(l => l && !/^Proxy-Connection:/i.test(l) && !/^Connection:/i.test(l));
            lines.push('Connection: close');
            const newReq = Buffer.from(
              `${method} ${pathPart} ${httpVer}\r\n${lines.join('\r\n')}\r\n\r\n`,
              'latin1'
            );
            torSock.write(newReq);
            if (extraPayload.length > 0) torSock.write(extraPayload);

            // Chromium HTTP/1.1 keep-alive proxy soketini yeniden kullanıp sonraki .onion isteklerini asılı bırakmasın
            let resBuf = Buffer.alloc(0);
            let resHeadersForwarded = false;
            const onTorData = (chunk) => {
              if (resHeadersForwarded) {
                if (!clientSocket.destroyed) clientSocket.write(chunk);
                return;
              }
              resBuf = resBuf.length === 0 ? chunk : Buffer.concat([resBuf, chunk]);
              const sepIdx = resBuf.indexOf('\r\n\r\n');
              if (sepIdx === -1) {
                if (resBuf.length > 65536) {
                  resHeadersForwarded = true;
                  if (!clientSocket.destroyed) clientSocket.write(resBuf);
                  resBuf = Buffer.alloc(0);
                }
                return;
              }
              resHeadersForwarded = true;
              const rawHead = resBuf.subarray(0, sepIdx).toString('latin1');
              const remainder = resBuf.subarray(sepIdx + 4);
              resBuf = Buffer.alloc(0);
              const resLines = rawHead.split('\r\n');
              const statusLine = resLines[0] || 'HTTP/1.1 200 OK';
              const filtered = resLines
                .slice(1)
                .filter(l => l && !/^Connection:/i.test(l) && !/^Proxy-Connection:/i.test(l));
              filtered.push('Connection: close');
              if (!clientSocket.destroyed) {
                clientSocket.write(Buffer.from(`${statusLine}\r\n${filtered.join('\r\n')}\r\n\r\n`, 'latin1'));
                if (remainder.length > 0) clientSocket.write(remainder);
              }
              torSock.removeListener('data', onTorData);
              torSock.pipe(clientSocket);
            };
            torSock.on('data', onTorData);
            clientSocket.pipe(torSock);

            torSock.once('end', () => {
              if (!resHeadersForwarded && resBuf.length > 0 && !clientSocket.destroyed) {
                clientSocket.write(resBuf);
                resBuf = Buffer.alloc(0);
              }
              if (!clientSocket.destroyed) clientSocket.end();
            });
            torSock.on('error', () => {
              if (!clientSocket.destroyed) clientSocket.destroy();
            });
            clientSocket.on('close', () => {
              if (!torSock.destroyed) torSock.destroy();
            });
            return;
          }

          clientSocket.destroy();
        } catch {
          if (!clientSocket.destroyed) clientSocket.destroy();
        }
      });

      server.on('error', err => reject(err));
      server.listen(0, '127.0.0.1', () => {
        resolve({ server, port: server.address().port, host: fixedFpRoot });
      });
    });
  }

  /**
   * Yerel Tor İzolasyon Geçidini (Gateway) başlatır.
   * "🧅 Tor Zırhlı" konteyneri her zaman bu geçide bağlanır (Fail-Closed Kill-Switch).
   */
  async ensureIsolationGateway() {
    if (this.gatewayServer && this.gatewayPort > 0) {
      return this.gatewayPort;
    }
    const created = await this._createGatewayServer('');
    this.gatewayServer = created.server;
    this.gatewayPort = created.port;
    return this.gatewayPort;
  }

  /**
   * Belirli bir First-Party sekme kökeni (firstPartyHost) için özel izole devre geçidi açar/döndürür.
   */
  async ensureFirstPartyGateway(firstPartyHost) {
    const fpRoot = extractRootDomain(firstPartyHost);
    if (!fpRoot || fpRoot === 'default') {
      return await this.ensureIsolationGateway();
    }
    const existing = this.firstPartyGateways.get(fpRoot);
    if (existing && existing.port > 0) {
      return existing.port;
    }
    const created = await this._createGatewayServer(fpRoot);
    this.firstPartyGateways.set(fpRoot, created);
    return created.port;
  }

  recordDomainCircuit(rootDomain, circuitTag) {
    const existing = this.isolatedDomains.get(rootDomain);
    if (existing) {
      existing.requests++;
      existing.lastUsed = Date.now();
      existing.circuitId = circuitTag;
    } else {
      this.isolatedDomains.set(rootDomain, {
        domain: rootDomain,
        circuitId: circuitTag,
        requests: 1,
        lastUsed: Date.now()
      });
    }
    this.emitStatus();
  }

  /**
   * Tor ağını başlatır (Varsayılan olarak Zaslon'un kendi CookieAuthentication'lı tor.exe süreci;
   * yalnızca allowExternalTor açıksa ve doğrulanırsa harici 9050/9150 portlarını devralır).
   */
  async start(opts = {}) {
    if (typeof opts.allowExternalTor === 'boolean') {
      this.allowExternalTor = opts.allowExternalTor;
    }
    if (typeof opts.clearTorDataOnExit === 'boolean') {
      this.clearTorDataOnExit = opts.clearTorDataOnExit;
    }

    if (this._installPromise) {
      await this._installPromise.catch(() => {});
    }
    if (this._startPromise) {
      return await this._startPromise;
    }

    const run = (async () => {
      await this.ensureIsolationGateway();

      if (this.state === 'connected') {
        return this.getStatus();
      }

      this.state = 'starting';
      this.bootstrapPct = 10;
      this._setSummary('tor.checkingLocal');
      this.lastError = '';
      this.emitStatus();

      // 1) Yalnızca açık kullanıcı izni varsa ve gerçek SOCKS5 doğrulamasından geçerse 9050/9150 portlarını kullan
      if (this.allowExternalTor) {
        if ((await checkPortOpen('127.0.0.1', 9050)) && (await verifySocks5Listener(9050))) {
          this.socksPort = 9050;
          this.state = 'connected';
          this.bootstrapPct = 100;
          this._setSummary('tor.connectedLocal');
          this.emitStatus();
          return this.getStatus();
        }
        if ((await checkPortOpen('127.0.0.1', 9150)) && (await verifySocks5Listener(9150))) {
          this.socksPort = 9150;
          this.state = 'connected';
          this.bootstrapPct = 100;
          this._setSummary('tor.connectedBrowser');
          this.emitStatus();
          return this.getStatus();
        }
      }

      // 2) tor.exe ikilisini bul ve --CookieAuthentication 1 ile başlat
      const torBin = this.findTorBinary();
      if (!torBin) {
        this.state = 'error';
        this.bootstrapPct = 0;
        this._setSummary('tor.missingBin');
        this.lastError = 'TOR_BINARY_MISSING';
        this.emitStatus();
        return this.getStatus();
      }

      const dataDir = path.join(this.userDataPath || path.dirname(torBin), 'tor-data');
      this.dataDir = dataDir;
      try {
        fs.mkdirSync(dataDir, { recursive: true });
      } catch {}

      const portBusy = await checkPortOpen('127.0.0.1', 9050, 300);
      this.socksPort = portBusy ? 19050 : 9050;
      this.controlPort = portBusy ? 19051 : 9051;
      this.bootstrapPct = 15;
      this._setSummary('tor.starting');
      this.emitStatus();

      return await new Promise(resolve => {
        let resolved = false;
        const done = () => {
          if (!resolved) {
            resolved = true;
            resolve(this.getStatus());
          }
        };

        try {
          const proc = spawn(
            torBin,
            this.buildTorSpawnArgs(dataDir, torBin),
            { windowsHide: true }
          );
          this.torProc = proc;

          const onLine = text => {
            const lines = String(text).split(/\r?\n/);
            for (const line of lines) {
              const m = line.match(/Bootstrapped\s+(\d+)%\s*\(([^)]+)\):\s*(.+)/i);
              if (m) {
                this.bootstrapPct = parseInt(m[1], 10);
                this._setSummary('tor.bootstrapping', { pct: this.bootstrapPct, stage: m[3] });
                if (this.bootstrapPct >= 100) {
                  this.state = 'connected';
                  this._setSummary('tor.connectedFull');
                  done();
                }
                this.emitStatus();
              }
            }
          };

          proc.stdout.on('data', onLine);
          proc.stderr.on('data', onLine);

          proc.on('error', err => {
            this.state = 'error';
            this.lastError = err.message;
            this._setSummary('tor.startFailed', { msg: err.message });
            this.emitStatus();
            done();
          });

          proc.on('exit', code => {
            this.torProc = null;
            if (this.state !== 'stopped') {
              this.state = 'error';
              this.bootstrapPct = 0;
              this._setSummary('tor.exited', { code: code ?? 0 });
              this.emitStatus();
            }
            done();
          });

          // 25 saniye içinde %100 olmazsa mevcut durumu döndür (arka planda devam eder)
          setTimeout(done, 25000);
        } catch (err) {
          this.state = 'error';
          this.lastError = err.message;
          this._setSummary('tor.error', { msg: err.message });
          this.emitStatus();
          done();
        }
      });
    })();

    this._startPromise = run;
    try {
      return await run;
    } finally {
      if (this._startPromise === run) {
        this._startPromise = null;
      }
    }
  }

  clearTorData() {
    const dir = this.dataDir || (this.userDataPath ? path.join(this.userDataPath, 'tor-data') : '');
    if (!dir) return false;
    try {
      if (fs.existsSync(dir)) {
        fs.rmSync(dir, { recursive: true, force: true });
      }
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Tor ağını durdurur
   */
  async stop(wipeData = false) {
    this.state = 'stopped';
    this.bootstrapPct = 0;
    this.circuitEpoch += 1;
    this._setSummary('tor.disabledKillSwitch');
    this.exitIp = null;
    this.isolatedDomains.clear();
    for (const gw of this.firstPartyGateways.values()) {
      try {
        if (typeof gw.server.closeAllConnections === 'function') gw.server.closeAllConnections();
        gw.server.close();
      } catch {}
    }
    this.firstPartyGateways.clear();
    if (this.gatewayServer) {
      try {
        if (typeof this.gatewayServer.closeAllConnections === 'function') {
          this.gatewayServer.closeAllConnections();
        }
        this.gatewayServer.close();
      } catch {}
      this.gatewayServer = null;
      this.gatewayPort = 0;
    }
    if (this.torProc) {
      try {
        this.torProc.kill();
      } catch {}
      this.torProc = null;
    }
    if (wipeData || this.clearTorDataOnExit) {
      this.clearTorData();
    }
    this.emitStatus();
    return this.getStatus();
  }

  _readControlAuthCommand() {
    const candidates = [
      this.dataDir ? path.join(this.dataDir, 'control_auth_cookie') : '',
      this.dataDir ? path.join(this.dataDir, 'control.authcookie') : ''
    ].filter(Boolean);
    for (const cookieFile of candidates) {
      try {
        if (fs.existsSync(cookieFile)) {
          const hex = fs.readFileSync(cookieFile).toString('hex');
          if (hex) return `AUTHENTICATE ${hex}\r\n`;
        }
      } catch {}
    }
    return this.allowExternalTor ? 'AUTHENTICATE ""\r\n' : '';
  }

  /**
   * Yeni Tor Kimliği & Devre Yenileme (NEWNYM + Epoch Artışı)
   * Tüm alan adlarının yeni bir Tor devresi ve yeni bir çıkış IP'si almasını zorlar.
   */
  async newIdentity() {
    this.circuitEpoch++;
    this.isolatedDomains.clear();
    this.exitIp = null;

    // ControlPort açıksa CookieAuthentication ile SIGNAL NEWNYM gönder
    const authCmd = this._readControlAuthCommand();
    if (authCmd && (await checkPortOpen('127.0.0.1', this.controlPort, 500))) {
      await new Promise(resolve => {
        const sock = net.connect(this.controlPort, '127.0.0.1', () => {
          sock.write(`${authCmd}SIGNAL NEWNYM\r\nQUIT\r\n`);
        });
        sock.setTimeout(1200, () => {
          sock.destroy();
          resolve();
        });
        sock.on('data', () => {});
        sock.on('close', () => resolve());
        sock.on('error', () => resolve());
      });
    }

    this.emitStatus();
    return this.getStatus();
  }

  /**
   * Tor SOCKS5 tüneli üzerinden check.torproject.org/api/ip sorgusu yaparak
   * gerçek Tor Çıkış IP adresini doğrular.
   */
  async verifyTorExitIp() {
    if (this.state !== 'connected') return null;
    return new Promise(resolve => {
      connectViaTorSocks5({
        socksHost: '127.0.0.1',
        socksPort: this.socksPort,
        targetHost: 'check.torproject.org',
        targetPort: 443,
        username: 'zaslon-check',
        password: `epoch-${this.circuitEpoch}`
      })
        .then(rawSock => {
          const tlsSock = tls.connect(
            {
              socket: rawSock,
              servername: 'check.torproject.org',
              rejectUnauthorized: true
            },
            () => {
              tlsSock.write(
                'GET /api/ip HTTP/1.1\r\nHost: check.torproject.org\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n'
              );
            }
          );

          let resp = '';
          tlsSock.setEncoding('utf8');
          tlsSock.on('data', d => {
            resp += d;
          });
          tlsSock.on('end', () => {
            try {
              const body = resp.split('\r\n\r\n').pop() || '';
              const jsonMatch = body.match(/\{[\s\S]*\}/);
              if (jsonMatch) {
                const parsed = JSON.parse(jsonMatch[0]);
                if (parsed.IP) {
                  this.exitIp = parsed.IP;
                  this.emitStatus();
                  return resolve(parsed);
                }
              }
            } catch {}
            resolve(null);
          });
          tlsSock.on('error', () => resolve(null));
        })
        .catch(() => resolve(null));
    });
  }

  /**
   * Sistemde tor.exe yoksa Resmi Tor Project arşivinden Windows Tor Expert Bundle indirip SHA-256 ile doğrulayarak kurar
   */
  async installTorBinary(opts = {}) {
    if (this.findTorBinary()) {
      return await this.start();
    }
    if (this._installPromise) {
      return await this._installPromise;
    }

    const run = (async () => {
      this.state = 'installing';
      this.bootstrapPct = 5;
      this._setSummary('tor.downloadingBundle');
      this.emitStatus();

      const urls = [
        `https://archive.torproject.org/tor-package-archive/torbrowser/${TOR_BUNDLE_VERSION}/tor-expert-bundle-windows-x86_64-${TOR_BUNDLE_VERSION}.tar.gz`,
        `https://dist.torproject.org/torbrowser/${TOR_BUNDLE_VERSION}/tor-expert-bundle-windows-x86_64-${TOR_BUNDLE_VERSION}.tar.gz`
      ];

      const expectedSha256 = String(opts.expectedSha256 || TOR_BUNDLE_SHA256).toLowerCase();
      const fetchFn = opts.fetchFn || this.fetchFn;
      const targetDir = path.join(this.userDataPath || path.join(__dirname, '../../resources'), 'bin', 'tor');
      const archivePath = path.join(targetDir, 'tor-expert-bundle.tar.gz');

      try {
        fs.mkdirSync(targetDir, { recursive: true });
        let downloaded = false;
        let shaMismatchErr = '';

        for (const u of urls) {
          try {
            const res = await fetchFn(u, { credentials: 'omit', referrerPolicy: 'no-referrer' });
            if (!res.ok) continue;
            const buf = Buffer.from(await res.arrayBuffer());
            if (buf.length > 1000000) {
              const actualSha256 = crypto.createHash('sha256').update(buf).digest('hex');
              if (actualSha256 !== expectedSha256) {
                shaMismatchErr = `Tor SHA-256 mismatch (${actualSha256.slice(0, 12)} != ${expectedSha256.slice(0, 12)})`;
                continue;
              }
              fs.writeFileSync(archivePath, buf);
              downloaded = true;
              break;
            }
          } catch {}
        }

        if (!downloaded) {
          throw new Error(shaMismatchErr || t('tor.downloadFailed'));
        }

        this.bootstrapPct = 60;
        this._setSummary('tor.extracting');
        this.emitStatus();

        await new Promise((resolve, reject) => {
          const tar = spawn('tar', ['-xzf', archivePath, '-C', targetDir], { windowsHide: true });
          tar.on('error', reject);
          tar.on('close', code => {
            if (code === 0) resolve();
            else reject(new Error(t('tor.extractError', { code })));
          });
        });

        try {
          if (fs.existsSync(archivePath)) fs.unlinkSync(archivePath);
        } catch {}

        return await this.start();
      } catch (err) {
        try {
          if (fs.existsSync(archivePath)) fs.unlinkSync(archivePath);
        } catch {}
        this.state = 'error';
        this.bootstrapPct = 0;
        this.lastError = err.message;
        this.bootstrapSummary = err.message;
        this.emitStatus();
        return this.getStatus();
      }
    })();

    this._installPromise = run;
    try {
      return await run;
    } finally {
      if (this._installPromise === run) {
        this._installPromise = null;
      }
    }
  }

  _setSummary(key, params = {}) {
    this.summaryKey = key;
    this.summaryParams = params;
    this.rawSummary = null;
  }

  get bootstrapSummary() {
    if (this.rawSummary !== null) return this.rawSummary;
    return t(this.summaryKey || 'tor.disabled', this.summaryParams || {});
  }

  set bootstrapSummary(val) {
    this.summaryKey = null;
    this.summaryParams = {};
    this.rawSummary = String(val ?? '');
  }

  /**
   * "🧅 Tor Zırhlı" konteynerinin Electron session.setProxy() kuralını döndürür.
   * Tüm HTTP/HTTPS/WS/FTP şemalarını First-Party İzolasyon Geçidine yönlendirir.
   */
  getTorSessionProxyRules(firstPartyHost = '') {
    const fpRoot = firstPartyHost ? extractRootDomain(firstPartyHost) : '';
    const gwPort = (fpRoot && this.firstPartyGateways.get(fpRoot)?.port) || this.gatewayPort;
    if (!gwPort) return null;
    return {
      mode: 'fixed_servers',
      proxyRules: `http=127.0.0.1:${gwPort};https=127.0.0.1:${gwPort};ftp=127.0.0.1:${gwPort}`,
      proxyBypassRules: '<-loopback>'
    };
  }

  /**
   * Harici araçlar (yt-dlp vb.) için First-Party + Epoch izoleli yerel HTTP tünel adresi döndürür.
   */
  async getIsolatedHttpProxyUrl(firstPartyHost = '') {
    if (this.state !== 'connected') return '';
    try {
      const port = firstPartyHost
        ? await this.ensureFirstPartyGateway(firstPartyHost)
        : await this.ensureIsolationGateway();
      return port ? `http://127.0.0.1:${port}` : '';
    } catch {
      return '';
    }
  }

  getStatus() {
    return {
      state: this.state,
      connected: this.state === 'connected',
      bootstrapPct: this.bootstrapPct,
      bootstrapSummary: this.bootstrapSummary,
      socksPort: this.socksPort,
      controlPort: this.controlPort,
      gatewayPort: this.gatewayPort,
      allowExternalTor: this.allowExternalTor,
      clearTorDataOnExit: this.clearTorDataOnExit,
      circuitEpoch: this.circuitEpoch,
      exitIp: this.exitIp,
      hasTorBinary: !!this.findTorBinary(),
      bridgesCount: Array.isArray(this.bridges) ? this.bridges.length : 0,
      lastError: this.lastError,
      isolatedCircuits: [...this.isolatedDomains.values()].sort((a, b) => b.lastUsed - a.lastUsed)
    };
  }

  emitStatus() {
    try {
      this.onStatusChange(this.getStatus());
    } catch {}
  }
}

module.exports = {
  TorManager,
  extractRootDomain,
  connectViaTorSocks5,
  verifySocks5Listener,
  sanitizeBridgeLine
};
