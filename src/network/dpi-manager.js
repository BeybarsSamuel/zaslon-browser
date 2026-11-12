/**
 * Zaslon Browser — Faz 3: DPI Aşıcı (Derin Paket İnceleme & SNI Engeli Aşma Motoru)
 *
 * 3 Modlu Hibrit Mimari:
 * 1) "builtin" (Varsayılan — Kurulumsuz & Sürücüsüz):
 *    - Yerel 127.0.0.1 HTTP/HTTPS CONNECT proxy başlatır.
 *    - Hedef alan adlarını İSS DNS'ine sormadan Şifreli DoH (1.1.1.1 / 9.9.9.9) ile çözümler.
 *    - İlk TLS ClientHello paketini (0x16 0x03 ...) yakalar; hem TLS Kayıt Katmanında (TLS Record Splitting)
 *      hem de TCP Segment Katmanında (TCP NoDelay + mikro parçalama) SNI alanının tam ortasından böler.
 *    - HTTP isteklerinde "Host:" başlığını "hOsT:" olarak karıştırır ve böler.
 * 2) "spoofdpi":
 *    - resources/bin/spoofdpi.exe veya sistemdeki SpoofDPI ikilisini yerel proxy olarak çalıştırır.
 * 3) "goodbyedpi":
 *    - resources/bin/goodbyedpi.exe (Windows) aracını çalıştırır + yerleşik DoH/SNI parçalayıcıyı destekler.
 */

const net = require('net');
const dns = require('dns');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { t } = require('../i18n/translations');

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
 * TLS ClientHello kaydı içinde SNI uzantısının veya el sıkışma verisinin bölüneceği
 * ofset noktalarını (TLS Record yükü içindeki indeks) bulur.
 */
function findTlsPayloadSplitOffset(payload) {
  if (!Buffer.isBuffer(payload) || payload.length < 16) return 2;
  // TLS Handshake ClientHello (type 0x01) uzanti tablosunu tarayarak SNI alan adını tam ortasından bul
  if (payload[0] === 0x01 && payload.length >= 43) {
    try {
      let pos = 38; // handshake hdr (4) + legacy_version (2) + random (32)
      const sessionIdLen = payload[pos];
      pos += 1 + sessionIdLen;
      if (pos + 2 <= payload.length) {
        const cipherSuitesLen = payload.readUInt16BE(pos);
        pos += 2 + cipherSuitesLen;
      }
      if (pos + 1 <= payload.length) {
        const compMethodsLen = payload[pos];
        pos += 1 + compMethodsLen;
      }
      if (pos + 2 <= payload.length) {
        const extTotalLen = payload.readUInt16BE(pos);
        pos += 2;
        const extEnd = Math.min(payload.length, pos + extTotalLen);
        while (pos + 4 <= extEnd) {
          const extType = payload.readUInt16BE(pos);
          const extLen = payload.readUInt16BE(pos + 2);
          if (pos + 4 + extLen > extEnd) break;
          if (extType === 0x0000 && extLen >= 5) {
            const hostLen = payload.readUInt16BE(pos + 7);
            if (hostLen > 1 && pos + 9 + hostLen <= extEnd) {
              return pos + 9 + Math.max(1, Math.floor(hostLen / 2));
            }
            return Math.min(payload.length - 2, pos + 8);
          }
          pos += 4 + extLen;
        }
      }
    } catch {}
  }
  // Yedek SNI Extension (0x00 0x00) taraması
  for (let i = 38; i < Math.min(payload.length - 8, 2048); i++) {
    if (payload[i] === 0x00 && payload[i + 1] === 0x00 && payload[i + 6] === 0x00) {
      const sniMid = Math.min(payload.length - 2, i + 10);
      if (sniMid > 6) return sniMid;
    }
  }
  return Math.min(24, Math.floor(payload.length / 2));
}

/**
 * Tek bir TLS ClientHello kaydını (0x16 0x03 <minor> <len_hi> <len_lo> <payload...>)
 * RFC uyumlu birden fazla küçük TLS Handshake kaydına (TLS Record Splitting) ve TCP parçasına ayırır.
 * Bu yöntem hem paket birleştiren (TCP reassembly) DPI cihazlarını hem de basit SNI filtrelerini aşar.
 */
function buildFragmentedTlsChunks(buf, splitProfile = 'sni-frag') {
  if (!Buffer.isBuffer(buf) || buf.length < 10 || buf[0] !== 0x16 || buf[1] !== 0x03) {
    return [buf];
  }

  const recVersionMinor = buf[2];
  const recLen = buf.readUInt16BE(3);
  if (buf.length < 5 + recLen || recLen < 8) {
    // Birden fazla TLS kaydı veya alışılmadık uzunluk varsa doğrudan TCP segmentlerine böl
    return [buf.subarray(0, 2), buf.subarray(2, 5), buf.subarray(5)];
  }

  const payload = buf.subarray(5, 5 + recLen);
  const trailing = buf.subarray(5 + recLen);
  const sniSplit = findTlsPayloadSplitOffset(payload);

  const slicePoints =
    splitProfile === 'aggr-frag'
      ? [...new Set([2, Math.min(12, sniSplit - 1), sniSplit - 4, sniSplit, sniSplit + 3])].filter(
          x => x > 0 && x < payload.length
        )
      : [...new Set([2, sniSplit])].filter(x => x > 0 && x < payload.length);

  slicePoints.sort((a, b) => a - b);

  const records = [];
  let prev = 0;
  for (const pt of slicePoints) {
    const part = payload.subarray(prev, pt);
    const hdr = Buffer.from([0x16, 0x03, recVersionMinor, (part.length >> 8) & 0xff, part.length & 0xff]);
    records.push(Buffer.concat([hdr, part]));
    prev = pt;
  }
  const lastPart = payload.subarray(prev);
  const lastHdr = Buffer.from([
    0x16,
    0x03,
    recVersionMinor,
    (lastPart.length >> 8) & 0xff,
    lastPart.length & 0xff
  ]);
  records.push(Buffer.concat([lastHdr, lastPart]));

  if (trailing.length > 0) {
    records.push(trailing);
  }
  return records;
}

/**
 * Hazırlanan parça dizisini TCP NoDelay ile sırayla sokete yazar.
 */
function writeChunksSequentially(socket, chunks, cb) {
  let idx = 0;
  const next = () => {
    if (socket.destroyed) return;
    if (idx >= chunks.length) {
      if (cb) cb();
      return;
    }
    const piece = chunks[idx++];
    socket.write(piece, () => {
      if (idx < chunks.length) {
        setTimeout(next, 2);
      } else if (cb) {
        cb();
      }
    });
  };
  next();
}

class DpiManager {
  constructor({ dohManager, userDataPath, resourcesPath, onStatusChange } = {}) {
    this.dohManager = dohManager || null;
    this.userDataPath = userDataPath || '';
    this.resourcesPath = resourcesPath || path.join(__dirname, '../../resources');
    this.onStatusChange = onStatusChange || (() => {});

    this.enabled = false;
    this.mode = 'builtin'; // 'builtin' | 'spoofdpi' | 'goodbyedpi'
    this.splitProfile = 'sni-frag'; // 'sni-frag' | 'aggr-frag'
    this.proxyServer = null;
    this.proxyPort = 0;
    this.activeSockets = new Set();
    this.externalProc = null;
    this.engineKey = 'dpi.off';
    this.stats = {
      fragmentedHandshakes: 0,
      dohResolved: 0,
      totalTunnels: 0
    };
  }

  /**
   * Harici ikili dosyaları (spoofdpi.exe / goodbyedpi.exe) diskte arar
   */
  findBinary(binName) {
    const candidates = [
      path.join(this.resourcesPath, 'bin', binName),
      path.join(__dirname, '../../resources/bin', binName),
      this.userDataPath ? path.join(this.userDataPath, 'bin', binName) : ''
    ].filter(Boolean);

    for (const p of candidates) {
      if (fs.existsSync(p)) return p;
    }
    return null;
  }

  /**
   * Hedef alan adını Şifreli DoH ile çözümler.
   * strictMode/dohStrict etkinse başarısızlıkta İSS sistem DNS'ine düşmez (Fail-Closed).
   */
  async resolveTargetHost(hostname) {
    if (!hostname) return hostname;
    if (net.isIP(hostname) !== 0 || hostname === 'localhost') {
      return hostname;
    }
    const isStrictDns = !!(this.dohManager && this.dohManager.strictMode !== false);
    if (this.dohManager && this.dohManager.enabled !== false) {
      const dohIp = await this.dohManager.resolveHostViaDoH(hostname);
      if (dohIp) {
        this.stats.dohResolved++;
        return dohIp;
      }
      if (isStrictDns) {
        throw new Error(`Strict DoH resolution failed for ${hostname}`);
      }
    } else if (isStrictDns && this.dohManager) {
      throw new Error(`DoH disabled under strict DNS mode for ${hostname}`);
    }

    try {
      const res = await dns.promises.lookup(hostname, { family: 4 });
      return res.address || hostname;
    } catch {
      return hostname;
    }
  }

  /**
   * Yerleşik Node.js TLS ClientHello Parçalayıcı & DoH Proxy Sunucusunu başlatır
   */
  async startBuiltinProxy() {
    if (this.proxyServer && this.proxyPort > 0) {
      return this.proxyPort;
    }

    return new Promise((resolve, reject) => {
      const server = net.createServer({ allowHalfOpen: false }, async clientSocket => {
        this.activeSockets.add(clientSocket);
        clientSocket.once('close', () => this.activeSockets.delete(clientSocket));
        clientSocket.setNoDelay(true);
        clientSocket.on('error', () => {});

        try {
          const { headerBuf, extraPayload } = await readHttpProxyHead(clientSocket);
          const headerText = headerBuf.toString('latin1');
          const firstLine = headerText.split('\r\n')[0] || '';

          // 1) HTTPS CONNECT Tüneli (TLS Record Splitting + TCP Segment Parçalama)
          const connectMatch = firstLine.match(
            /^CONNECT\s+(?:\[([^\]]+)\]|([^:\s]+)):(\d+)\s+HTTP\/1\.[01]/i
          );
          if (connectMatch) {
            const targetHost = connectMatch[1] || connectMatch[2];
            const targetPort = parseInt(connectMatch[3], 10) || 443;
            const targetIp = await this.resolveTargetHost(targetHost);
            let tunnelEstablished = false;

            const remoteSocket = net.connect(
              { host: targetIp, port: targetPort, noDelay: true },
              () => {
                if (clientSocket.destroyed) {
                  remoteSocket.destroy();
                  return;
                }
                tunnelEstablished = true;
                remoteSocket.setNoDelay(true);
                this.stats.totalTunnels++;

                // Sunucu -> İstemci yönünü yalnız BİR KEZ bağla
                remoteSocket.pipe(clientSocket);

                const handleInitialTlsData = tlsBuf => {
                  clientSocket.pause();
                  if (tlsBuf[0] === 0x16 && tlsBuf[1] === 0x03) {
                    this.stats.fragmentedHandshakes++;
                    const chunks = buildFragmentedTlsChunks(tlsBuf, this.splitProfile);
                    writeChunksSequentially(remoteSocket, chunks, () => {
                      if (!clientSocket.destroyed && !remoteSocket.destroyed) {
                        clientSocket.pipe(remoteSocket);
                        clientSocket.resume();
                      }
                    });
                  } else {
                    remoteSocket.write(tlsBuf);
                    clientSocket.pipe(remoteSocket);
                    clientSocket.resume();
                  }
                };

                clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
                if (extraPayload.length > 0) {
                  handleInitialTlsData(extraPayload);
                } else {
                  clientSocket.once('data', tlsChunk => handleInitialTlsData(tlsChunk));
                }
              }
            );

            remoteSocket.on('error', () => {
              if (!clientSocket.destroyed) {
                if (!tunnelEstablished) {
                  try {
                    clientSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n');
                  } catch {}
                }
                clientSocket.destroy();
              }
            });
            clientSocket.on('close', () => {
              if (!remoteSocket.destroyed) remoteSocket.destroy();
            });
            return;
          }

          // 2) Düz HTTP İsteği (Host başlığını hOsT: olarak karıştır ve böl)
          const httpMatch = firstLine.match(
            /^([A-Z]+)\s+http:\/\/(?:\[([^\]]+)\]|([^/:\s]+))(?::(\d+))?(\/[^\s]*)?\s+(HTTP\/1\.[01])/i
          );
          if (httpMatch) {
            clientSocket.pause();
            const method = httpMatch[1];
            const targetHost = httpMatch[2] || httpMatch[3];
            const targetPort = parseInt(httpMatch[4], 10) || 80;
            const pathPart = httpMatch[5] || '/';
            const httpVer = httpMatch[6];
            const targetIp = await this.resolveTargetHost(targetHost);

            const lines = headerText.split('\r\n').slice(1);
            const rewrittenLines = lines
              .filter(l => l && !/^Proxy-Connection:/i.test(l) && !/^Connection:/i.test(l))
              .map(l => l.replace(/^Host:/i, 'hOsT:'));
            rewrittenLines.push('Connection: close');

            const newReqHead = Buffer.from(
              `${method} ${pathPart} ${httpVer}\r\n${rewrittenLines.join('\r\n')}\r\n\r\n`,
              'latin1'
            );

            const remoteSocket = net.connect(
              { host: targetIp, port: targetPort, noDelay: true },
              () => {
                if (clientSocket.destroyed) {
                  remoteSocket.destroy();
                  return;
                }
                remoteSocket.setNoDelay(true);
                remoteSocket.pipe(clientSocket);
                const splitAt = Math.min(12, Math.max(2, newReqHead.length - 1));
                writeChunksSequentially(
                  remoteSocket,
                  [newReqHead.subarray(0, splitAt), newReqHead.subarray(splitAt)],
                  () => {
                    if (extraPayload.length > 0) remoteSocket.write(extraPayload);
                    if (!clientSocket.destroyed && !remoteSocket.destroyed) {
                      clientSocket.pipe(remoteSocket);
                      clientSocket.resume();
                    }
                  }
                );
              }
            );
            remoteSocket.on('error', () => {
              if (!clientSocket.destroyed) clientSocket.destroy();
            });
            clientSocket.on('close', () => {
              if (!remoteSocket.destroyed) remoteSocket.destroy();
            });
            return;
          }

          clientSocket.destroy();
        } catch {
          if (!clientSocket.destroyed) {
            try {
              clientSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n');
            } catch {}
            clientSocket.destroy();
          }
        }
      });

      server.on('error', err => reject(err));
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        this.proxyServer = server;
        this.proxyPort = addr.port;
        resolve(this.proxyPort);
      });
    });
  }

  /**
   * DPI Aşıcıyı başlatır
   */
  async start({ mode, splitProfile } = {}) {
    if (mode) this.mode = mode;
    if (splitProfile) this.splitProfile = splitProfile;

    await this.stop(false);

    // 1) SpoofDPI modu seçildiyse ve ikili mevcutsa başlat
    if (this.mode === 'spoofdpi') {
      const bin = this.findBinary(process.platform === 'win32' ? 'spoofdpi.exe' : 'spoofdpi');
      if (bin) {
        const port = 18650;
        const spoofArgs = ['-addr', '127.0.0.1', '-port', String(port), '-enable-doh'];
        try {
          const { DOH_PROVIDERS } = require('./doh-manager');
          const prov = DOH_PROVIDERS[this.dohManager?.provider] || DOH_PROVIDERS.quad9;
          if (prov && Array.isArray(prov.bootstrapIps) && prov.bootstrapIps[0]) {
            spoofArgs.push('-dns-addr', prov.bootstrapIps[0]);
          }
        } catch {}
        try {
          this.externalProc = spawn(
            bin,
            spoofArgs,
            { windowsHide: true }
          );
          this.externalProc.on('exit', () => {
            this.externalProc = null;
          });
          this.proxyPort = port;
          this.enabled = true;
          this.engineKey = 'dpi.spoofdpi';
          this.emitStatus();
          return this.getStatus();
        } catch {}
      }
    }

    // 2) GoodbyeDPI modu seçildiyse ve ikili mevcutsa başlat (Üçüncü taraf Yandex DNS yönlendirmesi olmadan yalnızca DPI parçalama)
    if (this.mode === 'goodbyedpi' && process.platform === 'win32') {
      const bin = this.findBinary('goodbyedpi.exe');
      if (bin) {
        try {
          this.externalProc = spawn(
            bin,
            ['-5'],
            { windowsHide: true }
          );
          this.externalProc.on('exit', () => {
            this.externalProc = null;
          });
        } catch {}
      }
    }

    // 3) Yerleşik Zaslon Anti-DPI (TLS ClientHello Parçalayıcı + Şifreli DoH) Proxy'sini başlat
    await this.startBuiltinProxy();
    this.enabled = true;
    this.engineKey =
      this.mode === 'goodbyedpi' && this.externalProc
        ? 'dpi.goodbyedpi'
        : 'dpi.builtin';
    this.emitStatus();
    return this.getStatus();
  }

  /**
   * DPI Aşıcıyı durdurur
   */
  async stop(notify = true) {
    if (this.externalProc) {
      try {
        this.externalProc.kill();
      } catch {}
      this.externalProc = null;
    }
    if (this.proxyServer) {
      for (const s of this.activeSockets) {
        try {
          s.destroy();
        } catch {}
      }
      this.activeSockets.clear();
      await new Promise(res => {
        try {
          this.proxyServer.close(() => res());
        } catch {
          res();
        }
      });
      this.proxyServer = null;
    }
    this.proxyPort = 0;
    this.enabled = false;
    this.engineKey = 'dpi.off';
    if (notify) this.emitStatus();
    return this.getStatus();
  }

  async toggle() {
    if (this.enabled) return await this.stop();
    return await this.start();
  }

  /**
   * Electron session.setProxy() için proxy kuralını döndürür
   */
  getProxyRulesForSession() {
    if (!this.enabled || !this.proxyPort) return null;
    return {
      proxyRules: `http=127.0.0.1:${this.proxyPort};https=127.0.0.1:${this.proxyPort}`,
      proxyBypassRules: '<local>,127.0.0.1,localhost'
    };
  }

  get port() {
    return this.proxyPort;
  }

  get proxyAddress() {
    return this.proxyPort ? `127.0.0.1:${this.proxyPort}` : '';
  }

  get activeEngine() {
    return t(this.engineKey || 'dpi.off');
  }

  getStatus() {
    return {
      enabled: this.enabled,
      mode: this.mode,
      splitProfile: this.splitProfile,
      proxyPort: this.proxyPort,
      activeEngine: this.activeEngine,
      hasSpoofDpiBin: !!this.findBinary(process.platform === 'win32' ? 'spoofdpi.exe' : 'spoofdpi'),
      hasGoodbyeDpiBin: !!this.findBinary('goodbyedpi.exe'),
      stats: { ...this.stats }
    };
  }

  emitStatus() {
    try {
      this.onStatusChange(this.getStatus());
    } catch {}
  }
}

module.exports = {
  DpiManager,
  buildFragmentedTlsChunks
};
