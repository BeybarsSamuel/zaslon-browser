/**
 * Zaslon Browser — Faz 4: Sınırsız Video & Ses İndirici (ytdlp-manager.js)
 *
 * 1) YouTube, OK.ru, VK, X (Twitter), Instagram, TikTok, Reddit, Twitch, Dailymotion, Vimeo
 *    ve gömülü HTML5/HLS/DASH oynatıcı kullanan tüm sitelerden yt-dlp + ffmpeg + Node JS Runtime
 *    ile 4K/1080p/720p MP4 video veya MP3/M4A ses indirir.
 * 2) Tarayıcı oturum çerezlerini (cookies.txt), Referer ve User-Agent başlıklarını otomatik
 *    aktararak oturum gerektiren veya koruma kullanan tüm sitelerde tek tek ayar gerektirmeden çalışır.
 * 3) yt-dlp'nin tanıyamadığı özel sitelerde sekmede yakalanan doğrudan .m3u8 (HLS) veya .mp4/.webm
 *    akışlarına otomatik geri dönüş (fallback) yapar.
 * 4) Panik (Her Şeyi Yak) veya kullanıcı iptali durumunda tüm alt süreçleri (yt-dlp + ffmpeg)
 *    anında sonlandırır.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn, execFileSync } = require('child_process');
const { t } = require('../i18n/translations');
const { getUniformBrowserUserAgent } = require('../privacy/chromium-hardening');

const YTDLP_RELEASE_URL =
  process.platform === 'win32'
    ? 'https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp.exe'
    : 'https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp';
const YTDLP_SHA256SUMS_URL = 'https://github.com/yt-dlp/yt-dlp/releases/latest/download/SHA2-256SUMS';
const NEUTRAL_YTDLP_UA = getUniformBrowserUserAgent();

function parseSha256Sums(sumsText, targetFile) {
  const lines = String(sumsText || '').split(/\r?\n/);
  for (const line of lines) {
    const m = line.trim().match(/^([a-fA-F0-9]{64})\s+\*?(.+)$/);
    if (!m) continue;
    const name = path.basename(m[2].trim());
    if (name === targetFile) {
      return m[1].toLowerCase();
    }
  }
  return '';
}

class YtDlpManager {
  constructor(options = {}) {
    this.userDataPath = options.userDataPath || options.binDir || '';
    this.resourcesPath = options.resourcesPath || '';
    this.downloadsPath = options.downloadsPath || options.downloadsDir || '';
    this.fetchFn = options.fetchFn || global.fetch;
    this.expectedSha256 = options.expectedSha256 ? String(options.expectedSha256).toLowerCase() : '';
    this.onProgress = options.onProgress || (() => {});
    this.onDlEvent = options.onDlEvent || (() => {});
    this.onToast = options.onToast || (() => {});
    this.activeJobs = new Map();
    this.activeProcs = new Map();
    this.activeAborts = new Map();
    this.tempFiles = new Set();
    this.installing = false;
  }

  findYtDlpBinary() {
    const isWin = process.platform === 'win32';
    const binName = isWin ? 'yt-dlp.exe' : 'yt-dlp';
    const candidates = [
      this.resourcesPath ? path.join(this.resourcesPath, 'bin', binName) : '',
      this.userDataPath ? path.join(this.userDataPath, 'bin', binName) : ''
    ].filter(Boolean);

    for (const c of candidates) {
      if (fs.existsSync(c)) return c;
    }

    try {
      const cmd = isWin ? 'where' : 'which';
      const out = execFileSync(cmd, [binName], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        windowsHide: true
      });
      const firstLine = (out || '').split(/\r?\n/)[0]?.trim();
      if (firstLine && fs.existsSync(firstLine)) return firstLine;
    } catch {}

    return null;
  }

  findFfmpegDir() {
    const isWin = process.platform === 'win32';
    const binName = isWin ? 'ffmpeg.exe' : 'ffmpeg';
    const candidates = [
      this.resourcesPath ? path.join(this.resourcesPath, 'bin', binName) : '',
      this.userDataPath ? path.join(this.userDataPath, 'bin', binName) : '',
      path.join(__dirname, '..', '..', 'node_modules', 'ffmpeg-static', binName)
    ].filter(Boolean);

    try {
      const staticPath = require('ffmpeg-static');
      if (staticPath && typeof staticPath === 'string') {
        candidates.unshift(staticPath);
      }
    } catch {}

    for (const c of candidates) {
      if (c && fs.existsSync(c)) return path.dirname(c);
    }

    try {
      const cmd = isWin ? 'where' : 'which';
      const out = execFileSync(cmd, [binName], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        windowsHide: true
      });
      const firstLine = (out || '').split(/\r?\n/)[0]?.trim();
      if (firstLine && fs.existsSync(firstLine)) return path.dirname(firstLine);
    } catch {}

    return null;
  }

  findNodeDir() {
    const isWin = process.platform === 'win32';
    const binName = isWin ? 'node.exe' : 'node';
    const candidates = [
      isWin ? 'C:\\Program Files\\nodejs\\node.exe' : '/usr/local/bin/node',
      isWin ? 'C:\\Program Files (x86)\\nodejs\\node.exe' : '/usr/bin/node',
      process.env.NVM_SYMLINK ? path.join(process.env.NVM_SYMLINK, binName) : ''
    ].filter(Boolean);

    for (const c of candidates) {
      if (fs.existsSync(c)) return path.dirname(c);
    }

    try {
      const cmd = isWin ? 'where' : 'which';
      const out = execFileSync(cmd, [binName], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        windowsHide: true
      });
      const firstLine = (out || '').split(/\r?\n/)[0]?.trim();
      if (firstLine && fs.existsSync(firstLine)) return path.dirname(firstLine);
    } catch {}

    return null;
  }

  /**
   * YouTube vb. sitelerde tekil video izlenirken URL'de bulunan &list=RD..., &index=..., &start_radio=1
   * gibi oynatma listesi parametrelerini temizler; böylece yt-dlp yüzlerce videoluk Mix listesini
   * tararken %0'da takılı kalmaz.
   */
  normalizeVideoUrl(rawUrl) {
    const str = String(rawUrl || '').trim();
    try {
      const u = new URL(str);
      if (/(^|\.)youtube\.com$/i.test(u.hostname) && u.pathname === '/watch' && u.searchParams.has('v')) {
        const vid = u.searchParams.get('v');
        return `https://www.youtube.com/watch?v=${vid}`;
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

  getStatus() {
    const bin = this.findYtDlpBinary();
    const ffmpegDir = this.findFfmpegDir();
    return {
      hasYtDlp: !!bin,
      ytDlpPath: bin || '',
      hasFfmpeg: !!ffmpegDir,
      ffmpegDir: ffmpegDir || '',
      installing: this.installing,
      activeJobs: [...this.activeJobs.values()]
    };
  }

  cleanupTempFile(filePath) {
    if (!filePath) return;
    this.tempFiles.delete(filePath);
    try {
      if (fs.existsSync(filePath)) {
        try {
          const stat = fs.statSync(filePath);
          if (stat.isFile() && stat.size > 0 && stat.size <= 10 * 1024 * 1024) {
            fs.writeFileSync(filePath, crypto.randomBytes(stat.size));
          }
        } catch {}
        fs.unlinkSync(filePath);
      }
    } catch {}
  }

  /**
   * Aktif bir indirme işini veya tüm indirmeleri (Her Şeyi Yak / İptal) anında sonlandırır.
   */
  cancelAllJobs(silent = false) {
    for (const [jobId, proc] of this.activeProcs.entries()) {
      try {
        const job = this.activeJobs.get(jobId);
        if (job) job.state = 'cancelled';
        if (process.platform === 'win32' && proc.pid) {
          try {
            spawn('taskkill', ['/PID', String(proc.pid), '/T', '/F'], { windowsHide: true });
          } catch {}
        }
        proc.kill('SIGKILL');
      } catch {}
    }
    this.activeProcs.clear();

    for (const [, ctrl] of this.activeAborts.entries()) {
      try { ctrl.abort(); } catch {}
    }
    this.activeAborts.clear();

    for (const tmp of [...this.tempFiles]) {
      this.cleanupTempFile(tmp);
    }

    this.activeJobs.clear();
    this.onProgress(null);
    if (!silent) {
      this.onToast(t('yt.stopped'));
    }
    return { ok: true };
  }

  async installYtDlpBinary(opts = {}) {
    if (this.installing) return this.getStatus();
    const existing = this.findYtDlpBinary();
    if (existing) return this.getStatus();
    if (opts.torBlocked) {
      return {
        ...this.getStatus(),
        ok: false,
        error: opts.torBlockedReason || t('err.torTitle')
      };
    }

    this.installing = true;
    this.onProgress({ type: 'install', status: 'starting', state: 'downloading', percent: 5, text: t('yt.installing') });

    const fetchFn = opts.fetchFn || this.fetchFn;
    const binName = process.platform === 'win32' ? 'yt-dlp.exe' : 'yt-dlp';
    const binDir = path.join(this.userDataPath, 'bin');
    const targetPath = path.join(binDir, binName);
    const tmpPath = `${targetPath}.tmp`;

    try {
      fs.mkdirSync(binDir, { recursive: true });

      const headers = { 'User-Agent': NEUTRAL_YTDLP_UA };
      const reqOpts = { headers, credentials: 'omit', referrerPolicy: 'no-referrer' };

      const [res, sumsRes] = await Promise.all([
        fetchFn(YTDLP_RELEASE_URL, reqOpts),
        opts.expectedSha256 || this.expectedSha256
          ? Promise.resolve(null)
          : fetchFn(YTDLP_SHA256SUMS_URL, reqOpts)
      ]);
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }

      let expectedHash = (opts.expectedSha256 || this.expectedSha256 || '').toLowerCase();
      if (!expectedHash) {
        if (!sumsRes || !sumsRes.ok) {
          throw new Error(`SHA2-256SUMS HTTP ${sumsRes ? sumsRes.status : 'unavailable'}`);
        }
        const sumsText = await sumsRes.text();
        expectedHash = parseSha256Sums(sumsText, binName);
      }
      if (!/^[a-f0-9]{64}$/.test(expectedHash)) {
        throw new Error('Missing official SHA-256 checksum for yt-dlp');
      }

      const buf = Buffer.from(await res.arrayBuffer());
      const actualHash = crypto.createHash('sha256').update(buf).digest('hex');
      if (actualHash !== expectedHash) {
        throw new Error(`yt-dlp SHA-256 mismatch (${actualHash.slice(0, 12)} != ${expectedHash.slice(0, 12)})`);
      }

      fs.writeFileSync(tmpPath, buf);
      if (process.platform !== 'win32') {
        fs.chmodSync(tmpPath, 0o755);
      }
      fs.renameSync(tmpPath, targetPath);

      this.installing = false;
      this.onProgress({ type: 'install', status: 'done', state: 'done', percent: 100, text: t('yt.installedText') });
      setTimeout(() => this.onProgress(null), 2500);
      this.onToast(t('yt.installedToast'));
      return this.getStatus();
    } catch (err) {
      try {
        if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
      } catch {}
      this.installing = false;
      this.onProgress({ type: 'install', status: 'error', state: 'failed', percent: 0, text: t('yt.installErrText', { msg: err.message }) });
      this.onToast(t('yt.installErrToast', { msg: err.message }));
      return { ...this.getStatus(), ok: false, error: err.message };
    }
  }

  buildFormatArgs(quality = 'best', hasFfmpeg = false) {
    if (!hasFfmpeg) {
      switch (quality) {
        case '1080p':
          return ['-f', 'b[height<=1080][ext=mp4]/b[height<=1080]/b[ext=mp4]/b'];
        case '720p':
          return ['-f', 'b[height<=720][ext=mp4]/b[height<=720]/b[ext=mp4]/b'];
        case '480p':
          return ['-f', 'b[height<=480][ext=mp4]/b[height<=480]/b[ext=mp4]/b'];
        case 'audio-mp3':
        case 'audio-m4a':
          return ['-f', 'ba[ext=m4a]/ba/b'];
        case 'best':
        default:
          return ['-f', 'b[ext=mp4]/b'];
      }
    }
    switch (quality) {
      case '1080p':
        return [
          '-f',
          'bv*[height<=1080][ext=mp4]+ba[ext=m4a]/b[height<=1080][ext=mp4]/bv*[height<=1080]+ba/b[height<=1080]/b',
          '--merge-output-format',
          'mp4'
        ];
      case '720p':
        return [
          '-f',
          'bv*[height<=720][ext=mp4]+ba[ext=m4a]/b[height<=720][ext=mp4]/bv*[height<=720]+ba/b[height<=720]/b',
          '--merge-output-format',
          'mp4'
        ];
      case '480p':
        return [
          '-f',
          'bv*[height<=480][ext=mp4]+ba[ext=m4a]/b[height<=480][ext=mp4]/bv*[height<=480]+ba/b[height<=480]/b',
          '--merge-output-format',
          'mp4'
        ];
      case 'audio-mp3':
        return ['-x', '--audio-format', 'mp3', '--audio-quality', '0'];
      case 'audio-m4a':
        return ['-f', 'ba[ext=m4a]/ba/b', '-x', '--audio-format', 'm4a'];
      case 'best':
      default:
        return [
          '-f',
          'bv*[ext=mp4]+ba[ext=m4a]/b[ext=mp4]/bv*+ba/b',
          '--merge-output-format',
          'mp4'
        ];
    }
  }

  sanitizeFilename(name, fallback = 'Zaslon-Medya') {
    const clean = String(name || '')
      .replace(/[<>:"/\\|?*\x00-\x1F]/g, '_')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 90);
    return clean || fallback;
  }

  uniqueDownloadPath(filename) {
    const dir = this.downloadsPath || process.cwd();
    const ext = path.extname(filename);
    const base = path.basename(filename, ext);
    let full = path.join(dir, filename);
    let n = 1;
    while (fs.existsSync(full)) {
      full = path.join(dir, `${base} (${n++})${ext}`);
    }
    return full;
  }

  /**
   * Ana Evrensel İndirme Yöneticisi:
   * - Doğrudan .mp4/.webm/.mp3/.m4a bağlantısıysa yerleşik akış indiricisiyle (çerez ve Referer destekli) indirir.
   * - Web sayfası, YouTube, OK.ru, X, Instagram veya .m3u8/.mpd akışıysa yt-dlp + ffmpeg + Node JS Runtime
   *   ile indirir.
   * - Eğer özel bir film/dizi sitesinde yt-dlp sayfa URL'sini çözemezse, sekmede yakalanmış olan
   *   doğrudan .m3u8 / .mp4 akışlarına otomatik geçiş (fallback) yapar.
   */
  async startDownload(options = {}) {
    const rawUrl = String(options.url || '').trim();
    const url = this.normalizeVideoUrl(rawUrl);
    const quality = options.quality || 'best';
    const customArgs = null;
    const title = options.title || options.suggestedTitle || '';
    const referer = options.referer || '';
    const userAgent = options.userAgent || NEUTRAL_YTDLP_UA;
    const cookieHeader = options.cookieHeader || '';
    const cookiesTxtPath = options.cookiesTxtPath || '';
    const fallbackStreams = Array.isArray(options.fallbackStreams) ? options.fallbackStreams : [];

    if (cookiesTxtPath) {
      this.tempFiles.add(cookiesTxtPath);
    }

    if (!/^https?:\/\//i.test(url) || /[\r\n\0]/.test(url)) {
      this.cleanupTempFile(cookiesTxtPath);
      this.onToast(t('yt.enterValidUrl'));
      return { ok: false, error: t('yt.invalidUrl') };
    }

    const isDirectMedia = /\.(mp4|webm|mkv|mov|m4v|mp3|m4a|aac|ogg|flac|wav)(\?|#|$)/i.test(url);
    const isHlsManifest = /\.m3u8(\?|#|$)/i.test(url);

    let bin = this.findYtDlpBinary();

    const proxyUrl = options.proxyUrl || '';
    const fetchFn = options.fetchFn || this.fetchFn;

    if (options.torBlocked) {
      const errMsg = options.torBlockedReason || t('err.torTitle');
      this.cleanupTempFile(cookiesTxtPath);
      this.onToast(errMsg);
      return { ok: false, error: errMsg };
    }

    // Doğrudan medya dosyasıysa yerleşik akış indiricisini kullan
    if (isDirectMedia && !customArgs) {
      const res = await this.downloadDirectStream(url, title, { referer, userAgent, cookieHeader, fetchFn });
      this.cleanupTempFile(cookiesTxtPath);
      return res;
    }

    if (isHlsManifest && !bin) {
      const res = await this.downloadHlsStreamNative(url, title, { referer, userAgent, cookieHeader, fetchFn });
      this.cleanupTempFile(cookiesTxtPath);
      return res;
    }

    if (!bin) {
      this.onToast(t('yt.autoInstallingToast'));
      await this.installYtDlpBinary({ fetchFn });
      bin = this.findYtDlpBinary();
    }

    if (!bin) {
      this.cleanupTempFile(cookiesTxtPath);
      if (isHlsManifest) {
        return await this.downloadHlsStreamNative(url, title, { referer, userAgent, cookieHeader, fetchFn });
      }
      return await this.downloadDirectStream(url, title, { referer, userAgent, cookieHeader, fetchFn });
    }

    const ytdlpResult = await this.spawnYtDlpJob(bin, url, quality, customArgs, title, {
      referer,
      userAgent,
      cookieHeader,
      cookiesTxtPath,
      proxyUrl
    });

    // Eğer yt-dlp özel bir sitede başarısız olduysa ve sekmede yakalanmış doğrudan .m3u8 / .mp4 akışı varsa otomatik onu indir!
    if (!ytdlpResult.ok && !ytdlpResult.cancelled && fallbackStreams.length > 0) {
      const bestStream = fallbackStreams.find(s => s && s.url && s.url !== url && s.url !== rawUrl);
      if (bestStream) {
        this.onToast(t('yt.fallbackToast'));
        if (/\.m3u8(\?|#|$)/i.test(bestStream.url)) {
          const fbRes = await this.spawnYtDlpJob(bin, bestStream.url, quality, null, title || bestStream.title, {
            referer: referer || url,
            userAgent,
            cookieHeader,
            cookiesTxtPath,
            proxyUrl
          });
          this.cleanupTempFile(cookiesTxtPath);
          if (fbRes.ok) return fbRes;
          return await this.downloadHlsStreamNative(bestStream.url, title || bestStream.title, {
            referer: referer || url,
            userAgent,
            cookieHeader,
            fetchFn
          });
        }
        const directRes = await this.downloadDirectStream(bestStream.url, title || bestStream.title, {
          referer: referer || url,
          userAgent,
          cookieHeader,
          fetchFn
        });
        this.cleanupTempFile(cookiesTxtPath);
        return directRes;
      }
    }

    this.cleanupTempFile(cookiesTxtPath);
    return ytdlpResult;
  }

  spawnYtDlpJob(binPath, url, quality, _customArgs, title, netOpts = {}) {
    const cleanUrl = String(url || '').trim();
    if (!/^https?:\/\//i.test(cleanUrl) || /[\r\n\0]/.test(cleanUrl)) {
      return Promise.resolve({ ok: false, error: t('yt.invalidUrl') });
    }
    const jobId = `ytdlp-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const dlDir = this.downloadsPath || process.cwd();
    const ffmpegDir = this.findFfmpegDir();
    const nodeDir = this.findNodeDir();
    const formatArgs = this.buildFormatArgs(quality, !!ffmpegDir);

    const args = [
      '--newline',
      '--encoding',
      'utf-8',
      '--no-part',
      '--no-mtime',
      '--no-playlist',
      '--concurrent-fragments',
      '4',
      '--js-runtimes',
      'node',
      '-P',
      dlDir,
      '-o',
      '%(title).85s [%(id)s].%(ext)s',
      ...formatArgs
    ];

    if (ffmpegDir) {
      args.push('--ffmpeg-location', ffmpegDir);
    }
    // Diskte düz metin geçici cookies.txt bırakma; varsa hemen güvenli şekilde ez ve sil
    if (netOpts.cookiesTxtPath) {
      this.cleanupTempFile(netOpts.cookiesTxtPath);
    }
    args.push('--no-cookies');
    if (netOpts.cookieHeader && !netOpts.omitCookies) {
      args.push('--add-header', `Cookie: ${String(netOpts.cookieHeader).replace(/[\r\n]/g, '')}`);
    }
    if (netOpts.userAgent) {
      args.push('--user-agent', netOpts.userAgent);
    }
    if (netOpts.referer && /^https?:\/\//i.test(netOpts.referer)) {
      args.push('--referer', netOpts.referer);
    }
    if (netOpts.proxyUrl && /^(https?|socks5h?):\/\//i.test(netOpts.proxyUrl)) {
      args.push('--proxy', netOpts.proxyUrl);
    }
    args.push('--', cleanUrl);

    const job = {
      id: jobId,
      url,
      title: title || url,
      quality,
      percent: 0,
      speed: '',
      eta: '',
      statusText: t('yt.resolving'),
      state: 'downloading',
      outputPath: ''
    };
    this.activeJobs.set(jobId, job);

    const emitJob = () => {
      this.onProgress({
        type: 'download',
        jobId: job.id,
        title: job.title,
        percent: job.percent,
        speed: job.speed,
        eta: job.eta,
        text: job.statusText,
        state: job.state,
        path: job.outputPath
      });
      this.onDlEvent({
        id: job.id,
        name: path.basename(job.outputPath || job.title || t('yt.downloadingFallback')),
        received: Math.round(job.percent * 10240),
        total: 100 * 10240,
        state: job.state === 'done' ? 'done' : job.state === 'failed' || job.state === 'cancelled' ? 'failed' : 'progress',
        path: job.outputPath || dlDir
      });
    };

    emitJob();
    this.onToast(t('yt.startedToast'));

    return new Promise(resolve => {
      const childEnv = {
        ...process.env,
        PYTHONIOENCODING: 'utf-8',
        PYTHONUTF8: '1'
      };
      const extraPaths = [nodeDir, ffmpegDir].filter(Boolean);
      if (extraPaths.length) {
        const sep = process.platform === 'win32' ? ';' : ':';
        childEnv.PATH = `${extraPaths.join(sep)}${sep}${childEnv.PATH || childEnv.Path || ''}`;
      }

      const proc = spawn(binPath, args, { windowsHide: true, env: childEnv });
      this.activeProcs.set(jobId, proc);
      let lastErrLine = '';

      const parseOutput = chunk => {
        const lines = String(chunk || '').split(/\r?\n/);
        for (const line of lines) {
          if (!line) continue;
          const trimmed = line.trim();
          if (/^ERROR:/i.test(trimmed)) {
            lastErrLine = trimmed.replace(/^ERROR:\s*/i, '').trim();
          }
          if (/\[jsc:node\]/i.test(trimmed)) {
            job.statusText = t('yt.solvingJs');
            emitJob();
          } else if (/\[Merger\]|\[ExtractAudio\]/i.test(trimmed)) {
            job.statusText = t('yt.mergingFfmpeg');
            job.percent = Math.max(job.percent, 99);
            emitJob();
          }
          const destMatch = trimmed.match(/\[(?:download|ExtractAudio|Merger)\]\s+Destination:\s+(.+)$/i);
          if (destMatch) {
            job.outputPath = destMatch[1].trim().replace(/^"+|"+$/g, '');
            job.title = path.basename(job.outputPath);
          }
          const mergeMatch = trimmed.match(/\[Merger\]\s+Merging formats into\s+"([^"]+)"/i);
          if (mergeMatch) {
            job.outputPath = mergeMatch[1].trim();
            job.title = path.basename(job.outputPath);
          }
          const alreadyMatch = trimmed.match(/\[download\]\s+(.+)\s+has already been downloaded/i);
          if (alreadyMatch) {
            job.outputPath = alreadyMatch[1].trim().replace(/^"+|"+$/g, '');
            job.title = path.basename(job.outputPath);
            job.percent = 100;
          }
          const progMatch = trimmed.match(/\[download\]\s+(\d+(?:\.\d+)?)%(?:\s+of\s+~?(\S+))?(?:\s+at\s+(\S+))?(?:\s+ETA\s+(\S+))?/i);
          if (progMatch) {
            job.percent = Math.min(100, parseFloat(progMatch[1]) || 0);
            if (progMatch[3] && progMatch[3] !== 'Unknown') job.speed = progMatch[3];
            if (progMatch[4] && progMatch[4] !== 'Unknown') job.eta = progMatch[4];
            job.statusText = t('yt.downloadingPct', {
              pct: Math.round(job.percent),
              speed: job.speed ? ` (${job.speed})` : ''
            });
            emitJob();
          }
        }
      };

      proc.stdout.on('data', parseOutput);
      proc.stderr.on('data', parseOutput);

      proc.on('error', err => {
        this.activeProcs.delete(jobId);
        if (job.state === 'cancelled') {
          this.activeJobs.delete(jobId);
          return resolve({ ok: false, cancelled: true, jobId });
        }
        job.state = 'failed';
        job.statusText = t('yt.errStatus', { msg: err.message });
        emitJob();
        this.activeJobs.delete(jobId);
        this.onToast(t('yt.errToast', { msg: err.message }));
        resolve({ ok: false, error: err.message, jobId, engine: 'yt-dlp' });
      });

      proc.on('close', code => {
        this.activeProcs.delete(jobId);
        if (job.state === 'cancelled') {
          this.activeJobs.delete(jobId);
          return resolve({ ok: false, cancelled: true, jobId });
        }
        if (code === 0) {
          job.percent = 100;
          job.state = 'done';
          const fname = path.basename(job.outputPath || t('yt.downloadsFolder'));
          job.statusText = t('yt.doneStatus', { name: fname });
          emitJob();
          this.onToast(t('yt.doneToast', { name: fname }));
          setTimeout(() => {
            this.activeJobs.delete(jobId);
            if (this.activeJobs.size === 0) this.onProgress(null);
          }, 3000);
          resolve({ ok: true, jobId, filename: fname, path: job.outputPath, engine: 'yt-dlp' });
        } else {
          job.state = 'failed';
          const errMsg = lastErrLine || t('yt.errCode', { code });
          job.statusText = t('yt.failedStatus', { msg: errMsg.slice(0, 70) });
          emitJob();
          setTimeout(() => {
            this.activeJobs.delete(jobId);
            if (this.activeJobs.size === 0) this.onProgress(null);
          }, 4000);
          resolve({ ok: false, error: errMsg, jobId, engine: 'yt-dlp' });
        }
      });
    });
  }

  /**
   * Doğrudan .mp4, .webm, .mp3, .m4a bağlantılarını yerleşik akış olarak (akışlı & iptal edilebilir) indirir.
   */
  async downloadDirectStream(url, title = '', netOpts = {}) {
    const jobId = `direct-${Date.now()}`;
    const abortCtrl = new AbortController();
    this.activeAborts.set(jobId, abortCtrl);
    try {
      const u = new URL(url);
      const extMatch = u.pathname.match(/\.(mp4|webm|mkv|mov|m4v|mp3|m4a|aac|ogg|flac|wav)$/i);
      const ext = extMatch ? extMatch[0].toLowerCase() : '.mp4';
      const baseName = this.sanitizeFilename(
        title ? title.replace(/\.[a-z0-9]{2,4}$/i, '') : path.basename(u.pathname, ext),
        'Zaslon-Video'
      );
      const outPath = this.uniqueDownloadPath(`${baseName}${ext}`);

      const headers = {
        'User-Agent': netOpts.userAgent || NEUTRAL_YTDLP_UA
      };
      if (netOpts.referer) headers['Referer'] = netOpts.referer;
      if (netOpts.cookieHeader) headers['Cookie'] = netOpts.cookieHeader;

      this.onProgress({
        type: 'download',
        jobId,
        title: path.basename(outPath),
        percent: 5,
        text: t('yt.directDownloadingText'),
        state: 'downloading',
        path: outPath
      });
      this.onToast(t('yt.directDownloadingToast', { name: path.basename(outPath) }));

      const fetchFn = netOpts.fetchFn || this.fetchFn;
      const res = await fetchFn(url, { headers, credentials: 'omit', referrerPolicy: 'no-referrer', signal: abortCtrl.signal });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const total = parseInt(res.headers.get('content-length') || '0', 10) || 0;
      const buf = Buffer.from(await res.arrayBuffer());
      fs.writeFileSync(outPath, buf);
      this.activeAborts.delete(jobId);

      this.onProgress({
        type: 'download',
        jobId,
        title: path.basename(outPath),
        percent: 100,
        text: t('yt.savedStatus', { name: path.basename(outPath) }),
        state: 'done',
        path: outPath
      });
      setTimeout(() => {
        if (this.activeJobs.size === 0) this.onProgress(null);
      }, 3000);
      this.onDlEvent({
        id: jobId,
        name: path.basename(outPath),
        received: buf.length,
        total: total || buf.length,
        state: 'done',
        path: outPath
      });
      this.onToast(t('yt.savedToast', { name: path.basename(outPath) }));
      return { ok: true, path: outPath, outputPath: outPath, filename: path.basename(outPath), engine: t('yt.engineStream') };
    } catch (err) {
      this.activeAborts.delete(jobId);
      if (err.name === 'AbortError') {
        this.onProgress(null);
        return { ok: false, cancelled: true };
      }
      this.onProgress(null);
      this.onToast(t('yt.streamErrToast', { msg: err.message }));
      return { ok: false, error: err.message };
    }
  }

  /**
   * Yerleşik HLS (.m3u8) İndirici:
   * Master playlist ise en yüksek kaliteli alt akışı seçer, tüm parçaları indirip birleştirir.
   */
  async downloadHlsStreamNative(manifestUrl, title = '', netOpts = {}) {
    const jobId = `hls-${Date.now()}`;
    const abortCtrl = new AbortController();
    this.activeAborts.set(jobId, abortCtrl);
    try {
      const headers = {
        'User-Agent': netOpts.userAgent || NEUTRAL_YTDLP_UA
      };
      if (netOpts.referer) headers['Referer'] = netOpts.referer;
      if (netOpts.cookieHeader) headers['Cookie'] = netOpts.cookieHeader;

      const fetchFn = netOpts.fetchFn || this.fetchFn;
      this.onToast(t('yt.hlsResolvingToast'));
      const res = await fetchFn(manifestUrl, { headers, credentials: 'omit', referrerPolicy: 'no-referrer', signal: abortCtrl.signal });
      if (!res.ok) throw new Error(`Manifest HTTP ${res.status}`);
      let text = await res.text();
      let activeManifestUrl = manifestUrl;

      if (text.includes('#EXT-X-STREAM-INF')) {
        const lines = text.split(/\r?\n/);
        let bestBw = -1;
        let bestUri = '';
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i].trim();
          if (line.startsWith('#EXT-X-STREAM-INF')) {
            const bwMatch = line.match(/BANDWIDTH=(\d+)/i);
            const bw = bwMatch ? parseInt(bwMatch[1], 10) : 0;
            const nextLine = (lines[i + 1] || '').trim();
            if (nextLine && !nextLine.startsWith('#') && bw >= bestBw) {
              bestBw = bw;
              bestUri = nextLine;
            }
          }
        }
        if (bestUri) {
          activeManifestUrl = new URL(bestUri, manifestUrl).toString();
          const subRes = await fetchFn(activeManifestUrl, { headers, credentials: 'omit', referrerPolicy: 'no-referrer', signal: abortCtrl.signal });
          if (subRes.ok) text = await subRes.text();
        }
      }

      const segmentUrls = text
        .split(/\r?\n/)
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#'))
        .map(l => new URL(l, activeManifestUrl).toString());

      if (!segmentUrls.length) {
        throw new Error(t('yt.hlsEmpty'));
      }

      const baseName = this.sanitizeFilename((title || '').replace(/\.m3u8$/i, ''), 'Zaslon-HLS-Video');
      const outPath = this.uniqueDownloadPath(`${baseName}.ts`);
      const outStream = fs.createWriteStream(outPath);
      let totalBytes = 0;

      const maxSegments = Math.min(segmentUrls.length, 600);
      for (let i = 0; i < maxSegments; i++) {
        const segRes = await fetchFn(segmentUrls[i], { headers, credentials: 'omit', referrerPolicy: 'no-referrer', signal: abortCtrl.signal });
        if (segRes.ok) {
          const chunk = Buffer.from(await segRes.arrayBuffer());
          outStream.write(chunk);
          totalBytes += chunk.length;
        }
        const pct = Math.round(((i + 1) / maxSegments) * 100);
        if (i % 3 === 0 || i === maxSegments - 1) {
          this.onProgress({
            type: 'download',
            jobId,
            title: path.basename(outPath),
            percent: pct,
            text: t('yt.hlsProgress', { pct, done: i + 1, total: maxSegments }),
            state: i === maxSegments - 1 ? 'done' : 'downloading',
            path: outPath
          });
          this.onDlEvent({
            id: jobId,
            name: path.basename(outPath),
            received: i + 1,
            total: maxSegments,
            state: i === maxSegments - 1 ? 'done' : 'progress',
            path: outPath
          });
        }
      }

      await new Promise(resolve => outStream.end(resolve));
      this.activeAborts.delete(jobId);
      setTimeout(() => {
        if (this.activeJobs.size === 0) this.onProgress(null);
      }, 3000);
      this.onToast(t('yt.hlsDoneToast', { mb: (totalBytes / 1048576).toFixed(1) }));
      return { ok: true, path: outPath, outputPath: outPath, filename: path.basename(outPath), engine: t('yt.engineHls') };
    } catch (err) {
      this.activeAborts.delete(jobId);
      this.onProgress(null);
      if (err.name === 'AbortError') {
        return { ok: false, cancelled: true };
      }
      this.onToast(t('yt.hlsErrToast', { msg: err.message }));
      return { ok: false, error: err.message };
    }
  }
}

module.exports = {
  YtDlpManager
};
