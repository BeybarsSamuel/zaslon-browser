const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { t } = require('../i18n/translations');

const GITHUB_API_BASE = 'https://api.github.com';
const REPO_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

function normalizeRepo(raw) {
  let s = String(raw || '').trim();
  if (!s) return '';
  s = s.replace(/^https?:\/\/(www\.)?github\.com\//i, '');
  s = s.replace(/\.git$/i, '');
  s = s.replace(/^\/+|\/+$/g, '');
  const parts = s.split('/').filter(Boolean);
  if (parts.length >= 2) {
    s = `${parts[0]}/${parts[1]}`;
  }
  return REPO_PATTERN.test(s) ? s : '';
}

function parseSemverParts(rawVersion) {
  const cleaned = String(rawVersion || '')
    .trim()
    .replace(/^(desktop-)?v/i, '');
  const core = cleaned.split(/[-+]/)[0] || '0';
  const nums = core.split('.').map(n => {
    const parsed = parseInt(n, 10);
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
  });
  while (nums.length < 3) nums.push(0);
  return nums.slice(0, 4);
}

function compareVersions(a, b) {
  const pa = parseSemverParts(a);
  const pb = parseSemverParts(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const va = pa[i] || 0;
    const vb = pb[i] || 0;
    if (va > vb) return 1;
    if (va < vb) return -1;
  }
  return 0;
}

function parseSha256Text(sumsText, targetFile) {
  const lines = String(sumsText || '').split(/\r?\n/);
  const targetLower = path.basename(String(targetFile || '')).toLowerCase();
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const m = trimmed.match(/^([a-fA-F0-9]{64})(?:\s+\*?(.+))?$/);
    if (!m) continue;
    if (!m[2]) return m[1].toLowerCase();
    const fname = path.basename(m[2].trim()).toLowerCase();
    if (fname === targetLower) return m[1].toLowerCase();
  }
  return '';
}

function sanitizeAssetFileName(name) {
  const base = path.basename(String(name || 'Zaslon-Update.exe')).replace(/[^A-Za-z0-9._-]/g, '_');
  return base || 'Zaslon-Update.exe';
}

function selectWindowsAsset(assets = [], preferPortable = false) {
  if (!Array.isArray(assets) || assets.length === 0) return null;
  const winExes = assets.filter(a => a && typeof a.name === 'string' && /\.exe$/i.test(a.name));
  const winZips = assets.filter(a => a && typeof a.name === 'string' && /\.zip$/i.test(a.name) && /win|zaslon|desktop/i.test(a.name));

  const setupExe = winExes.find(a => /setup|installer/i.test(a.name));
  const portableExe = winExes.find(a => /portable/i.test(a.name));
  const anyExe = winExes[0] || null;
  const anyZip = winZips[0] || assets.find(a => a && typeof a.name === 'string' && /\.zip$/i.test(a.name)) || null;

  if (preferPortable) {
    return portableExe || setupExe || anyExe || anyZip;
  }
  return setupExe || anyExe || portableExe || anyZip;
}

function selectChecksumAsset(assets = [], assetName = '') {
  if (!Array.isArray(assets)) return null;
  const lower = String(assetName || '').toLowerCase();
  return (
    assets.find(a => a && typeof a.name === 'string' && a.name.toLowerCase() === `${lower}.sha256`) ||
    assets.find(a => a && typeof a.name === 'string' && /^sha2-?256sums(\.txt)?$/i.test(a.name)) ||
    assets.find(a => a && typeof a.name === 'string' && /checksum|sha256/i.test(a.name) && /\.(txt|sha256)$/i.test(a.name)) ||
    null
  );
}

class GitHubUpdater {
  constructor(options = {}) {
    this.userDataPath = options.userDataPath || process.cwd();
    this.currentVersion = String(options.currentVersion || '1.0.0');
    this.preferPortable = !!options.preferPortable;
    this.fetchFn = options.fetchFn || global.fetch;
    this.onProgress = options.onProgress || (() => {});

    this.repo = normalizeRepo(options.repo || '');
    this.token = String(options.token || '').trim();
    this.state = 'idle'; // idle | checking | available | up-to-date | downloading | downloaded | error
    this.lastError = '';
    this.latestRelease = null;
    this.downloadedFile = '';
    this.checkedAt = 0;
  }

  setConfig({ repo, token } = {}) {
    if (repo !== undefined) {
      this.repo = normalizeRepo(repo);
    }
    if (token !== undefined) {
      this.token = String(token || '').trim();
    }
  }

  getStatus() {
    return {
      repo: this.repo,
      hasToken: !!this.token,
      currentVersion: this.currentVersion,
      state: this.state,
      lastError: this.lastError,
      latestRelease: this.latestRelease
        ? {
            version: this.latestRelease.version,
            tagName: this.latestRelease.tagName,
            name: this.latestRelease.name,
            notes: this.latestRelease.notes,
            publishedAt: this.latestRelease.publishedAt,
            htmlUrl: this.latestRelease.htmlUrl,
            assetName: this.latestRelease.asset?.name || '',
            assetSize: this.latestRelease.asset?.size || 0,
            hasChecksum: !!this.latestRelease.checksumAsset
          }
        : null,
      downloadedFile: this.downloadedFile,
      checkedAt: this.checkedAt
    };
  }

  _buildHeaders(accept = 'application/vnd.github+json', includeAuth = true) {
    const headers = {
      Accept: accept,
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'Zaslon-Updater'
    };
    if (includeAuth && this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    }
    return headers;
  }

  _emit(extra = {}) {
    this.onProgress({
      ...this.getStatus(),
      ...extra
    });
  }

  async checkForUpdates(override = {}) {
    const repo = override.repo !== undefined ? normalizeRepo(override.repo) : this.repo;
    const token = override.token !== undefined ? String(override.token || '').trim() : this.token;
    if (override.repo !== undefined) this.repo = repo;
    if (override.token !== undefined) this.token = token;

    if (!repo) {
      this.state = 'error';
      this.lastError = t('upd.errInvalidRepo');
      this._emit();
      return { ok: false, error: this.lastError, status: this.getStatus() };
    }

    this.state = 'checking';
    this.lastError = '';
    this._emit();

    try {
      const url = `${GITHUB_API_BASE}/repos/${repo}/releases?per_page=15`;
      const res = await this.fetchFn(url, {
        method: 'GET',
        headers: this._buildHeaders('application/vnd.github+json', true),
        credentials: 'omit',
        referrerPolicy: 'no-referrer'
      });

      if (!res.ok) {
        let msg = `GitHub HTTP ${res.status}`;
        if (res.status === 401) msg = t('upd.errAuth');
        else if (res.status === 403) msg = t('upd.errForbidden');
        else if (res.status === 404) msg = t('upd.errNotFound');
        this.state = 'error';
        this.lastError = msg;
        this._emit();
        return { ok: false, error: msg, status: this.getStatus() };
      }

      const releases = await res.json();
      if (!Array.isArray(releases) || releases.length === 0) {
        this.state = 'up-to-date';
        this.latestRelease = null;
        this.checkedAt = Date.now();
        this._emit();
        return { ok: true, hasUpdate: false, status: this.getStatus() };
      }

      // Masaüstü Windows kurulum/portable varlığı içeren en güncel kararlı (non-draft, non-prerelease) sürümü seç
      const candidateReleases = releases.filter(r => r && !r.draft && !r.prerelease);
      let chosen = null;
      let chosenAsset = null;

      for (const rel of candidateReleases) {
        const asset = selectWindowsAsset(rel.assets || [], this.preferPortable);
        if (asset) {
          chosen = rel;
          chosenAsset = asset;
          break;
        }
      }

      // Hiç Windows asset yoksa yine de en güncel kararlı release'i etiket üzerinden göster
      if (!chosen && candidateReleases.length > 0) {
        chosen = candidateReleases[0];
        chosenAsset = selectWindowsAsset(chosen.assets || [], this.preferPortable);
      }

      if (!chosen) {
        this.state = 'up-to-date';
        this.latestRelease = null;
        this.checkedAt = Date.now();
        this._emit();
        return { ok: true, hasUpdate: false, status: this.getStatus() };
      }

      const rawTag = String(chosen.tag_name || chosen.name || '').trim();
      const latestVersion = rawTag.replace(/^(desktop-)?v/i, '');
      const hasUpdate = compareVersions(latestVersion, this.currentVersion) > 0;
      const checksumAsset = chosenAsset ? selectChecksumAsset(chosen.assets || [], chosenAsset.name) : null;

      this.latestRelease = {
        version: latestVersion || rawTag,
        tagName: rawTag,
        name: String(chosen.name || rawTag),
        notes: String(chosen.body || ''),
        publishedAt: String(chosen.published_at || ''),
        htmlUrl: String(chosen.html_url || ''),
        asset: chosenAsset
          ? {
              id: chosenAsset.id,
              name: chosenAsset.name,
              size: Number(chosenAsset.size || 0),
              apiUrl: String(chosenAsset.url || ''),
              browserDownloadUrl: String(chosenAsset.browser_download_url || '')
            }
          : null,
        checksumAsset: checksumAsset
          ? {
              id: checksumAsset.id,
              name: checksumAsset.name,
              apiUrl: String(checksumAsset.url || ''),
              browserDownloadUrl: String(checksumAsset.browser_download_url || '')
            }
          : null
      };

      this.checkedAt = Date.now();
      this.downloadedFile = '';
      this.state = hasUpdate ? 'available' : 'up-to-date';
      this._emit();

      return {
        ok: true,
        hasUpdate,
        status: this.getStatus()
      };
    } catch (err) {
      this.state = 'error';
      this.lastError = err?.message || String(err);
      this._emit();
      return { ok: false, error: this.lastError, status: this.getStatus() };
    }
  }

  async _fetchExpectedSha256(checksumAsset, assetName) {
    if (!checksumAsset) return '';
    const targetUrl = checksumAsset.apiUrl || checksumAsset.browserDownloadUrl;
    if (!targetUrl) return '';
    const res = await this.fetchFn(targetUrl, {
      method: 'GET',
      headers: this._buildHeaders(
        checksumAsset.apiUrl ? 'application/octet-stream' : '*/*',
        !!this.token
      ),
      credentials: 'omit',
      referrerPolicy: 'no-referrer'
    });
    if (!res.ok) {
      throw new Error(`Checksum HTTP ${res.status}`);
    }
    const text = await res.text();
    return parseSha256Text(text, assetName);
  }

  async downloadUpdate() {
    if (!this.latestRelease || !this.latestRelease.asset) {
      return { ok: false, error: t('upd.errNoAsset') };
    }

    const asset = this.latestRelease.asset;
    const downloadUrl = asset.apiUrl || asset.browserDownloadUrl;
    if (!downloadUrl) {
      return { ok: false, error: t('upd.errNoAsset') };
    }

    const updatesDir = path.join(this.userDataPath, 'updates');
    fs.mkdirSync(updatesDir, { recursive: true });
    const safeName = sanitizeAssetFileName(asset.name);
    const outPath = path.join(updatesDir, safeName);
    const tmpPath = `${outPath}.part`;

    this.state = 'downloading';
    this.lastError = '';
    this._emit({ progressPct: 0, receivedBytes: 0, totalBytes: asset.size || 0 });

    try {
      let expectedSha256 = '';
      if (this.latestRelease.checksumAsset) {
        expectedSha256 = await this._fetchExpectedSha256(this.latestRelease.checksumAsset, asset.name);
      }

      const res = await this.fetchFn(downloadUrl, {
        method: 'GET',
        headers: this._buildHeaders(
          asset.apiUrl ? 'application/octet-stream' : '*/*',
          !!this.token
        ),
        credentials: 'omit',
        referrerPolicy: 'no-referrer'
      });

      if (!res.ok) {
        throw new Error(`Download HTTP ${res.status}`);
      }

      const totalBytes = Number(res.headers?.get?.('content-length') || asset.size || 0);
      const hash = crypto.createHash('sha256');
      let receivedBytes = 0;

      const writeStream = fs.createWriteStream(tmpPath);
      try {
        if (res.body && typeof res.body.getReader === 'function') {
          const reader = res.body.getReader();
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (value && value.length > 0) {
              const buf = Buffer.from(value);
              hash.update(buf);
              writeStream.write(buf);
              receivedBytes += buf.length;
              const progressPct = totalBytes > 0 ? Math.min(99, Math.round((receivedBytes / totalBytes) * 100)) : 0;
              this._emit({ progressPct, receivedBytes, totalBytes });
            }
          }
        } else {
          const buf = Buffer.from(await res.arrayBuffer());
          hash.update(buf);
          writeStream.write(buf);
          receivedBytes = buf.length;
        }
      } finally {
        await new Promise((resolve, reject) => {
          writeStream.on('finish', resolve);
          writeStream.on('error', reject);
          writeStream.end();
        });
      }

      const actualSha256 = hash.digest('hex').toLowerCase();
      if (expectedSha256 && actualSha256 !== expectedSha256) {
        try { fs.unlinkSync(tmpPath); } catch {}
        throw new Error(t('upd.errChecksumMismatch'));
      }

      try {
        if (fs.existsSync(outPath)) fs.unlinkSync(outPath);
      } catch {}
      fs.renameSync(tmpPath, outPath);

      this.downloadedFile = outPath;
      this.state = 'downloaded';
      this._emit({ progressPct: 100, receivedBytes, totalBytes: totalBytes || receivedBytes });

      return {
        ok: true,
        filePath: outPath,
        sha256: actualSha256,
        status: this.getStatus()
      };
    } catch (err) {
      try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch {}
      this.state = 'error';
      this.lastError = err?.message || String(err);
      this._emit();
      return { ok: false, error: this.lastError, status: this.getStatus() };
    }
  }

  installUpdate() {
    if (!this.downloadedFile || !fs.existsSync(this.downloadedFile)) {
      return { ok: false, error: t('upd.errNotDownloaded') };
    }

    const ext = path.extname(this.downloadedFile).toLowerCase();
    if (ext === '.exe') {
      const child = spawn(this.downloadedFile, [], {
        detached: true,
        stdio: 'ignore'
      });
      child.unref();
      return { ok: true, launched: true, shouldQuit: true, filePath: this.downloadedFile };
    }

    return { ok: true, launched: false, shouldQuit: false, filePath: this.downloadedFile };
  }
}

module.exports = {
  GitHubUpdater,
  normalizeRepo,
  compareVersions,
  parseSha256Text,
  selectWindowsAsset,
  selectChecksumAsset
};
