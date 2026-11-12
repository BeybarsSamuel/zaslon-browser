const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  GitHubUpdater,
  normalizeRepo,
  compareVersions,
  parseSha256Text,
  selectWindowsAsset
} = require('../src/storage/github-updater');

test('normalizeRepo and compareVersions parse GitHub URLs and semver tags cleanly', () => {
  assert.equal(normalizeRepo('https://github.com/SamilDev/Zaslon-Browser.git'), 'SamilDev/Zaslon-Browser');
  assert.equal(normalizeRepo('SamilDev/Zaslon-Browser/'), 'SamilDev/Zaslon-Browser');
  assert.equal(normalizeRepo('invalid'), '');

  assert.equal(compareVersions('v1.0.1', '1.0.0'), 1);
  assert.equal(compareVersions('desktop-v2.1.0', '2.0.9'), 1);
  assert.equal(compareVersions('1.0.0', 'v1.0.0'), 0);
  assert.equal(compareVersions('0.9.5', '1.0.0'), -1);
});

test('selectWindowsAsset prefers Setup.exe for installed and Portable.exe when preferPortable', () => {
  const assets = [
    { name: 'app-universal-release.apk', size: 10 },
    { name: 'Zaslon-Portable.exe', size: 20 },
    { name: 'Zaslon-Setup.exe', size: 30 }
  ];
  assert.equal(selectWindowsAsset(assets, false).name, 'Zaslon-Setup.exe');
  assert.equal(selectWindowsAsset(assets, true).name, 'Zaslon-Portable.exe');
});

test('GitHubUpdater skips Android-only releases, sends Bearer token for private repos, and verifies SHA-256', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zaslon-upd-'));
  try {
    const fakeExeBytes = Buffer.from('MZ-ZASLON-SETUP-BINARY-TEST');
    const fakeSha = crypto.createHash('sha256').update(fakeExeBytes).digest('hex');
    const seenHeaders = [];

    const mockFetch = async (url, opts = {}) => {
      seenHeaders.push({ url, headers: opts.headers || {} });
      if (url.endsWith('/releases?per_page=15')) {
        return {
          ok: true,
          status: 200,
          json: async () => [
            {
              tag_name: 'android-v2.5.0',
              draft: false,
              prerelease: false,
              assets: [{ id: 1, name: 'app-arm64-v8a-release.apk', size: 500, url: 'https://api.github.com/repos/a/b/releases/assets/1' }]
            },
            {
              tag_name: 'v1.2.0',
              name: 'Desktop 1.2.0',
              body: 'Release notes here',
              draft: false,
              prerelease: false,
              assets: [
                { id: 2, name: 'Zaslon-Setup.exe', size: fakeExeBytes.length, url: 'https://api.github.com/repos/a/b/releases/assets/2' },
                { id: 3, name: 'SHA256SUMS.txt', size: 100, url: 'https://api.github.com/repos/a/b/releases/assets/3' }
              ]
            }
          ]
        };
      }
      if (url.endsWith('/assets/3')) {
        return {
          ok: true,
          status: 200,
          text: async () => `${fakeSha}  Zaslon-Setup.exe\n`
        };
      }
      if (url.endsWith('/assets/2')) {
        return {
          ok: true,
          status: 200,
          headers: new Map([['content-length', String(fakeExeBytes.length)]]),
          arrayBuffer: async () => fakeExeBytes
        };
      }
      return { ok: false, status: 404 };
    };

    const updater = new GitHubUpdater({
      userDataPath: tmpDir,
      currentVersion: '1.0.0',
      fetchFn: mockFetch
    });

    const chk = await updater.checkForUpdates({ repo: 'owner/zaslon', token: 'ghp_secret_123' });
    assert.equal(chk.ok, true);
    assert.equal(chk.hasUpdate, true);
    assert.equal(chk.status.latestRelease.version, '1.2.0');
    assert.equal(chk.status.latestRelease.assetName, 'Zaslon-Setup.exe');
    assert.equal(seenHeaders[0].headers.Authorization, 'Bearer ghp_secret_123');

    const dl = await updater.downloadUpdate();
    assert.equal(dl.ok, true);
    assert.equal(dl.sha256, fakeSha);
    assert.equal(fs.existsSync(dl.filePath), true);
    assert.equal(seenHeaders[2].headers.Accept, 'application/octet-stream');
    assert.equal(seenHeaders[2].headers.Authorization, 'Bearer ghp_secret_123');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('GitHubUpdater fails closed on SHA-256 mismatch and deletes partial file', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zaslon-upd-bad-'));
  try {
    const fakeExeBytes = Buffer.from('TAMPERED-BINARY');
    const mockFetch = async url => {
      if (url.endsWith('/releases?per_page=15')) {
        return {
          ok: true,
          status: 200,
          json: async () => [
            {
              tag_name: 'v1.1.0',
              draft: false,
              prerelease: false,
              assets: [
                { id: 10, name: 'Zaslon-Setup.exe', size: fakeExeBytes.length, url: 'https://api.github.com/repos/a/b/releases/assets/10' },
                { id: 11, name: 'SHA256SUMS.txt', size: 80, url: 'https://api.github.com/repos/a/b/releases/assets/11' }
              ]
            }
          ]
        };
      }
      if (url.endsWith('/assets/11')) {
        return { ok: true, status: 200, text: async () => `${'0'.repeat(64)}  Zaslon-Setup.exe\n` };
      }
      if (url.endsWith('/assets/10')) {
        return { ok: true, status: 200, arrayBuffer: async () => fakeExeBytes };
      }
      return { ok: false, status: 404 };
    };

    const updater = new GitHubUpdater({ userDataPath: tmpDir, currentVersion: '1.0.0', fetchFn: mockFetch });
    await updater.checkForUpdates({ repo: 'owner/zaslon' });
    const dl = await updater.downloadUpdate();
    assert.equal(dl.ok, false);
    assert.equal(fs.existsSync(path.join(tmpDir, 'updates', 'Zaslon-Setup.exe')), false);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Desktop boot and Android ViewModel do not auto-check updates on startup', () => {
  const uiSrc = fs.readFileSync(path.join(__dirname, '..', 'ui.html'), 'utf8');
  const bootIdx = uiSrc.indexOf('(async function boot()');
  assert.ok(bootIdx >= 0);
  const bootSection = uiSrc.slice(bootIdx);
  assert.equal(bootSection.includes('updaterCheck'), false);

  const vmSrc = fs.readFileSync(
    path.join(__dirname, '..', '..', 'zaslon-android', 'app', 'src', 'main', 'java', 'com', 'zaslon', 'browser', 'ui', 'BrowserViewModel.kt'),
    'utf8'
  );
  const initStart = vmSrc.indexOf('init {');
  const initEnd = vmSrc.indexOf('override fun onCleared', initStart);
  const initRegion = vmSrc.slice(initStart, initStart + 2500);
  assert.equal(initRegion.includes('checkForAppUpdates'), false);
  assert.equal(parseSha256Text('abcd', 'x'), '');
});
