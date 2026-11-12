const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { t } = require('../i18n/translations');

let DatabaseSync = null;
try {
  ({ DatabaseSync } = require('node:sqlite'));
} catch {}

const VERIFIER_PLAINTEXT = 'ZASLON_VAULT_VERIFIED_V1';
const KDF_PARAMS = { N: 16384, r: 8, p: 1 };

/**
 * Faz 5.1: Zırh 6 — AES-256-GCM Şifreli Yerel Veritabanı Kasası (SQLite + safeStorage + Ana Parola)
 * - Tüm yerel verileri (geçmiş, yer imleri, okuma listesi, notlar, RSS, ayarlar, oturum)
 *   düz metin localStorage yerine diskte AES-256-GCM (96-bit IV + 128-bit AuthTag) ile şifreler.
 * - Yerleşik SQLite 3 (WAL + PRAGMA secure_delete = ON) motoru üzerinde çalışır.
 * - İki katmanlı anahtar yönetimi sunar:
 *   1) Varsayılan Mod: 256-bit Veri Şifreleme Anahtarı (DEK), Electron safeStorage (Windows DPAPI)
 *      ile işletim sistemi kullanıcı hesabına mühürlenir.
 *   2) Ana Parola (Master Password) Modu: DEK, kullanıcının belirlediği Ana Paroladan scrypt
 *      (N=16384, r=8, p=1) ile türetilen 256-bit KEK ile AES-256-GCM altında sarılır ve
 *      parola girilene kadar kasa kilitli (locked) kalır.
 */
class EncryptedVault {
  constructor(options = {}) {
    this.userDataPath = options.userDataPath || process.cwd();
    this.safeStorage = options.safeStorage || null;
    this.dbPath = path.join(this.userDataPath, 'zaslon-vault.sqlite');
    this.fallbackPath = path.join(this.userDataPath, 'zaslon-vault.enc.json');

    this.db = null;
    this.useSqlite = false;
    this.fallbackStore = { meta: {}, kv: {} };

    this.dek = null; // Bellekteki 32-byte Buffer (Kasa kilitliyken null)
    this.locked = false;
    this.hasMasterPassword = false;
    this.initialized = false;

    this._init();
  }

  _init() {
    fs.mkdirSync(this.userDataPath, { recursive: true });

    if (DatabaseSync) {
      try {
        this.db = new DatabaseSync(this.dbPath);
        this.db.exec(`
          PRAGMA journal_mode = WAL;
          PRAGMA synchronous = NORMAL;
          PRAGMA secure_delete = ON;
          CREATE TABLE IF NOT EXISTS vault_meta (
            k TEXT PRIMARY KEY,
            v TEXT NOT NULL
          );
          CREATE TABLE IF NOT EXISTS vault_kv (
            k TEXT PRIMARY KEY,
            iv BLOB NOT NULL,
            tag BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            updated_at INTEGER NOT NULL
          );
        `);
        this.useSqlite = true;
      } catch {
        this.useSqlite = false;
      }
    }

    if (!this.useSqlite) {
      this._loadFallbackFile();
    }

    const hasMaster = this._getMeta('has_master_password') === '1';
    this.hasMasterPassword = hasMaster;

    if (hasMaster) {
      // Ana parola aktif: Kasa kilitli başlar, kullanıcı parolasını girene kadar DEK belleğe açılmaz
      this.dek = null;
      this.locked = true;
      this.initialized = true;
      return;
    }

    // Varsayılan Donanım / OS DPAPI Modu: DEK varsa çöz, yoksa yeni 256-bit DEK üret
    const osWrapped = this._getMeta('os_wrapped_dek');
    if (osWrapped) {
      const unwrapped = this._unwrapDekWithOs(osWrapped);
      if (unwrapped && unwrapped.length === 32) {
        this.dek = unwrapped;
        this.locked = false;
        this.initialized = true;
        return;
      }
    }

    // İlk kurulum: 256-bit kriptografik rastgele DEK üret
    this.dek = crypto.randomBytes(32);
    const wrapped = this._wrapDekWithOs(this.dek);
    this._setMeta('os_wrapped_dek', wrapped);
    this._setMeta('has_master_password', '0');
    this._setMeta('cipher_algo', 'AES-256-GCM');
    this._setMeta('created_at', String(Date.now()));
    this._writeVerifier();
    this.locked = false;
    this.initialized = true;
  }

  _loadFallbackFile() {
    try {
      if (fs.existsSync(this.fallbackPath)) {
        const raw = JSON.parse(fs.readFileSync(this.fallbackPath, 'utf8'));
        if (raw && typeof raw === 'object') {
          this.fallbackStore.meta = raw.meta || {};
          this.fallbackStore.kv = raw.kv || {};
        }
      }
    } catch {
      this.fallbackStore = { meta: {}, kv: {} };
    }
  }

  _saveFallbackFile() {
    if (this.useSqlite) return;
    try {
      fs.writeFileSync(this.fallbackPath, JSON.stringify(this.fallbackStore, null, 2), 'utf8');
    } catch {}
  }

  _getMeta(key) {
    if (this.useSqlite) {
      const row = this.db.prepare('SELECT v FROM vault_meta WHERE k = ?').get(key);
      return row ? row.v : null;
    }
    return this.fallbackStore.meta[key] ?? null;
  }

  _setMeta(key, value) {
    if (this.useSqlite) {
      this.db
        .prepare('INSERT INTO vault_meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v')
        .run(key, String(value));
      return;
    }
    this.fallbackStore.meta[key] = String(value);
    this._saveFallbackFile();
  }

  _deleteMeta(key) {
    if (this.useSqlite) {
      this.db.prepare('DELETE FROM vault_meta WHERE k = ?').run(key);
      return;
    }
    delete this.fallbackStore.meta[key];
    this._saveFallbackFile();
  }

  _getMachineFallbackKey() {
    let saltHex = this._getMeta('machine_salt');
    if (!saltHex) {
      saltHex = crypto.randomBytes(32).toString('hex');
      this._setMeta('machine_salt', saltHex);
    }
    const seed = `zaslon-os-key:${this.userDataPath}:${process.platform}:${process.arch}`;
    return crypto.scryptSync(seed, Buffer.from(saltHex, 'hex'), 32, KDF_PARAMS);
  }

  _wrapDekWithOs(dekBuf) {
    const hexStr = dekBuf.toString('hex');
    if (this.safeStorage && typeof this.safeStorage.isEncryptionAvailable === 'function') {
      try {
        if (this.safeStorage.isEncryptionAvailable()) {
          const encBuf = this.safeStorage.encryptString(hexStr);
          return 'dpapi:' + encBuf.toString('base64');
        }
      } catch {}
    }
    const mk = this._getMachineFallbackKey();
    const env = this._aesGcmEncryptBuffer(dekBuf, mk);
    return 'scrypt:' + JSON.stringify({
      iv: env.iv.toString('base64'),
      tag: env.tag.toString('base64'),
      ct: env.ciphertext.toString('base64')
    });
  }

  _unwrapDekWithOs(wrappedStr) {
    try {
      if (wrappedStr.startsWith('dpapi:') && this.safeStorage) {
        const b64 = wrappedStr.slice(6);
        const hexStr = this.safeStorage.decryptString(Buffer.from(b64, 'base64'));
        return Buffer.from(hexStr, 'hex');
      }
      if (wrappedStr.startsWith('scrypt:')) {
        const parsed = JSON.parse(wrappedStr.slice(7));
        const mk = this._getMachineFallbackKey();
        return this._aesGcmDecryptBuffer(
          Buffer.from(parsed.ct, 'base64'),
          mk,
          Buffer.from(parsed.iv, 'base64'),
          Buffer.from(parsed.tag, 'base64')
        );
      }
    } catch {}
    return null;
  }

  _derivePasswordKek(password, saltBuf) {
    return crypto.scryptSync(String(password), saltBuf, 32, KDF_PARAMS);
  }

  _aesGcmEncryptBuffer(plainBuf, keyBuf) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', keyBuf, iv);
    const ciphertext = Buffer.concat([cipher.update(plainBuf), cipher.final()]);
    const tag = cipher.getAuthTag();
    return { iv, tag, ciphertext };
  }

  _aesGcmDecryptBuffer(ciphertextBuf, keyBuf, ivBuf, tagBuf) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuf, ivBuf);
    decipher.setAuthTag(tagBuf);
    return Buffer.concat([decipher.update(ciphertextBuf), decipher.final()]);
  }

  _writeVerifier() {
    if (!this.dek) return;
    const enc = this._aesGcmEncryptBuffer(Buffer.from(VERIFIER_PLAINTEXT, 'utf8'), this.dek);
    this._setMeta(
      'verifier',
      JSON.stringify({
        iv: enc.iv.toString('base64'),
        tag: enc.tag.toString('base64'),
        ct: enc.ciphertext.toString('base64')
      })
    );
  }

  _checkVerifierWithDek(candidateDek) {
    const raw = this._getMeta('verifier');
    if (!raw) return true;
    try {
      const parsed = JSON.parse(raw);
      const dec = this._aesGcmDecryptBuffer(
        Buffer.from(parsed.ct, 'base64'),
        candidateDek,
        Buffer.from(parsed.iv, 'base64'),
        Buffer.from(parsed.tag, 'base64')
      );
      return dec.toString('utf8') === VERIFIER_PLAINTEXT;
    } catch {
      return false;
    }
  }

  isLocked() {
    return this.locked || !this.dek;
  }

  /**
   * Ana Parola ile kasayı açar
   */
  unlock(password) {
    if (!this.hasMasterPassword) {
      return { ok: true, locked: false };
    }
    if (!password || typeof password !== 'string') {
      return { ok: false, error: t('vault.errPasswordRequired') };
    }
    try {
      const saltHex = this._getMeta('kdf_salt');
      const pwdWrappedRaw = this._getMeta('pwd_wrapped_dek');
      if (!saltHex || !pwdWrappedRaw) {
        return { ok: false, error: t('vault.errKeyDataMissing') };
      }
      const saltBuf = Buffer.from(saltHex, 'hex');
      const kek = this._derivePasswordKek(password, saltBuf);
      const parsed = JSON.parse(pwdWrappedRaw);
      const candidateDek = this._aesGcmDecryptBuffer(
        Buffer.from(parsed.ct, 'base64'),
        kek,
        Buffer.from(parsed.iv, 'base64'),
        Buffer.from(parsed.tag, 'base64')
      );
      if (!candidateDek || candidateDek.length !== 32 || !this._checkVerifierWithDek(candidateDek)) {
        return { ok: false, error: t('vault.errPasswordWrong') };
      }
      this.dek = candidateDek;
      this.locked = false;
      return { ok: true, locked: false };
    } catch {
      return { ok: false, error: t('vault.errPasswordVerifyFailed') };
    }
  }

  /**
   * Kasayı anında kilitler ve bellekteki DEK anahtarını sıfırlar
   */
  lock() {
    if (!this.hasMasterPassword) {
      return { ok: false, error: t('vault.errSetPasswordFirst') };
    }
    if (this.dek) {
      try {
        this.dek.fill(0);
      } catch {}
      this.dek = null;
    }
    this.locked = true;
    return { ok: true, locked: true };
  }

  /**
   * Ana Parola belirler veya mevcut Ana Parolayı değiştirir
   */
  setMasterPassword(newPassword, currentPassword = '') {
    if (!newPassword || String(newPassword).trim().length < 4) {
      return { ok: false, error: t('vault.errMinLength') };
    }
    if (this.hasMasterPassword) {
      if (this.isLocked()) {
        const u = this.unlock(currentPassword);
        if (!u.ok) return { ok: false, error: t('vault.errCurrentWrong') };
      } else if (currentPassword) {
        const u = this.unlock(currentPassword);
        if (!u.ok) return { ok: false, error: t('vault.errCurrentWrong') };
      }
    }
    if (!this.dek) {
      return { ok: false, error: t('vault.errLockedUnlockFirst') };
    }

    const saltBuf = crypto.randomBytes(32);
    const kek = this._derivePasswordKek(newPassword, saltBuf);
    const wrapped = this._aesGcmEncryptBuffer(this.dek, kek);

    this._setMeta('kdf_salt', saltBuf.toString('hex'));
    this._setMeta(
      'pwd_wrapped_dek',
      JSON.stringify({
        iv: wrapped.iv.toString('base64'),
        tag: wrapped.tag.toString('base64'),
        ct: wrapped.ciphertext.toString('base64')
      })
    );
    this._setMeta('has_master_password', '1');
    this._deleteMeta('os_wrapped_dek');
    this._writeVerifier();

    this.hasMasterPassword = true;
    this.locked = false;
    return { ok: true, hasMasterPassword: true, locked: false };
  }

  /**
   * Ana Parola korumasını kaldırır ve OS DPAPI (safeStorage) otomatik şifrelemesine döner
   */
  removeMasterPassword(currentPassword) {
    if (!this.hasMasterPassword) {
      return { ok: true, hasMasterPassword: false };
    }
    const u = this.unlock(currentPassword);
    if (!u.ok) {
      return { ok: false, error: t('vault.errCurrentWrong') };
    }

    const osWrapped = this._wrapDekWithOs(this.dek);
    this._setMeta('os_wrapped_dek', osWrapped);
    this._setMeta('has_master_password', '0');
    this._deleteMeta('pwd_wrapped_dek');
    this._deleteMeta('kdf_salt');

    this.hasMasterPassword = false;
    this.locked = false;
    return { ok: true, hasMasterPassword: false, locked: false };
  }

  /**
   * Tek bir anahtarı AES-256-GCM ile şifreleyerek kaydeder
   */
  set(key, value) {
    if (this.isLocked()) {
      return { ok: false, locked: true, error: t('vault.errLocked') };
    }
    const k = String(key || '').trim();
    if (!k) return { ok: false, error: t('vault.errInvalidKey') };

    const plainBuf = Buffer.from(JSON.stringify(value ?? null), 'utf8');
    const { iv, tag, ciphertext } = this._aesGcmEncryptBuffer(plainBuf, this.dek);
    const now = Date.now();

    if (this.useSqlite) {
      this.db
        .prepare(
          `INSERT INTO vault_kv (k, iv, tag, ciphertext, updated_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(k) DO UPDATE SET
             iv = excluded.iv,
             tag = excluded.tag,
             ciphertext = excluded.ciphertext,
             updated_at = excluded.updated_at`
        )
        .run(k, iv, tag, ciphertext, now);
    } else {
      this.fallbackStore.kv[k] = {
        iv: iv.toString('base64'),
        tag: tag.toString('base64'),
        ciphertext: ciphertext.toString('base64'),
        updated_at: now
      };
      this._saveFallbackFile();
    }

    this._setMeta('updated_at', String(now));
    return { ok: true };
  }

  /**
   * Birden fazla anahtarı tek seferde şifreleyerek kaydeder
   */
  setBatch(entriesObj) {
    if (this.isLocked()) {
      return { ok: false, locked: true, error: t('vault.errLocked') };
    }
    if (!entriesObj || typeof entriesObj !== 'object') {
      return { ok: false };
    }
    for (const [k, v] of Object.entries(entriesObj)) {
      this.set(k, v);
    }
    return { ok: true };
  }

  /**
   * Tek bir anahtarı AES-256-GCM ile çözerek döndürür
   */
  get(key, defaultValue = null) {
    if (this.isLocked()) return defaultValue;
    const k = String(key || '').trim();
    try {
      if (this.useSqlite) {
        const row = this.db
          .prepare('SELECT iv, tag, ciphertext FROM vault_kv WHERE k = ?')
          .get(k);
        if (!row) return defaultValue;
        const plainBuf = this._aesGcmDecryptBuffer(
          Buffer.from(row.ciphertext),
          this.dek,
          Buffer.from(row.iv),
          Buffer.from(row.tag)
        );
        return JSON.parse(plainBuf.toString('utf8'));
      } else {
        const item = this.fallbackStore.kv[k];
        if (!item) return defaultValue;
        const plainBuf = this._aesGcmDecryptBuffer(
          Buffer.from(item.ciphertext, 'base64'),
          this.dek,
          Buffer.from(item.iv, 'base64'),
          Buffer.from(item.tag, 'base64')
        );
        return JSON.parse(plainBuf.toString('utf8'));
      }
    } catch {
      return defaultValue;
    }
  }

  /**
   * Kasadaki tüm kayıtları çözüp nesne olarak döndürür
   */
  getAll() {
    if (this.isLocked()) {
      return { ok: false, locked: true, data: {} };
    }
    const data = {};
    try {
      if (this.useSqlite) {
        const rows = this.db.prepare('SELECT k, iv, tag, ciphertext FROM vault_kv').all();
        for (const r of rows) {
          try {
            const plainBuf = this._aesGcmDecryptBuffer(
              Buffer.from(r.ciphertext),
              this.dek,
              Buffer.from(r.iv),
              Buffer.from(r.tag)
            );
            data[r.k] = JSON.parse(plainBuf.toString('utf8'));
          } catch {}
        }
      } else {
        for (const [k, item] of Object.entries(this.fallbackStore.kv)) {
          try {
            const plainBuf = this._aesGcmDecryptBuffer(
              Buffer.from(item.ciphertext, 'base64'),
              this.dek,
              Buffer.from(item.iv, 'base64'),
              Buffer.from(item.tag, 'base64')
            );
            data[k] = JSON.parse(plainBuf.toString('utf8'));
          } catch {}
        }
      }
    } catch {}
    return { ok: true, locked: false, data };
  }

  checkpointWal() {
    if (this.useSqlite && this.db) {
      try {
        this.db.exec('PRAGMA wal_checkpoint(TRUNCATE);');
        return true;
      } catch {}
    }
    return false;
  }

  delete(key) {
    const k = String(key || '').trim();
    if (this.useSqlite) {
      // Silmeden önce kriptografik rastgele veri ile üzerine yaz (Forensic Shred)
      try {
        const noise = crypto.randomBytes(64);
        this.db
          .prepare('UPDATE vault_kv SET ciphertext = ?, iv = ?, tag = ? WHERE k = ?')
          .run(noise, crypto.randomBytes(12), crypto.randomBytes(16), k);
      } catch {}
      this.db.prepare('DELETE FROM vault_kv WHERE k = ?').run(k);
      this.checkpointWal();
    } else {
      delete this.fallbackStore.kv[k];
      this._saveFallbackFile();
    }
    return { ok: true };
  }

  /**
   * 🔥 Panik Yakıcı (Panic Burn): Geçmişi, açık sekme oturumunu ve okuma izlerini adli bilişim (forensic)
   * kalıntısı bırakmayacak şekilde rastgele baytlarla ezip SQLite VACUUM + WAL TRUNCATE çalıştırır.
   */
  panicWipe(wipeEverything = false) {
    const keysToShred = wipeEverything
      ? ['hist', 'search_hist', 'session', 'rss_read', 'favcache', 'bms', 'reads', 'notes', 'stats', 'priv', 'shield_rules']
      : ['hist', 'search_hist', 'session', 'rss_read', 'favcache', 'shield_rules'];

    for (const k of keysToShred) {
      this.delete(k);
    }
    if (!this.isLocked()) {
      this.set('hist', []);
      this.set('search_hist', []);
      this.set('session', []);
      this.set('favcache', {});
    }
    if (this.useSqlite) {
      try {
        this.db.exec('VACUUM;');
      } catch {}
      this.checkpointWal();
    }
    return { ok: true, shreddedKeys: keysToShred };
  }

  /**
   * Fabrika Sıfırlaması: Tüm kasayı imha eder ve yeni bir 256-bit DEK üretir
   */
  factoryReset() {
    if (this.useSqlite) {
      try {
        this.db.exec('DELETE FROM vault_kv; DELETE FROM vault_meta; VACUUM;');
      } catch {}
      this.checkpointWal();
    } else {
      this.fallbackStore = { meta: {}, kv: {} };
      this._saveFallbackFile();
    }
    this.dek = crypto.randomBytes(32);
    const wrapped = this._wrapDekWithOs(this.dek);
    this._setMeta('os_wrapped_dek', wrapped);
    this._setMeta('has_master_password', '0');
    this._setMeta('cipher_algo', 'AES-256-GCM');
    this._setMeta('created_at', String(Date.now()));
    this._writeVerifier();
    this.hasMasterPassword = false;
    this.locked = false;
    return { ok: true };
  }

  /**
   * Şifreli Yedek Dışa Aktarma (.zasvault / AES-256-GCM zarfı)
   */
  exportBackup(backupPassword = '') {
    if (this.isLocked()) {
      return { ok: false, error: t('vault.errUnlockBackupExport') };
    }
    const all = this.getAll();
    const payload = {
      app: 'Zaslon Browser',
      version: '1.0',
      exportedAt: new Date().toISOString(),
      data: all.data
    };

    if (backupPassword && String(backupPassword).trim().length > 0) {
      const salt = crypto.randomBytes(32);
      const key = this._derivePasswordKek(backupPassword, salt);
      const plainBuf = Buffer.from(JSON.stringify(payload), 'utf8');
      const enc = this._aesGcmEncryptBuffer(plainBuf, key);
      return {
        ok: true,
        encrypted: true,
        filename: `zaslon-kasa-sifreli-${new Date().toISOString().slice(0, 10)}.zasvault`,
        content: JSON.stringify(
          {
            zaslonVaultBackup: true,
            encrypted: true,
            cipher: 'AES-256-GCM',
            kdf: 'scrypt',
            salt: salt.toString('base64'),
            iv: enc.iv.toString('base64'),
            tag: enc.tag.toString('base64'),
            ciphertext: enc.ciphertext.toString('base64')
          },
          null,
          2
        )
      };
    }

    return {
      ok: true,
      encrypted: false,
      filename: `zaslon-yedek-${new Date().toISOString().slice(0, 10)}.json`,
      content: JSON.stringify(
        {
          zaslonVaultBackup: true,
          encrypted: false,
          ...payload
        },
        null,
        2
      )
    };
  }

  /**
   * Şifreli (.zasvault) veya standart (.json) yedeği kasaya geri yükler
   */
  importBackup(rawText, backupPassword = '') {
    if (this.isLocked()) {
      return { ok: false, error: t('vault.errUnlockBackupImport') };
    }
    try {
      const parsed = JSON.parse(rawText);
      let dataObj = null;

      if (parsed.zaslonVaultBackup && parsed.encrypted) {
        if (!backupPassword) {
          return { ok: false, needsPassword: true, error: t('vault.errBackupNeedsPassword') };
        }
        const salt = Buffer.from(parsed.salt, 'base64');
        const key = this._derivePasswordKek(backupPassword, salt);
        const decBuf = this._aesGcmDecryptBuffer(
          Buffer.from(parsed.ciphertext, 'base64'),
          key,
          Buffer.from(parsed.iv, 'base64'),
          Buffer.from(parsed.tag, 'base64')
        );
        const inner = JSON.parse(decBuf.toString('utf8'));
        dataObj = inner.data || {};
      } else if (parsed.zaslonVaultBackup && parsed.data) {
        dataObj = parsed.data;
      } else if (parsed && typeof parsed === 'object') {
        // Eski localStorage zas_* formatı desteği
        dataObj = {};
        for (const [k, v] of Object.entries(parsed)) {
          const cleanKey = k.startsWith('zas_') ? k.slice(4) : k;
          try {
            dataObj[cleanKey] = typeof v === 'string' ? JSON.parse(v) : v;
          } catch {
            dataObj[cleanKey] = v;
          }
        }
      }

      if (!dataObj || typeof dataObj !== 'object') {
        return { ok: false, error: t('vault.errInvalidBackupFormat') };
      }

      this.setBatch(dataObj);
      return { ok: true, importedKeys: Object.keys(dataObj), data: dataObj };
    } catch {
      return { ok: false, error: t('vault.errBackupDecryptFailed') };
    }
  }

  getStatus() {
    let recordCount = 0;
    let dbSizeBytes = 0;
    try {
      if (this.useSqlite) {
        const row = this.db.prepare('SELECT COUNT(*) AS cnt FROM vault_kv').get();
        recordCount = row ? Number(row.cnt) : 0;
        if (fs.existsSync(this.dbPath)) {
          dbSizeBytes = fs.statSync(this.dbPath).size;
        }
      } else {
        recordCount = Object.keys(this.fallbackStore.kv).length;
        if (fs.existsSync(this.fallbackPath)) {
          dbSizeBytes = fs.statSync(this.fallbackPath).size;
        }
      }
    } catch {}

    const dpapiActive =
      !this.hasMasterPassword &&
      this.safeStorage &&
      typeof this.safeStorage.isEncryptionAvailable === 'function' &&
      this.safeStorage.isEncryptionAvailable();

    return {
      initialized: this.initialized,
      locked: this.isLocked(),
      hasMasterPassword: this.hasMasterPassword,
      cipher: 'AES-256-GCM (96-bit IV + 128-bit AuthTag)',
      keyProtection: this.hasMasterPassword
        ? t('vault.protMaster')
        : dpapiActive
          ? t('vault.protOs')
          : t('vault.protLocal'),
      backend: this.useSqlite ? 'SQLite 3 (WAL + Secure Delete)' : 'AES-256-GCM Binary Store',
      dbPath: this.useSqlite ? this.dbPath : this.fallbackPath,
      dbSizeBytes,
      recordCount,
      updatedAt: Number(this._getMeta('updated_at') || 0)
    };
  }
}

module.exports = {
  EncryptedVault
};
