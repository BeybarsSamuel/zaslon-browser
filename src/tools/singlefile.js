/**
 * Zaslon Browser — Faz 4: Tek Dosya Sayfa Kaydedici (singlefile.js)
 *
 * Aktif web sayfasını tüm CSS stilleri, görselleri (Base64 data:URI) ve
 * sayfa düzeniyle birlikte tek bir bağımsız .html dosyası olarak yerelde arşivler.
 * İnternet bağlantısı tamamen kesik olsa bile çevrimdışı açılır.
 */

const fs = require('fs');
const path = require('path');
const { t } = require('../i18n/translations');

function buildSingleFileSerializerScript() {
  return `(async () => {
    try {
      const pageUrl = location.href;
      const pageTitle = document.title || location.hostname || 'Zaslon-Sayfa';

      // 1) Görselleri Base64 Data-URI'ye çeviren yardımcı
      const imgToDataUrl = async (imgEl) => {
        try {
          const src = imgEl.currentSrc || imgEl.src;
          if (!src || src.startsWith('data:')) return src;
          // Önce doğal boyutlarıyla Canvas üzerinden dene
          if (imgEl.complete && imgEl.naturalWidth > 0 && imgEl.naturalHeight > 0 && imgEl.naturalWidth <= 2400 && imgEl.naturalHeight <= 2400) {
            try {
              const c = document.createElement('canvas');
              c.width = imgEl.naturalWidth;
              c.height = imgEl.naturalHeight;
              const ctx = c.getContext('2d');
              ctx.drawImage(imgEl, 0, 0);
              return c.toDataURL('image/webp', 0.86);
            } catch {}
          }
          // CORS engeli varsa fetch ile dene
          const r = await fetch(src, { cache: 'force-cache' });
          if (!r.ok) return src;
          const blob = await r.blob();
          if (blob.size > 4 * 1024 * 1024) return src; // 4MB üstü dev görselleri atla
          return await new Promise((resolve) => {
            const reader = new FileReader();
            reader.onloadend = () => resolve(reader.result || src);
            reader.onerror = () => resolve(src);
            reader.readAsDataURL(blob);
          });
        } catch {
          return imgEl.src || '';
        }
      };

      // 2) Tüm etkin CSS kurallarını topla
      let combinedCss = '';
      for (const sheet of Array.from(document.styleSheets || [])) {
        try {
          const rules = sheet.cssRules || sheet.rules;
          if (rules) {
            for (const rule of Array.from(rules)) {
              combinedCss += rule.cssText + '\\n';
            }
          }
        } catch {
          // Cross-origin stylesheet ise href üzerinden fetch etmeyi dene
          if (sheet.href) {
            try {
              const r = await fetch(sheet.href, { cache: 'force-cache' });
              if (r.ok) {
                combinedCss += (await r.text()) + '\\n';
              }
            } catch {}
          }
        }
      }

      // 3) DOM ağacını klonla
      const clone = document.documentElement.cloneNode(true);

      // 4) Canlı görselleri klon içindeki karşılıklarına göm
      const liveImgs = Array.from(document.querySelectorAll('img'));
      const cloneImgs = Array.from(clone.querySelectorAll('img'));
      const maxInlineImgs = Math.min(liveImgs.length, 80);
      for (let i = 0; i < maxInlineImgs; i++) {
        const live = liveImgs[i];
        const target = cloneImgs[i];
        if (!live || !target) continue;
        const dataUri = await imgToDataUrl(live);
        if (dataUri) {
          target.setAttribute('src', dataUri);
          target.removeAttribute('srcset');
          target.removeAttribute('loading');
        }
      }

      // 5) Input ve Textarea değerlerini koru
      const liveInputs = Array.from(document.querySelectorAll('input'));
      const cloneInputs = Array.from(clone.querySelectorAll('input'));
      for (let i = 0; i < liveInputs.length; i++) {
        if (cloneInputs[i] && liveInputs[i].type !== 'password') {
          cloneInputs[i].setAttribute('value', liveInputs[i].value || '');
        }
      }

      // 6) Script, harici stylesheet, CSP ve takipçi etiketlerini temizle
      clone.querySelectorAll('script, noscript, iframe, link[rel="stylesheet"], link[rel*="preload"], link[rel*="prefetch"], meta[http-equiv="Content-Security-Policy"]').forEach(el => el.remove());

      // 7) Gömülü CSS ve bilgi başlığını <head> içine ekle
      let head = clone.querySelector('head');
      if (!head) {
        head = document.createElement('head');
        clone.insertBefore(head, clone.firstChild);
      }
      const metaCharset = document.createElement('meta');
      metaCharset.setAttribute('charset', 'utf-8');
      head.insertBefore(metaCharset, head.firstChild);

      const styleEl = document.createElement('style');
      styleEl.setAttribute('data-zaslon-singlefile', 'true');
      styleEl.textContent = combinedCss;
      head.appendChild(styleEl);

      const bannerComment = \`<!--
  ${t('singlefile.commentTitle')}
  ${t('singlefile.sourceUrl')}: \${pageUrl}
  ${t('singlefile.savedAt')}: \${new Date().toISOString()}
-->\`;

      const htmlContent = '<!DOCTYPE html>\\n' + bannerComment + '\\n' + clone.outerHTML;
      return {
        ok: true,
        title: pageTitle,
        url: pageUrl,
        html: htmlContent,
        byteLength: htmlContent.length
      };
    } catch (err) {
      return { ok: false, error: err && err.message ? err.message : String(err) };
    }
  })()`;
}

function sanitizeArchiveName(title) {
  const clean = String(title || 'Sayfa')
    .replace(/[<>:"/\\|?*\x00-\x1F]/g, '-')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 75);
  return clean || 'Zaslon-Arsiv';
}

async function saveSingleFileArchive(webContents, downloadsDir) {
  if (!webContents || webContents.isDestroyed()) {
    return { ok: false, error: t('err.noActiveWebPage') };
  }

  const url = webContents.getURL() || '';
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    return { ok: false, error: t('singlefile.onlyWeb') };
  }

  const res = await webContents.executeJavaScript(buildSingleFileSerializerScript(), true);
  if (!res || !res.ok || !res.html) {
    return { ok: false, error: res?.error || t('singlefile.serializeFail') };
  }

  const safeTitle = sanitizeArchiveName(res.title);
  const dateTag = new Date().toISOString().slice(0, 10);
  let fileName = `${safeTitle} [${dateTag}].html`;
  let fullPath = path.join(downloadsDir, fileName);
  let idx = 1;
  while (fs.existsSync(fullPath)) {
    fileName = `${safeTitle} [${dateTag}] (${idx++}).html`;
    fullPath = path.join(downloadsDir, fileName);
  }

  fs.writeFileSync(fullPath, res.html, 'utf8');
  return {
    ok: true,
    path: fullPath,
    fileName,
    sizeBytes: Buffer.byteLength(res.html, 'utf8'),
    title: res.title,
    url: res.url
  };
}

module.exports = {
  saveSingleFileArchive,
  buildSingleFileSerializerScript
};
