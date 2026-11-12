/**
 * Zaslon Browser — Faz 4: Gelişmiş Ekran Görüntüsü Motoru (screenshot-full.js)
 *
 * 3 Farklı Yakalama Modu:
 * 1) Görünür Alan (visible): Mevcut görünümü anında PNG olarak kaydeder ve panoya kopyalar.
 * 2) Bölge Kırpma (region): Kullanıcının fareyle seçtiği dikdörtgen alanı kırpıp kaydeder.
 * 3) Tam Sayfa Kaydırmalı (fullpage): Sayfayı yukarıdan aşağıya otomatik kaydırarak
 *    parçaları birleştirir (sticky başlık tekrarlarını önler) ve tek parça uzun PNG üretir.
 */

const fs = require('fs');
const path = require('path');
const { t } = require('../i18n/translations');

function buildTimestampName(prefix = 'Zaslon') {
  const now = new Date();
  const stamp = now.toISOString().replace(/[:.]/g, '-').slice(0, 19);
  return `${prefix}-${stamp}.png`;
}

async function captureVisibleViewport(webContents, picturesDir, clipboard) {
  if (!webContents || webContents.isDestroyed()) {
    return { ok: false, error: t('err.noActivePage') };
  }
  const img = await webContents.capturePage();
  const filePath = path.join(picturesDir, buildTimestampName('Zaslon-Gorunur'));
  fs.writeFileSync(filePath, img.toPNG());
  if (clipboard) clipboard.writeImage(img);
  return {
    ok: true,
    mode: 'visible',
    path: filePath,
    fileName: path.basename(filePath)
  };
}

async function captureCroppedRegion(webContents, rect, picturesDir, clipboard) {
  if (!webContents || webContents.isDestroyed()) {
    return { ok: false, error: t('err.noActivePage') };
  }
  const cleanRect = {
    x: Math.max(0, Math.round(Number(rect?.x) || 0)),
    y: Math.max(0, Math.round(Number(rect?.y) || 0)),
    width: Math.max(10, Math.round(Number(rect?.width) || 100)),
    height: Math.max(10, Math.round(Number(rect?.height) || 100))
  };

  const img = await webContents.capturePage(cleanRect);
  const filePath = path.join(picturesDir, buildTimestampName('Zaslon-Bolge'));
  fs.writeFileSync(filePath, img.toPNG());
  if (clipboard) clipboard.writeImage(img);
  return {
    ok: true,
    mode: 'region',
    path: filePath,
    fileName: path.basename(filePath)
  };
}

async function captureFullPageScrolling(webContents, picturesDir, clipboard, nativeImage) {
  if (!webContents || webContents.isDestroyed()) {
    return { ok: false, error: t('err.noActivePage') };
  }

  const shotTag = `_s_${Math.random().toString(36).slice(2, 8)}`;
  // 1) Sayfa ölçülerini al ve kaydırma çubuklarını geçici gizle
  const metrics = await webContents.executeJavaScript(
    `(() => {
      const docEl = document.documentElement;
      const body = document.body;
      const totalHeight = Math.max(
        docEl ? docEl.scrollHeight : 0,
        body ? body.scrollHeight : 0,
        window.innerHeight
      );
      const viewportWidth = window.innerWidth || 1280;
      const viewportHeight = window.innerHeight || 720;
      const origX = window.scrollX || 0;
      const origY = window.scrollY || 0;

      const styleEl = document.createElement('style');
      styleEl.id = ${JSON.stringify(shotTag)};
      styleEl.textContent = '::-webkit-scrollbar { display: none !important; } html, body { scroll-behavior: auto !important; }';
      document.head.appendChild(styleEl);

      return {
        totalHeight: Math.min(totalHeight, 12000),
        viewportWidth,
        viewportHeight,
        origX,
        origY,
        dpr: window.devicePixelRatio || 1
      };
    })()`,
    true
  );

  if (!metrics || metrics.totalHeight <= metrics.viewportHeight + 10) {
    // Sayfa tek ekrana sığıyorsa doğrudan görünür alanı çek
    await webContents.executeJavaScript(
      `document.getElementById(${JSON.stringify(shotTag)})?.remove()`,
      true
    ).catch(() => {});
    return await captureVisibleViewport(webContents, picturesDir, clipboard);
  }

  const slices = [];
  const vh = metrics.viewportHeight;
  const totalH = metrics.totalHeight;
  let currentY = 0;
  let sliceIndex = 0;

  try {
    while (currentY < totalH) {
      await webContents.executeJavaScript(`window.scrollTo(0, ${currentY});`, true);
      // İlk kareden sonra fixed/sticky üst barları gizle ki her karede tekrar etmesin
      if (sliceIndex === 1) {
        await webContents.executeJavaScript(
          `(() => {
            document.querySelectorAll('*').forEach(el => {
              const cs = getComputedStyle(el);
              if (cs.position === 'fixed' || cs.position === 'sticky') {
                el.dataset.shotVis = el.style.visibility || '';
                el.style.setProperty('visibility', 'hidden', 'important');
              }
            });
          })()`,
          true
        );
      }

      await new Promise(r => setTimeout(r, 120));
      const actualY = await webContents.executeJavaScript(`window.scrollY || 0`, true);
      const img = await webContents.capturePage();
      slices.push({
        y: actualY,
        dataUrl: img.toDataURL()
      });

      currentY += vh;
      sliceIndex++;
      if (sliceIndex > 18) break; // Sonsuz kaydırmalı sayfalarda güvenli sınır
    }

    // Sayfa içinde birleştirme (Canvas stitch) yap ve PNG base64 olarak döndür
    const stitchedBase64 = await webContents.executeJavaScript(
      `(async () => {
        const slices = ${JSON.stringify(slices)};
        const vw = ${metrics.viewportWidth};
        const vh = ${metrics.viewportHeight};
        const totalH = ${totalH};

        const loadImg = (src) => new Promise((res, rej) => {
          const im = new Image();
          im.onload = () => res(im);
          im.onerror = rej;
          im.src = src;
        });

        const firstImg = await loadImg(slices[0].dataUrl);
        const scale = firstImg.width / vw;
        const canvas = document.createElement('canvas');
        canvas.width = firstImg.width;
        canvas.height = Math.round(totalH * scale);
        const ctx = canvas.getContext('2d');

        for (const s of slices) {
          const im = await loadImg(s.dataUrl);
          ctx.drawImage(im, 0, Math.round(s.y * scale));
        }

        return canvas.toDataURL('image/png').replace(/^data:image\\/png;base64,/, '');
      })()`,
      true
    );

    const buf = Buffer.from(stitchedBase64, 'base64');
    const filePath = path.join(picturesDir, buildTimestampName('Zaslon-TamSayfa'));
    fs.writeFileSync(filePath, buf);

    if (clipboard && nativeImage) {
      const nImg = nativeImage.createFromBuffer(buf);
      clipboard.writeImage(nImg);
    }

    return {
      ok: true,
      mode: 'fullpage',
      path: filePath,
      fileName: path.basename(filePath)
    };
  } finally {
    // Sayfayı eski kaydırma konumuna ve görünürlüğüne döndür
    await webContents
      .executeJavaScript(
        `(() => {
          document.getElementById(${JSON.stringify(shotTag)})?.remove();
          document.querySelectorAll('[data-shot-vis]').forEach(el => {
            el.style.visibility = el.dataset.shotVis;
            delete el.dataset.shotVis;
          });
          window.scrollTo(${metrics.origX}, ${metrics.origY});
        })()`,
        true
      )
      .catch(() => {});
  }
}

module.exports = {
  captureVisibleViewport,
  captureCroppedRegion,
  captureFullPageScrolling
};
