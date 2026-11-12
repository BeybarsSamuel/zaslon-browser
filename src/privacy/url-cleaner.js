/**
 * Zaslon Browser — Faz 1: Genişletilmiş URL Takip Temizleyici (ClearURLs Mantığı)
 * Linklerdeki reklamcı ve analitik takip parametrelerini sayfa açılmadan önce sıyırır.
 */

const TRACKING_PARAM_REGEX = new RegExp(
  '^(' +
    [
      'utm_[a-z0-9_]+',
      'fbclid',
      'fb_action_ids',
      'fb_action_types',
      'fb_source',
      'fb_ref',
      'igshid',
      'igsh',
      'gclid',
      'gclsrc',
      'dclid',
      'wbraid',
      'gbraid',
      'msclkid',
      'yclid',
      'ymclid',
      '_openstat',
      'ttclid',
      'twclid',
      'mc_cid',
      'mc_eid',
      '_hsenc',
      '_hsmi',
      '__hssc',
      '__hstc',
      '__hsfp',
      'hsCtaTracking',
      'mkt_tok',
      'vero_id',
      'oly_enc_id',
      'oly_anon_id',
      'rb_clickid',
      'wickedid',
      'spm',
      'scm',
      'aff_platform',
      'aff_trace_key',
      'ref_src',
      'ref_url',
      '_ga',
      '_gl',
      '_ke',
      'trk',
      'trkInfo',
      'lipi',
      'licu'
    ].join('|') +
    ')$',
  'i'
);

// Alan adına özel takip parametreleri (ör. YouTube paylaşım takipçisi ?si=...)
const DOMAIN_SPECIFIC_PARAMS = {
  'youtube.com': new Set(['si', 'pp', 'feature']),
  'youtu.be': new Set(['si', 'feature']),
  'x.com': new Set(['s', 't']),
  'twitter.com': new Set(['s', 't']),
  'instagram.com': new Set(['igshid', 'igsh']),
  'tiktok.com': new Set(['_r', '_t', 'checksum', 'sec_user_id', 'share_app_id', 'share_link_id'])
};

function getBaseDomain(hostname) {
  if (!hostname) return '';
  const parts = hostname.toLowerCase().replace(/^www\./, '').split('.');
  if (parts.length <= 2) return parts.join('.');
  return parts.slice(-2).join('.');
}

function cleanTrackingUrl(rawUrl) {
  try {
    const u = new URL(rawUrl);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      return { url: rawUrl, removedCount: 0, removedKeys: [] };
    }
    const baseDomain = getBaseDomain(u.hostname);
    const domainParams = DOMAIN_SPECIFIC_PARAMS[baseDomain] || DOMAIN_SPECIFIC_PARAMS[u.hostname.replace(/^www\./, '')];
    const removedKeys = [];

    for (const key of [...u.searchParams.keys()]) {
      const isGlobalTracker = TRACKING_PARAM_REGEX.test(key);
      const isDomainTracker =
        domainParams &&
        domainParams.has(key) &&
        !(key === 't' && baseDomain !== 'x.com' && baseDomain !== 'twitter.com') &&
        !(key === 'feature' && u.searchParams.get(key) === 'emb_title');

      if (isGlobalTracker || isDomainTracker) {
        u.searchParams.delete(key);
        removedKeys.push(key);
      }
    }

    return {
      url: removedKeys.length > 0 ? u.toString() : rawUrl,
      removedCount: removedKeys.length,
      removedKeys
    };
  } catch {
    return { url: rawUrl, removedCount: 0, removedKeys: [] };
  }
}

module.exports = {
  cleanTrackingUrl,
  TRACKING_PARAM_REGEX,
   getBaseDomain
};
