/**
 * BinaryStudio — ad slot renderer. Off by default; never loaded unless the configuration enables ads.
 *
 * Where it runs
 *   content pages   learn/ pages include it (deferred) only when a network provider is enabled for
 *                   the 'content' slot. Its config is the JSON island #bs-ads-config.
 *   the app         static/app.js loads it only when config.ads.enabled && config.ads.slots.footer
 *                   (an explicit opt-in). Config: BS.config.ads; slot: BS.ui.slot('footer'), whose
 *                   height the core has already reserved before any content exists.
 *
 * Rules this file keeps (see tools/site_pages.py for the policy and the CSP each provider needs):
 *   - No third-party code ever runs in this origin. Providers are rendered by this file as inert DOM
 *     (textContent, <a rel="sponsored noopener">, <img>) or in a sandboxed iframe without
 *     allow-same-origin. Nothing from a provider is ever assigned to innerHTML.
 *   - Every URL from a provider must be https on an origin the config names; anything else is dropped.
 *   - No request at all until the privacy checks pass: Do Not Track / Global Privacy Control (when
 *     respect_dnt), then the consent choice (when consent is required).
 *   - Clearly labelled. No animation, nothing fixed or sticky, never over content. Blocked, refused,
 *     failed or unfilled -> the slot is hidden (it takes no space).
 *   - This file names no third-party origin itself; they come from the configuration.
 */
(() => {
  'use strict';

  const CONSENT_KEY = 'binarystudio:ads.consent';
  const TIMEOUT_MS = 6000;
  const here = document.currentScript && document.currentScript.src ? document.currentScript.src : document.baseURI;

  const str = (v) => (v === null || v === undefined ? '' : String(v));
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  };

  function privacySignal() {
    try {
      return navigator.globalPrivacyControl === true || navigator.doNotTrack === '1' || window.doNotTrack === '1';
    } catch {
      return false;
    }
  }

  function readConsent(provider) {
    try {
      const v = JSON.parse(window.localStorage.getItem(CONSENT_KEY) || 'null');
      return v && v.provider === provider && (v.choice === 'yes' || v.choice === 'no') ? v.choice : null;
    } catch {
      return null;
    }
  }

  function writeConsent(provider, choice) {
    try {
      if (choice) window.localStorage.setItem(CONSENT_KEY, JSON.stringify({ provider, choice, at: Date.now() }));
      else window.localStorage.removeItem(CONSENT_KEY);
    } catch {
      /* storage unavailable: the question is asked again next time */
    }
  }

  /** https URL on one of `origins` (http only when the configured origin itself is http, i.e. a loopback test). */
  function safeUrl(value, origins) {
    try {
      const u = new URL(str(value), document.baseURI);
      if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
      if (u.username || u.password) return null;
      return origins.includes(u.origin) ? u.href : null;
    } catch {
      return null;
    }
  }

  function sameOriginOrHttps(value) {
    try {
      const u = new URL(str(value), document.baseURI);
      if (u.origin === window.location.origin) return u.href;
      return u.protocol === 'https:' ? u.href : null;
    } catch {
      return null;
    }
  }

  function labelEl(opts, via, viaHref) {
    const label = el('span', 'bs-ad-label', str(opts.label || 'Advertisement'));
    if (via) {
      label.append(' · ');
      const href = viaHref ? sameOriginOrHttps(viaHref) : null;
      if (href) {
        const a = el('a', '', via);
        a.href = href;
        a.rel = 'noopener';
        a.target = '_blank';
        label.appendChild(a);
      } else label.append(via);
    }
    return label;
  }

  function unitEl(opts, { href, title, body, cta, image, imageAlt, width, height, via, viaHref }) {
    const box = el('div', 'bs-ad');
    box.appendChild(labelEl(opts, via, viaHref));
    const a = el('a', 'bs-ad-link');
    a.href = href;
    a.rel = 'sponsored noopener';
    a.target = '_blank';
    a.referrerPolicy = 'no-referrer';
    if (image) {
      const img = el('img', 'bs-ad-img');
      img.src = image;
      img.alt = str(imageAlt);
      img.width = width || 120;
      img.height = height || 90;
      img.decoding = 'async';
      img.referrerPolicy = 'no-referrer';
      a.appendChild(img);
    }
    const copy = el('span', 'bs-ad-copy');
    if (title) copy.appendChild(el('strong', 'bs-ad-title', title));
    if (body) copy.appendChild(el('span', 'bs-ad-body', body));
    if (cta) copy.appendChild(el('span', 'bs-ad-cta', cta));
    a.appendChild(copy);
    box.appendChild(a);
    return box;
  }

  // ---------------------------------------------------------------------------------------------
  // Providers: render(container, ads, placement, signal) -> Promise<boolean filled>
  // ---------------------------------------------------------------------------------------------
  const PROVIDERS = {
    house: {
      network: false,
      async render(box, ads) {
        const units = Array.isArray(ads.options.units) ? ads.options.units : [];
        if (!units.length) return false;
        const u = units[Math.floor(Math.random() * units.length)];
        const href = sameOriginOrHttps(u.url);
        if (!href) return false;
        const image = u.image ? sameOriginOrHttps(u.image) : null;
        box.replaceChildren(unitEl(ads.options, {
          href, title: str(u.title), body: str(u.text), image, imageAlt: u.image_alt,
          width: u.image_width, height: u.image_height, via: str(u.sponsor) || null,
        }));
        return true;
      },
    },

    ethicalads: {
      network: true,
      async render(box, ads, placement, signal) {
        const o = ads.options;
        const api = str(o.api);
        const media = Array.isArray(o.media) ? o.media.map(str) : [];
        const q = new URLSearchParams({
          publisher: str(o.publisher),
          ad_types: o.ad_type === 'text' ? 'text-v1' : 'image-v1',
          div_ids: `bs-ad-${placement}`,
          format: 'json',
          // The page, without query or fragment: in the app the fragment names the open view.
          url: window.location.origin + window.location.pathname,
        });
        if (Array.isArray(o.keywords) && o.keywords.length) q.set('keywords', o.keywords.join('|'));
        if (Array.isArray(o.campaign_types) && o.campaign_types.length) q.set('campaign_types', o.campaign_types.join('|'));
        const res = await fetch(`${api}/api/v1/decision/?${q}`, {
          signal, credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer', mode: 'cors',
        });
        if (!res.ok) return false;
        const ad = await res.json();
        if (!ad || typeof ad !== 'object') return false;
        const href = safeUrl(ad.link, [api]);
        if (!href) return false;
        const copy = ad.copy && typeof ad.copy === 'object' ? ad.copy : {};
        const title = str(copy.headline).slice(0, 120);
        const body = str(copy.content || ad.body).slice(0, 300);
        if (!title && !body) return false;
        const image = o.ad_type === 'text' ? null : safeUrl(ad.image, media.concat([api]));
        box.replaceChildren(unitEl(o, {
          href, title, body, cta: str(copy.cta).slice(0, 60), image, imageAlt: '',
          via: str(o.provider_name || 'EthicalAds'), viaHref: o.attribution_url,
        }));
        // A view counts once at least half the unit has been on screen (the provider's view pixel).
        const viewUrl = safeUrl(ad.view_url, [api]);
        if (viewUrl && 'IntersectionObserver' in window) {
          const io = new IntersectionObserver((entries) => {
            if (entries.some((e) => e.isIntersecting && e.intersectionRatio >= 0.5)) {
              io.disconnect();
              const px = new Image();
              px.referrerPolicy = 'no-referrer';
              px.src = viewUrl;
            }
          }, { threshold: [0.5] });
          io.observe(box);
        }
        return true;
      },
    },

    frame: {
      network: true,
      render(box, ads) {
        const o = ads.options;
        const src = safeUrl(o.src, [str(o.origin)]);
        if (!src || new URL(src).origin === window.location.origin) return Promise.resolve(false);
        return new Promise((resolve) => {
          const wrap = el('div', 'bs-ad');
          wrap.appendChild(labelEl(o));
          const frame = document.createElement('iframe');
          frame.className = 'bs-ad-frame';
          // Never allow-same-origin: the frame gets an opaque origin and cannot reach this page,
          // its storage or the API. Popups may escape the sandbox so the advertiser's page works.
          frame.setAttribute('sandbox', 'allow-scripts allow-popups allow-popups-to-escape-sandbox');
          frame.referrerPolicy = 'no-referrer';
          frame.title = str(o.title || 'Advertisement');
          frame.setAttribute('scrolling', 'no');
          // The framed page may say it has nothing to show: postMessage('bs-ad:empty', '*').
          const onMessage = (ev) => {
            if (ev.source === frame.contentWindow && ev.data === 'bs-ad:empty') {
              window.removeEventListener('message', onMessage);
              resolve(false);
            }
          };
          window.addEventListener('message', onMessage);
          frame.addEventListener('load', () => resolve(true), { once: true });
          frame.addEventListener('error', () => resolve(false), { once: true });
          frame.src = src;
          wrap.appendChild(frame);
          box.replaceChildren(wrap);
        });
      },
    },
  };

  function consentPrompt(box, ads, onChoice) {
    const o = ads.options;
    const name = str(o.provider_name || ads.provider);
    let origin = '';
    try {
      origin = new URL(str(o.origin || o.api)).host;
    } catch {
      origin = '';
    }
    const text = str(o.consent_text) || `This space can show an ad from ${name}. Loading it contacts ${origin || 'the ad network'}, which can see your IP address and may set cookies. Nothing loads unless you choose to show ads.`;
    const card = el('div', 'bs-ad bs-ad-consent');
    card.appendChild(labelEl(o));
    card.appendChild(el('p', '', text));
    const actions = el('div', 'bs-ad-actions');
    [['yes', 'Show ads'], ['no', 'No ads']].forEach(([choice, label]) => {
      const b = el('button', '', label);
      b.type = 'button';
      b.addEventListener('click', () => onChoice(choice));
      actions.appendChild(b);
    });
    card.appendChild(actions);
    box.replaceChildren(card);
  }

  async function fill(slot, ads, placement) {
    const provider = PROVIDERS[ads.provider];
    if (!provider) return slot.hide();
    const o = ads.options || {};
    if (provider.network && o.respect_dnt !== false && privacySignal()) return slot.hide();
    const run = async () => {
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
      let filled = false;
      try {
        filled = await Promise.race([
          provider.render(slot.el, ads, placement, ctl.signal),
          new Promise((resolve) => setTimeout(() => resolve(false), TIMEOUT_MS + 100)),
        ]);
      } catch {
        filled = false; // blocked by an extension or the CSP, offline, malformed answer
      } finally {
        clearTimeout(timer);
      }
      if (!filled) {
        slot.el.replaceChildren();
        slot.hide();
      }
    };
    if (provider.network && o.consent) {
      const choice = readConsent(ads.provider);
      if (choice === 'no') return slot.hide();
      if (choice !== 'yes') {
        consentPrompt(slot.el, ads, (picked) => {
          writeConsent(ads.provider, picked);
          if (picked === 'yes') run();
          else {
            slot.el.replaceChildren();
            slot.hide();
          }
        });
        return undefined;
      }
    }
    return run();
  }

  function resetChoice(ads) {
    writeConsent(ads.provider, null);
    window.location.reload();
  }

  // ---------------------------------------------------------------------------------------------
  // Content pages
  // ---------------------------------------------------------------------------------------------
  function startContentPage() {
    const node = document.querySelector('[data-ad-slot="content"]');
    const island = document.getElementById('bs-ads-config');
    if (!node || !island) return;
    let ads = null;
    try {
      ads = JSON.parse(island.textContent);
    } catch {
      ads = null;
    }
    const slot = {
      el: node,
      hide() { node.hidden = true; },
    };
    if (!ads || !ads.enabled || !ads.slots || !ads.slots.content || !ads.options) return slot.hide();
    const o = ads.options;
    if (o.consent && readConsent(ads.provider)) {
      const nav = document.querySelector('.site-footer nav');
      if (nav) {
        const b = el('button', 'bs-ad-reset', 'Change ad choice');
        b.type = 'button';
        b.addEventListener('click', () => resetChoice(ads));
        nav.appendChild(b);
      }
    }
    return fill(slot, ads, 'content');
  }

  // ---------------------------------------------------------------------------------------------
  // The app (explicit opt-in: config.ads.slots.footer)
  // ---------------------------------------------------------------------------------------------
  function startApp(BS) {
    BS.on('ready', ({ config }) => {
      const ads = config && config.ads;
      const slot = BS.ui.slot('footer');
      if (!slot) return;
      if (!ads || !ads.enabled || !ads.slots || !ads.slots.footer || !ads.options) {
        slot.hide();
        return;
      }
      const link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = new URL('../css/ads.css', here).href;
      document.head.appendChild(link);
      if (ads.options.consent && typeof BS.registerCommand === 'function') {
        BS.registerCommand({
          id: 'ads.consent.reset', title: 'Ads: change ad choice', keywords: 'advertising consent privacy',
          when: () => readConsent(ads.provider) !== null, run: () => resetChoice(ads),
        });
      }
      fill(slot, ads, 'footer');
    });
  }

  if (window.BinaryStudio && typeof window.BinaryStudio.on === 'function') startApp(window.BinaryStudio);
  else if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', startContentPage, { once: true });
  else startContentPage();
})();
