/**
 * BinaryStudio static build: service worker for offline use.
 *
 * Emitted to the site root as sw.js by tools/build_static.py, which replaces the placeholders
 * below with the build id and the list of files to precache. Registered by transport.js only
 * after the engine has started, so it never competes with the first load.
 *
 * Update behaviour (deliberately simple):
 *  - Each build has its own cache, named after the build id. install precaches every file of
 *    that build; it fails as a whole if any file is missing, so a half-cached build never serves.
 *  - Navigations (the HTML pages) are network-first: online visitors always get the newest
 *    deployment, whose index.html names its own content-hashed assets. Offline (or when the host
 *    answers 5xx), the cached page of this worker's build is served, with the assets of the same
 *    build.
 *  - Content-hashed files (assets/) are immutable: cache first. Other files: network first,
 *    cache as the offline fallback.
 *  - No skipWaiting / clients.claim: a new worker takes over only once every tab of the old
 *    build is closed, so an open tab never loses the files of its own build. activate then
 *    deletes the caches of older builds.
 *  - Only same-origin GET requests are ever handled; everything else goes to the network
 *    untouched (and the CSP allows no other origin anyway).
 */
'use strict';

const BUILD_ID = '@@BUILD_ID@@';
const PRECACHE = /*@@PRECACHE@@*/ [];
const CACHE = `binarystudio-${BUILD_ID}`;
const PREFIX = 'binarystudio-';

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    const scope = self.registration.scope;
    await cache.addAll(PRECACHE.map((p) => new Request(new URL(p, scope).href, { cache: 'reload', credentials: 'same-origin' })));
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const names = await caches.keys();
    await Promise.all(names.filter((n) => n.startsWith(PREFIX) && n !== CACHE).map((n) => caches.delete(n)));
  })());
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  if (req.mode === 'navigate') {
    event.respondWith((async () => {
      let res = null;
      let failure = null;
      try {
        res = await fetch(req);
        // A host that is up and answers normally always wins; an outage (5xx) falls back below.
        if (res.status < 500) return res;
      } catch (err) {
        failure = err;
      }
      const cache = await caches.open(CACHE);
      const path = url.pathname.endsWith('/') ? url.pathname + 'index.html' : url.pathname;
      // The app shell stands in only for the site root. Any other directory (the generated
      // content pages, which are not precached) must not get it: its relative asset URLs would
      // resolve under that directory and the page would come up unstyled and without scripts.
      const atRoot = url.pathname === new URL(self.registration.scope).pathname;
      const hit = await cache.match(new URL(path, url.origin).href, { ignoreSearch: true })
        || (atRoot ? await cache.match(new URL('index.html', self.registration.scope).href) : undefined);
      if (hit) return hit;
      if (res) return res;
      throw failure;
    })());
    return;
  }

  const immutable = url.href.startsWith(new URL('assets/', self.registration.scope).href);
  event.respondWith((async () => {
    const cache = await caches.open(CACHE);
    if (immutable) {
      const hit = await cache.match(req);
      return hit || fetch(req);
    }
    // Files without a content hash: network first, so they always match the newest pages online.
    try {
      return await fetch(req);
    } catch (err) {
      const hit = await cache.match(req);
      if (hit) return hit;
      throw err;
    }
  })());
});
