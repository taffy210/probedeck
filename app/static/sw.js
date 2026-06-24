/* ProbeDeck service worker.
   Strategy: cache-first for static assets (fast, offline-capable), network-first
   for the app shell ("/"), and *no* interception of data endpoints, the
   WebSocket, downloads or POSTs — so live monitor/console data is never served
   stale from cache. Bump CACHE to invalidate old asset copies on deploy. */
const CACHE = 'probedeck-v1';
const ASSETS = [
  '/static/app.css',
  '/static/htmx.min.js',
  '/static/icon-192.png',
  '/static/icon-512.png',
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== location.origin) return;

  if (url.pathname.startsWith('/static/')) {
    // Cache-first for versioned-ish static assets.
    e.respondWith(
      caches.match(req).then((hit) => hit || fetch(req).then((resp) => {
        const copy = resp.clone();
        caches.open(CACHE).then((c) => c.put(req, copy));
        return resp;
      }))
    );
  } else if (url.pathname === '/') {
    // Network-first for the shell so a fresh load wins, cache as offline fallback.
    e.respondWith(
      fetch(req).then((resp) => {
        const copy = resp.clone();
        caches.open(CACHE).then((c) => c.put(req, copy));
        return resp;
      }).catch(() => caches.match(req))
    );
  }
  // Everything else (data endpoints, downloads, ws upgrades) falls through to
  // the network untouched.
});
