/**
 * RTR Scripts — Service Worker
 * Caches all static assets for offline use in airgapped environments.
 *
 * Strategy: Cache-first for static assets, network-first for navigation.
 * On install, pre-cache all known assets so the app works immediately offline.
 */

const CACHE_NAME = 'rtr-scripts-v1';

const PRECACHE_ASSETS = [
  './',
  './index.html',
  './app.js',
  './styles.css',
  './scripts-data.js',
  './manifest.json',
  './favicon.svg',
  // Monaco Editor — loaded from CDN; falls back gracefully if offline
];

// ── Install: pre-cache static shell ──────────────────────────────────────────
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(PRECACHE_ASSETS))
      .then(() => self.skipWaiting())
  );
});

// ── Activate: clean up old caches ────────────────────────────────────────────
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(key => key !== CACHE_NAME)
          .map(key => caches.delete(key))
      )
    ).then(() => self.clients.claim())
  );
});

// ── Fetch: cache-first for local assets, network-first for CDN ───────────────
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // Skip non-GET requests
  if (event.request.method !== 'GET') return;

  // For CDN resources (Monaco etc.) — network first, fall back to cache
  if (url.hostname !== self.location.hostname && url.hostname !== 'localhost') {
    event.respondWith(
      fetch(event.request)
        .then(response => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
          }
          return response;
        })
        .catch(() => caches.match(event.request))
    );
    return;
  }

  // For local assets — cache first, fall back to network then update cache
  event.respondWith(
    caches.match(event.request).then(cached => {
      if (cached) return cached;

      return fetch(event.request).then(response => {
        if (response.ok) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
        }
        return response;
      });
    })
  );
});

// ── Background sync: notify clients when new content is available ─────────────
self.addEventListener('message', event => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
