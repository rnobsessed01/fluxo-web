const CACHE_NAME = 'fluxo-ai-cache-v7';
const URLS_TO_CACHE = [
  './index.html',
  './manifest.json',
  // You would typically cache CSS and JS files here, 
  // but since Fluxo is a single-file app, index.html is all we strictly need.
];

// Install event: cache files
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(URLS_TO_CACHE))
      .then(() => self.skipWaiting())
  );
});

// Activate event: clean up old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cache => {
          if (cache !== CACHE_NAME) {
            return caches.delete(cache);
          }
        })
      );
    })
  );
  return self.clients.claim();
});

// Fetch event: serve from cache if available, otherwise fetch and cache dynamic CDN assets
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') {
    return;
  }

  const url = new URL(event.request.url);

  // Dynamic caching list for external resources (Tailwind, Google Fonts, marked, PDF.js, images)
  const isCDN = url.origin.includes('cdn.tailwindcss.com') ||
                url.origin.includes('fonts.googleapis.com') ||
                url.origin.includes('fonts.gstatic.com') ||
                url.origin.includes('cdn.jsdelivr.net') ||
                url.origin.includes('cdnjs.cloudflare.com') ||
                url.pathname.endsWith('.png') ||
                url.pathname.endsWith('.jpg') ||
                url.pathname.endsWith('.svg') ||
                url.pathname.endsWith('.webp') ||
                url.pathname.endsWith('.avif') ||
                url.pathname.endsWith('.ico') ||
                url.pathname.endsWith('.css') ||
                url.pathname.endsWith('.js');

  if (isCDN) {
    event.respondWith(
      caches.open(CACHE_NAME).then(cache => {
        return cache.match(event.request).then(cachedResponse => {
          if (cachedResponse) {
            // Background update (Stale-While-Revalidate)
            fetch(event.request).then(networkResponse => {
              if (networkResponse.status === 200) {
                cache.put(event.request, networkResponse);
              }
            }).catch(() => {});
            return cachedResponse;
          }

          return fetch(event.request).then(networkResponse => {
            if (networkResponse.status === 200) {
              cache.put(event.request, networkResponse.clone());
            }
            return networkResponse;
          }).catch(() => {
            return new Response('', { status: 408, statusText: 'Network timeout' });
          });
        });
      })
    );
  } else {
    event.respondWith(
      caches.match(event.request)
        .then(response => {
          return response || fetch(event.request);
        })
        .catch(() => {
          if (event.request.mode === 'navigate') {
            return caches.match('./index.html');
          }
        })
    );
  }
});
