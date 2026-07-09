const CACHE_NAME = 'svfc-pos-v19';
const URLS_TO_CACHE = [
  '/',
  '/static/style.css',
  '/static/app.jsx',
  '/static/app.js',
  '/static/app_icon.png',
  '/manifest.json'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(URLS_TO_CACHE))
  );
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  
  // Network-first for API calls, HTML, CSS, and JS/JSX to ensure app updates are visible immediately
  if (url.pathname.includes('/api/') || url.pathname === '/' || url.pathname.endsWith('.jsx') || url.pathname.endsWith('.js') || url.pathname.endsWith('.css') || url.pathname.endsWith('.json')) {
    event.respondWith(
      fetch(event.request)
        .then(response => {
          // Clone the response and update the cache
          const resClone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, resClone));
          return response;
        })
        .catch(() => caches.match(event.request))
    );
  } else {
    // Cache-first for other static assets like images and CSS
    event.respondWith(
      caches.match(event.request).then(cached => cached || fetch(event.request))
    );
  }
});
