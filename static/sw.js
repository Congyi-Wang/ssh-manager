const CACHE_NAME = 'ssh-manager-v1';
const STATIC_ASSETS = [
    '/',
    '/static/css/style.css',
    '/static/js/api.js',
    '/static/js/totp-modal.js',
    '/static/js/app.js',
    '/manifest.json',
];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then(cache => cache.addAll(STATIC_ASSETS))
    );
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then(keys =>
            Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
        )
    );
    self.clients.claim();
});

self.addEventListener('fetch', (event) => {
    if (event.request.url.includes('/api/')) return;
    event.respondWith(
        fetch(event.request).catch(() => caches.match(event.request))
    );
});
