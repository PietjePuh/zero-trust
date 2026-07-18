/**
 * Service Worker for Zero Trust Knowledge Base.
 * Network-first strategy for HTML files, cache-first (stale-while-revalidate) for static assets.
 */

var CACHE_NAME = 'zt-cache-20260325';

var URLS_TO_CACHE = [
    './',
    './index.html',
    './tools.html',
    './resources.html',
    './compliance.html',
    './policy.html',
    './processes.html',
    './maturity.html',
    './resets.html',
    './privacy.html',
    './checklist.html',
    './comparison.html',
    './css/style.css',
    './js/theme.js',
    './js/highlight.js',
    './js/search.js',
    './js/search-data.js',
    './js/ui.js'
];

// Install: pre-cache core assets
self.addEventListener('install', function (event) {
    event.waitUntil(
        caches.open(CACHE_NAME).then(function (cache) {
            return cache.addAll(URLS_TO_CACHE);
        })
    );
});

// Activate: clean up old caches
self.addEventListener('activate', function (event) {
    event.waitUntil(
        caches.keys().then(function (cacheNames) {
            return Promise.all(
                cacheNames.filter(function (name) {
                    return name.startsWith('zt-cache-') && name !== CACHE_NAME;
                }).map(function (name) {
                    return caches.delete(name);
                })
            );
        }).then(function () {
            return self.clients.claim();
        })
    );
});

// Handle messages from the client
self.addEventListener('message', function (event) {
    if (event.data && event.data.type === 'SKIP_WAITING') {
        self.skipWaiting();
    }
});

// Fetch strategy
self.addEventListener('fetch', function (event) {
    // Only handle GET requests
    if (event.request.method !== 'GET') return;

    // Only handle same-origin requests
    if (!event.request.url.startsWith(self.location.origin)) return;

    var url = new URL(event.request.url);
    var isHtml = url.pathname.endsWith('.html') || url.pathname.endsWith('/') || !url.pathname.includes('.');

    if (isHtml) {
        // Network-first for HTML files
        event.respondWith(
            fetch(event.request).then(function (networkResponse) {
                if (networkResponse && networkResponse.status === 200) {
                    var responseClone = networkResponse.clone();
                    caches.open(CACHE_NAME).then(function (cache) {
                        cache.put(event.request, responseClone);
                    });
                }
                return networkResponse;
            }).catch(function () {
                return caches.match(event.request);
            })
        );
    } else {
        // Cache-first (stale-while-revalidate) for static assets
        event.respondWith(
            caches.match(event.request).then(function (cachedResponse) {
                var fetchPromise = fetch(event.request).then(function (networkResponse) {
                    if (networkResponse && networkResponse.status === 200) {
                        var responseClone = networkResponse.clone();
                        caches.open(CACHE_NAME).then(function (cache) {
                            cache.put(event.request, responseClone);
                        });
                    }
                    return networkResponse;
                }).catch(function () {
                    // Fail silently, we'll use the cache
                });

                return cachedResponse || fetchPromise;
            })
        );
    }
});
