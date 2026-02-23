/**
 * Service Worker for Zero Trust Knowledge Base.
 * Cache-first strategy for static assets with network fallback.
 */

var CACHE_NAME = 'zt-cache-v1';

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
        }).then(function () {
            return self.skipWaiting();
        })
    );
});

// Activate: clean up old caches
self.addEventListener('activate', function (event) {
    event.waitUntil(
        caches.keys().then(function (cacheNames) {
            return Promise.all(
                cacheNames.filter(function (name) {
                    return name !== CACHE_NAME;
                }).map(function (name) {
                    return caches.delete(name);
                })
            );
        }).then(function () {
            return self.clients.claim();
        })
    );
});

// Fetch: cache-first, then network
self.addEventListener('fetch', function (event) {
    // Only handle GET requests
    if (event.request.method !== 'GET') return;

    // Only handle same-origin requests
    if (!event.request.url.startsWith(self.location.origin)) return;

    event.respondWith(
        caches.match(event.request).then(function (cachedResponse) {
            if (cachedResponse) {
                // Return cache hit, but also update cache in background
                var fetchPromise = fetch(event.request).then(function (networkResponse) {
                    if (networkResponse && networkResponse.status === 200) {
                        var responseClone = networkResponse.clone();
                        caches.open(CACHE_NAME).then(function (cache) {
                            cache.put(event.request, responseClone);
                        });
                    }
                    return networkResponse;
                }).catch(function () {
                    // Network failed, that is fine - we have the cache
                });

                return cachedResponse;
            }

            // Not in cache, try network
            return fetch(event.request).then(function (networkResponse) {
                if (networkResponse && networkResponse.status === 200) {
                    var responseClone = networkResponse.clone();
                    caches.open(CACHE_NAME).then(function (cache) {
                        cache.put(event.request, responseClone);
                    });
                }
                return networkResponse;
            });
        })
    );
});
