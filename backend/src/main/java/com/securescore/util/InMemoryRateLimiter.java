package com.securescore.util;

import com.securescore.exception.RateLimitException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Simple in-memory sliding-window rate limiter.
 *
 * NOTE: This is suitable for a single-instance deployment (hackathon MVP).
 * Production distributed rate limiting would require Redis or similar.
 * Keyed by IP address extracted from the request.
 */
@Component
public class InMemoryRateLimiter {

    @Value("${rate-limiter.max-requests-per-window:10}")
    private int maxRequests;

    @Value("${rate-limiter.window-seconds:60}")
    private int windowSeconds;

    private record WindowEntry(AtomicInteger count, long windowStart) {}

    private final ConcurrentHashMap<String, WindowEntry> windows = new ConcurrentHashMap<>();

    /**
     * Check and consume a rate limit token for the given key (e.g., client IP).
     * Throws RateLimitException if the limit is exceeded.
     */
    public void checkLimit(String key) {
        long now = System.currentTimeMillis();
        long windowMs = windowSeconds * 1000L;

        windows.compute(key, (k, existing) -> {
            if (existing == null || (now - existing.windowStart()) > windowMs) {
                // New window
                return new WindowEntry(new AtomicInteger(1), now);
            }
            return existing;
        });

        WindowEntry entry = windows.get(key);
        int count = entry.count().incrementAndGet();

        if (count > maxRequests) {
            throw new RateLimitException("Rate limit exceeded for key: " + key);
        }
    }

    /** Periodically called to clean up stale entries. Not strictly required for MVP. */
    public void cleanup() {
        long now = System.currentTimeMillis();
        long windowMs = windowSeconds * 1000L;
        windows.entrySet().removeIf(e -> (now - e.getValue().windowStart()) > windowMs * 2);
    }
}
