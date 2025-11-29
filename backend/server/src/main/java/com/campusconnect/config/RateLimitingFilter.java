package com.campusconnect.config;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * API Rate Limiting Filter using Token Bucket Algorithm.
 * <p>
 * Protects critical endpoints (Auth, User Registration) from abuse and brute-force attacks.
 * Uses an in-memory `ConcurrentHashMap` to track buckets per IP address.
 */
@Slf4j
@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    private final Map<String, Bucket> cache = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    @PostConstruct
    public void init() {
        // 🛠️ MEMORY LEAK PROTECTION:
        // Since we store buckets in-memory, we must periodically clear inactive IPs.
        // In a production environment, this should be replaced by Redis (e.g., Redisson).
        scheduler.scheduleAtFixedRate(() -> {
            log.debug("Maintenance: Clearing Rate Limit Cache (Size: {})", cache.size());
            cache.clear();
        }, 1, 1, TimeUnit.HOURS);
    }

    @PreDestroy
    public void tearDown() {
        scheduler.shutdownNow();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();

        // Apply limits only to high-risk paths
        if (isRateLimitedPath(path)) {
            String ip = getClientIp(request);
            Bucket bucket = cache.computeIfAbsent(ip, this::createNewBucket);

            // Try to consume 1 token. If false, bucket is empty -> 429 Error.
            if (!bucket.tryConsume(1)) {
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.getWriter().write("Too many requests. Please try again later.");
                return; // Stop the filter chain here
            }
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Defines which paths require protection.
     * Currently targeting Authentication and Registration endpoints.
     */
    private boolean isRateLimitedPath(String path) {
        return path.startsWith("/auth/") || path.startsWith("/api/v1/users");
    }

    /**
     * Configures the Token Bucket rules.
     * <p>
     * <b>Rule:</b> 10 requests per minute per IP.
     * This is strict enough to stop brute-force but generous enough for normal human use.
     */
    private Bucket createNewBucket(String key) {
        Bandwidth limit = Bandwidth.classic(10, Refill.greedy(10, Duration.ofMinutes(1)));
        return Bucket.builder().addLimit(limit).build();
    }

    private String getClientIp(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return req.getRemoteAddr();
    }
}