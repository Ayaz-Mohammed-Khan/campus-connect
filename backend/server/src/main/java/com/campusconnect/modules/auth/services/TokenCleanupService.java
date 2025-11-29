package com.campusconnect.modules.auth.services;

import com.campusconnect.modules.auth.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * Background maintenance service for Token Hygiene.
 * <p>
 * <b>Why this exists:</b>
 * High-traffic auth systems generate massive amounts of token data.
 * Without aggressive cleanup, the `refresh_tokens` table will grow indefinitely,
 * slowing down login/refresh speeds.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenCleanupService {

    private final RefreshTokenRepository repo;

    /**
     * Periodically prunes database of invalid tokens.
     * <p>
     * <b>Strategy:</b>
     * <ol>
     * <li><b>Expired Tokens:</b> Deleted immediately. They are cryptographically useless.</li>
     * <li><b>Used Tokens:</b> Retained for 24 hours after use. This retention window
     * is critical for <b>Replay Attack Detection</b>. If we deleted them immediately,
     * we wouldn't know if a token presented to us was "stolen and used" or just "fake".</li>
     * </ol>
     *
     * Runs every hour (3600000 ms).
     */
    @Scheduled(fixedRate = 3600000)
    @Transactional
    public void cleanupTokens() {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);

        // 1. Delete Naturally Expired Tokens (They are useless)
        int expiredDeleted = repo.deleteByExpiresAtBefore(now);

        // 2. Delete "Old Used" Tokens (Tokens used > 24 hours ago)
        // CRITICAL: We keep them for 24h to allow reuse detection logic to work.
        // After 24h, the risk of reuse is outweighed by storage costs.
        OffsetDateTime usageCutoff = now.minusHours(24);
        int usedDeleted = repo.deleteByLastUsedAtBefore(usageCutoff);

        if (expiredDeleted > 0 || usedDeleted > 0) {
            log.info("🧹 TOKEN CLEANUP: Deleted {} expired and {} old used tokens.", expiredDeleted, usedDeleted);
        }
    }
}