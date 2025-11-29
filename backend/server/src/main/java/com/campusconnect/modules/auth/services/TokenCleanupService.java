package com.campusconnect.modules.auth.services;

import com.campusconnect.modules.auth.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenCleanupService {

    private final RefreshTokenRepository repo;

    // Run every hour (3600000 ms)
    @Scheduled(fixedRate = 3600000)
    @Transactional
    public void cleanupTokens() {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);

        // 1. Delete Expired Tokens (They are useless)
        int expiredDeleted = repo.deleteByExpiresAtBefore(now);

        // 2. Delete "Old Used" Tokens (Tokens used > 24 hours ago)
        // We keep them for 24h to allow reuse detection, then we discard to save space.
        OffsetDateTime usageCutoff = now.minusHours(24);
        int usedDeleted = repo.deleteByLastUsedAtBefore(usageCutoff);

        if (expiredDeleted > 0 || usedDeleted > 0) {
            log.info("🧹 TOKEN CLEANUP: Deleted {} expired and {} old used tokens.", expiredDeleted, usedDeleted);
        }
    }
}