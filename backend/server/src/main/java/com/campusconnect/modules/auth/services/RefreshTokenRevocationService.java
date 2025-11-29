package com.campusconnect.modules.auth.services;

import com.campusconnect.modules.auth.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenRevocationService {

    private final RefreshTokenRepository repo;

    // --- CRITICAL FIX: Removed Propagation.REQUIRES_NEW ---
    // We use default propagation (REQUIRED) so this method joins the
    // existing transaction. This allows it to delete the rows that
    // are currently locked by 'rotate' without waiting (Deadlock Fix).
    @Transactional
    public void revokeAll(UUID userId) {
        log.error("REVOCATION: deleting ALL refresh tokens for user {}", userId);
        repo.deleteAllByUserId(userId);
        log.error("REVOCATION COMMIT SUCCESS for {}", userId);
    }
}