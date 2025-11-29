package com.campusconnect.modules.auth.services;

import com.campusconnect.modules.auth.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * specialized service for invalidating security sessions.
 * <p>
 * This service is intentionally isolated to handle the "Nuclear Option":
 * revoking ALL tokens for a user when a security breach (like a Replay Attack) is detected.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenRevocationService {

    private final RefreshTokenRepository repo;

    /**
     * Revokes all active sessions for a specific user.
     * <p>
     * <b>Transactional Note:</b>
     * Uses default propagation (REQUIRED). This allows it to participate in the
     * existing transaction of the caller (e.g., `RefreshTokenService.rotate`).
     * This is critical for atomic "Rotate OR Die" logic where the revocation
     * must happen within the same commit boundary as the detection logic.
     *
     * @param userId The unique identifier of the user whose sessions will be terminated.
     */
    @Transactional
    public void revokeAll(UUID userId) {
        log.error("REVOCATION: deleting ALL refresh tokens for user {}", userId);

        // Bulk delete operation (efficient for users with many devices)
        repo.deleteAllByUserId(userId);

        log.error("REVOCATION COMMIT SUCCESS for {}", userId);
    }
}