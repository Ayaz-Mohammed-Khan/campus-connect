package com.campusconnect.userservice.auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenRevocationService {

    private final RefreshTokenRepository repo;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void revokeAll(UUID userId) {
        log.error("REVOCATION: deleting ALL refresh tokens for user {}", userId);
        repo.deleteAllByUserId(userId);
        log.error("REVOCATION COMMIT SUCCESS for {}", userId);
    }
}
