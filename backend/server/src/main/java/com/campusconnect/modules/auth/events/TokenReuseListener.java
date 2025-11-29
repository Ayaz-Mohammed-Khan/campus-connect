package com.campusconnect.modules.auth.events;

import com.campusconnect.modules.auth.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
@Slf4j
public class TokenReuseListener {

    private final RefreshTokenRepository repo;

    @Async // <--- RUNS IN A SEPARATE THREAD (No Deadlock)
    @EventListener
    @Transactional // Opens its own fresh transaction
    public void handleReuseEvent(TokenReuseEvent event) {
        log.warn("ASYNC SECURITY: Token reuse detected for User {}. Revoking all sessions...", event.userId());

        try {
            repo.deleteAllByUserId(event.userId());
            log.info("ASYNC SECURITY: Successfully revoked all tokens for User {}", event.userId());
        } catch (Exception e) {
            log.error("ASYNC SECURITY: Failed to revoke tokens for user {}", event.userId(), e);
        }
    }
}