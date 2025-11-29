package com.campusconnect.modules.auth.services;

import com.campusconnect.exception.TokenReuseException;
import com.campusconnect.modules.auth.RefreshTokenRepository;
import com.campusconnect.modules.auth.events.TokenReuseEvent;
import com.campusconnect.modules.auth.model.RefreshToken;
import com.campusconnect.modules.auth.utils.HashUtils;
import com.campusconnect.modules.user.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository repo;
    private final BCryptPasswordEncoder passwordEncoder;
    private final ApplicationEventPublisher eventPublisher;
    private final RefreshTokenRevocationService revocationService;

    @Value("${jwt.refresh-token-ttl-days:30}")
    private long refreshTokenValidityDays;

    private static final SecureRandom RNG = new SecureRandom();
    private static final int PREFIX_LENGTH = 12;



    private String generateRawToken() {
        byte[] a = new byte[48];
        byte[] b = new byte[32];
        RNG.nextBytes(a);
        RNG.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(a) + "." +
                Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private String computePrefix(String raw) {
        String clean = raw.replaceAll("[^A-Za-z0-9]", "");
        if (clean.length() < PREFIX_LENGTH) {
            return String.format("%1$-" + PREFIX_LENGTH + "s", clean).replace(' ', '0');
        }
        return clean.substring(0, PREFIX_LENGTH);
    }

    @Transactional
    public String createRefreshToken(User user, String ip, String ua) {
        String raw = generateRawToken();
        String prefix = computePrefix(raw);
        String hash = HashUtils.sha256Hex(raw);

        RefreshToken t = RefreshToken.builder()
                .user(user)
                .tokenPrefix(prefix)
                .tokenHash(hash)
                .expiresAt(OffsetDateTime.now(ZoneOffset.UTC).plusDays(refreshTokenValidityDays))
                .userAgent(ua)
                .ipAddress(ip)
                .build();

        repo.save(t);
        return raw;
    }

    public Optional<RefreshToken> findByRawToken(String raw) {
        String prefix = computePrefix(raw);
        return repo.findByTokenPrefixWithUser(prefix)
                .filter(t -> {
                    String stored = t.getTokenHash();
                    if (stored == null) return false;
                    if (stored.startsWith("$2a$") || stored.startsWith("$2b$")) {
                        return passwordEncoder.matches(raw, stored);
                    }
                    return HashUtils.sha256Hex(raw).equalsIgnoreCase(stored);
                });
    }

    // 🚀 CRITICAL FIX: Added noRollbackFor here too!
    // This prevents this inner service from marking the transaction as "Rollback-Only"
    // when the exception is thrown.
    @Transactional(noRollbackFor = TokenReuseException.class)
    public String rotate(RefreshToken staleToken, String ip, String ua) {
        // 1. Atomic DB Check
        int rowsUpdated = repo.updateLastUsedAt(staleToken.getId(), OffsetDateTime.now(ZoneOffset.UTC));

        if (rowsUpdated == 0) {
            log.warn("🚨 REUSE DETECTED [User: {}]. Executing Synchronous Revocation.", staleToken.getUserId());

            // 2. Revoke (This runs in the current transaction)
            revocationService.revokeAll(staleToken.getUserId());

            eventPublisher.publishEvent(new TokenReuseEvent(staleToken.getUserId()));

            // 3. Throw Special Exception (Now ignored by Transaction Manager)
            throw new TokenReuseException("Invalid or reused refresh token");
        }

        return createRefreshToken(staleToken.getUser(), ip, ua);
    }
}