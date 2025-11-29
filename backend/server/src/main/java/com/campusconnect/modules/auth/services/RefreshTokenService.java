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

/**
 * Manages the lifecycle of stateful Refresh Tokens.
 * <p>
 * Implements "Refresh Token Rotation" with "Family Reuse Detection".
 * Instead of storing raw tokens, this service stores a SHA-256 hash of the token.
 * The token format is: {@code [12-char-prefix].[32-byte-random-string]}.
 * The prefix allows for efficient database lookups, while the hash ensures
 * the raw token cannot be leaked via database dumps.
 */
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

    /**
     * Generates a secure random token, hashes it, and persists it.
     */
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
                    // Backward compatibility for old BCrypt tokens (development only)
                    if (stored.startsWith("$2a$") || stored.startsWith("$2b$")) {
                        return passwordEncoder.matches(raw, stored);
                    }
                    return HashUtils.sha256Hex(raw).equalsIgnoreCase(stored);
                });
    }

    /**
     * Atomically rotates a refresh token.
     * <p>
     * <b>Replay Attack Detection:</b>
     * Tries to update the {@code lastUsedAt} timestamp of the provided token.
     * If {@code rowsUpdated == 0}, it implies the token was already used (Atomic Check).
     * In this scenario, the method triggers a {@link TokenReuseEvent} and revokes
     * <b>ALL</b> sessions for the user.
     *
     * @param staleToken The database entity of the token being exchanged.
     * @param ip         The IP address of the requester.
     * @param ua         The User-Agent of the requester.
     * @return A new raw refresh token string.
     * @throws TokenReuseException if the DB update fails, indicating the token was already used.
     */
    @Transactional(noRollbackFor = TokenReuseException.class)
    public String rotate(RefreshToken staleToken, String ip, String ua) {
        // Atomic Swap: Only succeeds if lastUsedAt was null.
        // Returns 0 if another thread/request used it first (Replay Attack).
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