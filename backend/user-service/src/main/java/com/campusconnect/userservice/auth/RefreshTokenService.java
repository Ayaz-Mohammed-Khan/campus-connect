package com.campusconnect.userservice.auth;

import com.campusconnect.userservice.auth.model.RefreshToken;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository repo;
    private final BCryptPasswordEncoder passwordEncoder;

    @org.springframework.beans.factory.annotation.Value("${security.jwt.refresh-token-ttl-days:30}")
    private long refreshTokenValidityDays;

    private static final SecureRandom RNG = new SecureRandom();
    private static final int PREFIX_LENGTH = 12;

    private String generateRawToken() {
        byte[] a = new byte[48];
        byte[] b = new byte[32];
        RNG.nextBytes(a);
        RNG.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(a)
                + "." +
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
    public String createRefreshToken(UUID userId, String ip, String ua) {
        String raw = generateRawToken();
        String prefix = computePrefix(raw);
        String hash = passwordEncoder.encode(raw);

        RefreshToken t = RefreshToken.builder()
                .userId(userId)
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
        return repo.findByTokenPrefix(prefix)
                .filter(t -> passwordEncoder.matches(raw, t.getTokenHash()));
    }

    @Transactional
    public void revokeAllTokensForUser(UUID userId) {
        repo.deleteByUserId(userId);
    }

    @Transactional
    public String rotate(RefreshToken existing, String ip, String ua) {
        if (existing.getLastUsedAt() != null) {
            revokeAllTokensForUser(existing.getUserId());
            throw new SecurityException("Refresh token reuse detected");
        }

        existing.setLastUsedAt(OffsetDateTime.now(ZoneOffset.UTC));
        repo.save(existing);

        String newRaw = createRefreshToken(existing.getUserId(), ip, ua);

        repo.delete(existing);
        return newRaw;
    }
}
