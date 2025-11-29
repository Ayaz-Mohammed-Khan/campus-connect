package com.campusconnect.modules.auth.services;

import com.campusconnect.exception.TokenReuseException;
import com.campusconnect.modules.auth.dto.AuthResponse;
import com.campusconnect.modules.user.UserRepository;
import com.campusconnect.modules.user.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * Orchestrates high-level authentication flows including Login, Refresh, and Logout.
 * <p>
 * This service acts as a facade, coordinating between the {@link UserRepository},
 * {@link JwtService}, and {@link RefreshTokenService}. It enforces security policies
 * such as account lockouts and transactional consistency during token rotation.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserAuthService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenRevocationService revocationService;

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCKOUT_DURATION_MINUTES = 15;

    /**
     * Authenticates a user and issues a new pair of Access/Refresh tokens.
     * <p>
     * <b>Security Mechanisms:</b>
     * <ul>
     * <li><b>Pessimistic Locking:</b> Acquires a write lock on the user row to prevent race conditions during concurrent login attempts.</li>
     * <li><b>Lockout Policy:</b> Checks and enforces temporary account locking after {@code MAX_FAILED_ATTEMPTS}.</li>
     * </ul>
     *
     * @param email    The user's email address.
     * @param password The raw password.
     * @param ip       The client's IP address.
     * @param ua       The client's User-Agent string.
     * @return {@link AuthResponse} containing the JWT access token and raw refresh token.
     * @throws LockedException if the account is currently locked.
     * @throws BadCredentialsException if the password does not match.
     */
    @Transactional(noRollbackFor = {BadCredentialsException.class, LockedException.class})
    public AuthResponse login(String email, String password, String ip, String ua) {
        User user = userRepository.findByEmailIgnoreCase(email)
                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

        if (user.isLocked()) {
            throw new LockedException("Account is temporarily locked. Please try again later.");
        }

        boolean passwordMatch = passwordEncoder.matches(password, user.getPasswordHash());

        // PESSIMISTIC WRITE LOCK: Serializes concurrent login attempts for this user
        // to prevent race conditions on the 'failedAttempts' counter.
        User lockedUser = userRepository.findByIdAndLock(user.getId())
                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

        if (lockedUser.isLocked()) {
            throw new LockedException("Account is temporarily locked. Please try again later.");
        }

        if (!passwordMatch) {
            handleLoginFailure(lockedUser);
            throw new BadCredentialsException("Invalid credentials");
        }

        if (lockedUser.getFailedAttempts() > 0 || lockedUser.getLockoutEnd() != null) {
            lockedUser.setFailedAttempts(0);
            lockedUser.setLockoutEnd(null);
            userRepository.save(lockedUser);
        }

        String accessToken = jwtService.generateAccessToken(lockedUser.getId(), lockedUser.getEmail(), List.of("USER"));
        String refreshToken = refreshTokenService.createRefreshToken(lockedUser, ip, ua);

        log.info("LOGIN SUCCESS [User: {}] [IP: {}]", email, ip);
        return new AuthResponse(accessToken, refreshToken, 900L);
    }

    /**
     * Terminates a specific session by verifying and then revoking the refresh token.
     *
     * @param rawRefreshToken The refresh token to revoke.
     */
    @Transactional
    public void logout(String rawRefreshToken) {
        // We don't care if it's invalid/expired, we just want to try to find the user and nuke sessions.
        refreshTokenService.findByRawToken(rawRefreshToken)
                .ifPresent(token -> revocationService.revokeAll(token.getUserId()));

        log.info("LOGOUT SUCCESS");
    }

    /**
     * Rotates a refresh token to issue a new session.
     * <p>
     * <b>Critical Transactional Behavior:</b><br>
     * If a {@link TokenReuseException} occurs (replay attack), this method is configured to
     * <b>COMMIT</b> the transaction (via {@code noRollbackFor}) rather than roll back.
     * This ensures that the side-effect of the attack (revoking all user sessions) is
     * persisted to the database.
     *
     * @param rawRefreshToken The raw refresh token string provided by the client.
     * @param ip              The client's IP address.
     * @param ua              The client's User-Agent string.
     * @return {@link AuthResponse} containing the new JWT and rotated refresh token.
     * @throws SecurityException if the token is missing or malformed.
     * @throws CredentialsExpiredException if the token has naturally expired.
     * @throws TokenReuseException if the token has already been used.
     */
    // ⚠️ CRITICAL: Must COMMIT transaction to persist the "reuse detected" flag/logs
    // even if we throw an exception to the client. Do not remove noRollbackFor.
    @Transactional(noRollbackFor = {
            TokenReuseException.class,
            BadCredentialsException.class,
            CredentialsExpiredException.class
    })
    public AuthResponse refresh(String rawRefreshToken, String ip, String ua) {
        var token = refreshTokenService.findByRawToken(rawRefreshToken)
                .orElseThrow(() -> new SecurityException("Invalid refresh token"));

        if (token.getExpiresAt().isBefore(OffsetDateTime.now())) {
            revocationService.revokeAll(token.getUserId());
            throw new CredentialsExpiredException("Refresh token expired");
        }

        // This call throws TokenReuseException, which bubbles up here.
        // Because of the annotation above, we COMMIT the transaction (persisting the delete)
        // before throwing the error to the controller.
        String newRefreshRaw = refreshTokenService.rotate(token, ip, ua);

        User user = token.getUser();
        String newAccess = jwtService.generateAccessToken(user.getId(), user.getEmail(), List.of("USER"));

        log.info("REFRESH SUCCESS [User: {}]", user.getEmail());
        return new AuthResponse(newAccess, newRefreshRaw, 900L);
    }

    private void handleLoginFailure(User user) {
        int newFailures = user.getFailedAttempts() + 1;
        user.setFailedAttempts(newFailures);

        if (newFailures >= MAX_FAILED_ATTEMPTS) {
            user.setLockoutEnd(OffsetDateTime.now().plusMinutes(LOCKOUT_DURATION_MINUTES));
            log.warn("🚨 ACCOUNT LOCKOUT [Email: {}]", user.getEmail());
        }
        userRepository.save(user);
    }
}