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

    @Transactional(noRollbackFor = {BadCredentialsException.class, LockedException.class})
    public AuthResponse login(String email, String password, String ip, String ua) {
        User user = userRepository.findByEmailIgnoreCase(email)
                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

        if (user.isLocked()) {
            throw new LockedException("Account is temporarily locked. Please try again later.");
        }

        boolean passwordMatch = passwordEncoder.matches(password, user.getPasswordHash());

        // 🚀 PESSIMISTIC LOCK: Ensures failedAttempts are updated sequentially
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

    // 🚀 NEW: Simple Logout Logic
    @Transactional
    public void logout(String rawRefreshToken) {
        // We don't care if it's invalid/expired, we just want to try to find the user and nuke sessions.
        refreshTokenService.findByRawToken(rawRefreshToken)
                .ifPresent(token -> revocationService.revokeAll(token.getUserId()));

        log.info("LOGOUT SUCCESS");
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

    // 🚀 CRITICAL FIX: The "Outer" transaction must ALSO know not to rollback.
    // If you miss this, the delete happens, but this method rolls it back when it sees the exception.
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
}