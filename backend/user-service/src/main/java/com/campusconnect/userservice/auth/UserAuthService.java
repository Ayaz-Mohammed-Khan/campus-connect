package com.campusconnect.userservice.auth;

import com.campusconnect.userservice.auth.dto.AuthResponse;
import com.campusconnect.userservice.user.User;
import com.campusconnect.userservice.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.apache.logging.log4j.Logger;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.List;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserAuthService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder; // ONLY for login password
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenRevocationService revocationService;



    /** LOGIN */
    public AuthResponse login(String email, String password, String ip, String ua) {

        User user = userRepository.findByEmailIgnoreCase(email)
                .orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));

        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new IllegalArgumentException("Invalid credentials");
        }

        String accessToken = jwtService.generateAccessToken(
                user.getId(),
                user.getEmail(),
                List.of("USER")
        );

        String refreshToken = refreshTokenService.createRefreshToken(
                user.getId(),
                ip,
                ua
        );


        log.error("DEBUG RT1 = [{}]", refreshToken);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(900L)
                .build();
    }

    /** REFRESH FLOW */
    @Transactional
    public AuthResponse refresh(String rawRefreshToken, String ip, String ua) {

        var token = refreshTokenService.findByRawToken(rawRefreshToken)
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));

        // Expiration check
        if (token.getExpiresAt().isBefore(OffsetDateTime.now())) {
            revocationService.revokeAll(token.getUserId());
            throw new IllegalArgumentException("Refresh token expired");
        }

        // Rotate token (may throw reuse detection)
        String newRefreshRaw = refreshTokenService.rotate(token, ip, ua);

        User user = userRepository.findById(token.getUserId())
                .orElseThrow(() -> new IllegalStateException("User not found"));

        String newAccess = jwtService.generateAccessToken(
                user.getId(),
                user.getEmail(),
                List.of("USER")
        );

        return AuthResponse.builder()
                .accessToken(newAccess)
                .refreshToken(newRefreshRaw)
                .expiresIn(900L)
                .build();
    }
}
