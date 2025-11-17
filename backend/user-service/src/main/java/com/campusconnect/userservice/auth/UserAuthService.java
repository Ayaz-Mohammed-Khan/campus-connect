package com.campusconnect.userservice.auth;

import com.campusconnect.userservice.auth.dto.AuthResponse;
import com.campusconnect.userservice.user.User;
import com.campusconnect.userservice.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserAuthService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    public AuthResponse login(String email, String password, String ip, String ua) {
        User user = userRepository.findByEmailIgnoreCase(email)
                .orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));

        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new IllegalArgumentException("Invalid credentials");
        }

        String access = jwtService.generateAccessToken(user.getId(), user.getEmail(), List.of("USER"));
        String refresh = refreshTokenService.createRefreshToken(user.getId(), ip, ua);

        return AuthResponse.builder()
                .accessToken(access)
                .refreshToken(refresh)
                .expiresIn(900L)
                .build();
    }

    @Transactional
    public AuthResponse refresh(String rawRefreshToken, String ip, String ua) {
        var token = refreshTokenService.findByRawToken(rawRefreshToken)
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));

        if (token.getExpiresAt().isBefore(java.time.OffsetDateTime.now())) {
            refreshTokenService.revokeAllTokensForUser(token.getUserId());
            throw new IllegalArgumentException("Refresh token expired");
        }

        String newRaw = refreshTokenService.rotate(token, ip, ua);

        User user = userRepository.findById(token.getUserId())
                .orElseThrow(() -> new IllegalStateException("User not found"));

        String access = jwtService.generateAccessToken(user.getId(), user.getEmail(), List.of("USER"));

        return AuthResponse.builder()
                .accessToken(access)
                .refreshToken(newRaw)
                .expiresIn(900L)
                .build();
    }
}
