package com.campusconnect.userservice.auth;

import com.campusconnect.userservice.auth.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    Optional<RefreshToken> findByTokenPrefix(String tokenPrefix);
    void deleteByUserId(UUID userId);
}
