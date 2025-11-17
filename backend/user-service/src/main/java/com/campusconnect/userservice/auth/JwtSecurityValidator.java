package com.campusconnect.userservice.auth;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtSecurityValidator {

    @Value("${security.jwt.secret:}")
    private String secret;

    @PostConstruct
    public void validate() {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException("JWT_SECRET must be set.");
        }
        if (secret.length() < 64) {
            throw new IllegalStateException("JWT secret must be ≥ 64 characters.");
        }
    }
}
