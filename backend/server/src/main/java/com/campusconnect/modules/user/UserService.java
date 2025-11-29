package com.campusconnect.modules.user;

import com.campusconnect.exception.DuplicateResourceException;
import com.campusconnect.modules.user.dto.CreateUserRequest;
import com.campusconnect.modules.user.dto.UserMapper;
import com.campusconnect.modules.user.dto.UserResponse;
import com.campusconnect.modules.user.model.User;
import com.campusconnect.modules.user.model.UserStatus;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    @Transactional
    public UserResponse createUser(CreateUserRequest request) {
        String email = request.email().trim().toLowerCase(Locale.ROOT);

        // 🛡️ Pre-emptive check: Decouples us from DB error strings
        if (userRepository.existsByEmailIgnoreCase(email)) {
            throw new DuplicateResourceException("User", email, "Email already in use");
        }

        User user = User.builder()
                .email(email)
                .passwordHash(passwordEncoder.encode(request.password()))
                .fullName(request.fullName())
                .status(UserStatus.ACTIVE)
                .build();

        try {
            User saved = userRepository.save(user);
            return UserMapper.toResponse(saved);
        } catch (DataIntegrityViolationException e) {
            // Fallback for race conditions (rare)
            throw new DuplicateResourceException("User", email, "Email already in use");
        }
    }

    public UserResponse getCurrentUserResponse() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            throw new SecurityException("Not authenticated");
        }

        // 🚀 JAVA 25: Pattern Matching for Switch
        String userId = switch (auth.getPrincipal()) {
            case Jwt jwt -> jwt.getSubject();
            default -> throw new IllegalStateException("Unexpected principal type: " + auth.getPrincipal().getClass());
        };

        User user = userRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        return UserMapper.toResponse(user);
    }
}