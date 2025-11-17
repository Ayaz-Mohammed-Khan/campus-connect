package com.campusconnect.userservice.user;

import com.campusconnect.userservice.exception.DuplicateResourceException;
import com.campusconnect.userservice.user.dto.CreateUserRequest;
import com.campusconnect.userservice.user.dto.UserMapper;
import com.campusconnect.userservice.user.dto.UserResponse;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;


import java.util.Locale;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    /**
     * Create a new user. Normalizes email, checks duplicates, stores password hash.
     */
    @Transactional
    public UserResponse createUser(CreateUserRequest request) {
        if (request == null) throw new IllegalArgumentException("Request body is required");

        // Normalize and validate
        String rawEmail = request.getEmail();
        if (rawEmail == null || rawEmail.isBlank()) {
            throw new IllegalArgumentException("Email is required");
        }
        String email = rawEmail.trim().toLowerCase(Locale.ROOT);

        if (userRepository.existsByEmailIgnoreCase(email)) {
            throw new DuplicateResourceException("User", email, "Email already in use");
        }

        User user = User.builder()
                .email(email)
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .fullName(request.getFullName())
                .status("ACTIVE")
                .build();

        User saved = userRepository.save(user);
        return UserMapper.toResponse(saved);
    }

    public UserResponse getCurrentUserResponse() {
        var auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !auth.isAuthenticated()) {
            throw new org.springframework.security.core.AuthenticationException("Not authenticated") {};
        }

        Object principal = auth.getPrincipal();
        String userId = null;

        if (principal instanceof Jwt jwt) {
            userId = jwt.getSubject();
        }

        var user = userRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        return UserMapper.toResponse(user);
    }


    // additional service methods (find, update, delete) go here
}
