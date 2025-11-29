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

/**
 * Service handling User lifecycle operations.
 * <p>
 * This service implements the business rules for user registration, including
 * normalization of email addresses and handling of race conditions during
 * concurrent account creation.
 */
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    /**
     * Registers a new user in the system.
     * <p>
     * <b>Concurrency Handling:</b>
     * This method employs a "Check-Then-Act" strategy with a fallback.
     * <ol>
     * <li><b>Pre-emptive Check:</b> Queries the DB to fail fast if the email exists.</li>
     * <li><b>Database Constraint:</b> Relies on the unique index `idx_users_email` to catch
     * race conditions where two requests pass the check simultaneously.</li>
     * </ol>
     *
     * @param request The registration payload containing email, password, and name.
     * @return The created user metadata (excluding sensitive credentials).
     * @throws DuplicateResourceException if the email is already registered.
     */
    @Transactional
    public UserResponse createUser(CreateUserRequest request) {
        // Normalize email to ensure uniqueness checks are case-insensitive/consistent
        String email = request.email().trim().toLowerCase(Locale.ROOT);

        // 🛡️ Pre-emptive check: Decouples us from raw DB error strings for better UX
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
            // Fallback for race conditions (rare but possible under high load)
            throw new DuplicateResourceException("User", email, "Email already in use");
        }
    }

    /**
     * Retrieves the currently authenticated user based on the SecurityContext.
     * <p>
     * Supports extraction of the User ID from the JWT {@code sub} claim.
     *
     * @return The authenticated user's profile.
     * @throws SecurityException if no authentication is found in the context.
     * @throws EntityNotFoundException if the token is valid but the user was deleted.
     */
    public UserResponse getCurrentUserResponse() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            throw new SecurityException("Not authenticated");
        }

        // 🚀 JAVA 25: Pattern Matching for Switch (Preview Feature)
        // Extracts the subject safely based on the Principal type
        String userId = switch (auth.getPrincipal()) {
            case Jwt jwt -> jwt.getSubject();
            default -> throw new IllegalStateException("Unexpected principal type: " + auth.getPrincipal().getClass());
        };

        User user = userRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        return UserMapper.toResponse(user);
    }
}