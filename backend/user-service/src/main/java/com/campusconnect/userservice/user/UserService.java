package com.campusconnect.userservice.user;

import com.campusconnect.userservice.exception.DuplicateResourceException;
import com.campusconnect.userservice.user.dto.CreateUserRequest;
import com.campusconnect.userservice.user.dto.UserMapper;
import com.campusconnect.userservice.user.dto.UserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;

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

    // additional service methods (find, update, delete) go here
}
