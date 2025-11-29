package com.campusconnect.modules.user.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * The root entity representing a system user.
 * <p>
 * <b>Database Schema:</b>
 * <ul>
 * <li><b>Indexes:</b> `idx_users_status` for filtering active users.</li>
 * <li><b>Locking:</b> Supports optimistic locking via versioning (implied) or pessimistic locking via repository.</li>
 * </ul>
 */
@Entity
@Table(name = "users", indexes = {
        @Index(name = "idx_users_status", columnList = "status")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @Column(nullable = false, unique = true, length = 255)
    private String email;

    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    @Column(name = "full_name", nullable = false, length = 255)
    private String fullName;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private UserStatus status;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    // 🚀 PHASE 1 SECURITY: Lockout Fields
    // Used by UserAuthService to track brute-force attempts
    @Column(name = "failed_attempts", nullable = false)
    @Builder.Default
    private int failedAttempts = 0;

    @Column(name = "lockout_end")
    private OffsetDateTime lockoutEnd;

    @PrePersist
    public void onCreate() {
        createdAt = OffsetDateTime.now();
        updatedAt = createdAt;
        if (status == null) status = UserStatus.ACTIVE;
        if (failedAttempts != 0) failedAttempts = 0; // ensure default
    }

    @PreUpdate
    public void onUpdate() {
        updatedAt = OffsetDateTime.now();
    }

    /**
     * Checks if the user is currently locked out due to excessive failed login attempts.
     * @return true if the lockout period is still active.
     */
    public boolean isLocked() {
        return lockoutEnd != null && lockoutEnd.isAfter(OffsetDateTime.now());
    }
}