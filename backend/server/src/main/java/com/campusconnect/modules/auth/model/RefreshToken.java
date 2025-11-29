package com.campusconnect.modules.auth.model;

import com.campusconnect.modules.user.model.User;
import jakarta.persistence.*;
import lombok.*;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

/**
 * Represents a long-lived session token (Refresh Token).
 * <p>
 * <b>Security Architecture:</b>
 * <ul>
 * <li><b>Token Hashing:</b> We do NOT store the raw token. We store a SHA-256 hash.
 * If the database is leaked, attackers cannot use these tokens to impersonate users.</li>
 * <li><b>Prefix Optimization:</b> We store the first 12 chars (`token_prefix`)
 * indexed for O(1) lookups, avoiding expensive full-table scans on hashes.</li>
 * </ul>
 */
@Entity
@Table(name = "refresh_tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id")
    private UUID id;

    // OPTIMIZATION: Mapped with Lazy Fetch to prevent loading User data
    // during simple token validation checks.
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    /**
     * The first 12 characters of the raw token.
     * Used for fast database lookups (Index: `idx_refresh_tokens_prefix`).
     */
    @Column(name = "token_prefix", nullable = false, length = 12)
    private String tokenPrefix;

    /**
     * The SHA-256 hash of the full token.
     * Used to verify authenticity after the prefix match is found.
     */
    @Column(name = "token_hash", nullable = false)
    private String tokenHash;

    @Column(name = "expires_at", nullable = false)
    private OffsetDateTime expiresAt;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    /**
     * Timestamp of when this token was exchanged.
     * If NULL, the token is valid.
     * If SET, the token has been used and is kept only for Replay Detection.
     */
    @Column(name = "last_used_at")
    private OffsetDateTime lastUsedAt;

    // Audit fields for security forensics
    @Column(name = "user_agent")
    private String userAgent;

    @Column(name = "ip_address")
    private String ipAddress;

    @PrePersist
    public void prePersist() {
        if (id == null) {
            id = UUID.randomUUID();
        }
        if (createdAt == null) {
            createdAt = OffsetDateTime.now(ZoneOffset.UTC);
        }
    }

    /**
     * Helper for accessing User ID without triggering a full Lazy Load of the User entity.
     * (Useful for logging or simple ID checks).
     */
    public UUID getUserId() {
        return user != null ? user.getId() : null;
    }
}