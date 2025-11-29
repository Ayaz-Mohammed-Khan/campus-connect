package com.campusconnect.modules.auth;

import com.campusconnect.modules.auth.model.RefreshToken;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends ListCrudRepository<RefreshToken, UUID> {

    @Query("""
        SELECT rt FROM RefreshToken rt
        JOIN FETCH rt.user u
        WHERE rt.tokenPrefix = :tokenPrefix
    """)
    Optional<RefreshToken> findByTokenPrefixWithUser(@Param("tokenPrefix") String tokenPrefix);

    Optional<RefreshToken> findByTokenPrefix(String tokenPrefix);

    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.lastUsedAt = :now WHERE rt.id = :id AND rt.lastUsedAt IS NULL")
    int updateLastUsedAt(@Param("id") UUID id, @Param("now") OffsetDateTime now);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("DELETE FROM RefreshToken rt WHERE rt.user.id = :userId")
    void deleteAllByUserId(@Param("userId") UUID userId);

    // 🚀 CLEANUP: Delete tokens that have naturally expired
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiresAt < :now")
    int deleteByExpiresAtBefore(@Param("now") OffsetDateTime now);

    // 🚀 CLEANUP: Delete tokens used long ago (Prune history to save space)
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.lastUsedAt < :cutoff")
    int deleteByLastUsedAtBefore(@Param("cutoff") OffsetDateTime cutoff);
}