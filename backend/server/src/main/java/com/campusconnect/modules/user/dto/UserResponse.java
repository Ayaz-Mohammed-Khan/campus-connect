package com.campusconnect.modules.user.dto;

import com.campusconnect.modules.user.model.UserStatus;
import java.time.OffsetDateTime;
import java.util.UUID;

public record UserResponse(
        UUID id,
        String email,
        String fullName,
        UserStatus status,
        OffsetDateTime createdAt,
        OffsetDateTime updatedAt
) {}