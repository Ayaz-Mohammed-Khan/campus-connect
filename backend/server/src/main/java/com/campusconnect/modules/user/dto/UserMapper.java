package com.campusconnect.modules.user.dto;

import com.campusconnect.modules.user.model.User;

public final class UserMapper {

    private UserMapper() {}

    public static UserResponse toResponse(User user) {
        if (user == null) return null;

        // 🚀 JAVA 25 UPDATE: Records use the constructor, not Builder
        return new UserResponse(
                user.getId(),
                user.getEmail(),
                user.getFullName(),
                user.getStatus(), // Pass the Enum directly (Type-Safe)
                user.getCreatedAt(),
                user.getUpdatedAt()
        );
    }
}