package com.campusconnect.userservice.user.dto;

import lombok.Builder;
import lombok.Data;

import java.time.OffsetDateTime;
import java.util.UUID;

@Data
@Builder
public class UserResponse {

    private UUID id;
    private String email;
    private String fullName;
    private String status;
    private OffsetDateTime createdAt;
    private OffsetDateTime updatedAt;
}
