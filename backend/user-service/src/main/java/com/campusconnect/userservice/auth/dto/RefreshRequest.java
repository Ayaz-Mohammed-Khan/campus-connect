package com.campusconnect.userservice.auth.dto;

import lombok.Data;

@Data
public class RefreshRequest {
    private String refreshToken;
}
