package com.campusconnect.exception;


import lombok.Builder;
import lombok.Data;
import java.time.OffsetDateTime;
import java.util.Map;

@Data
@Builder
public class ApiError {
    private String code;
    private String error;
    private String message;
    private OffsetDateTime timestamp;
    private String traceId;
    private Map<String, Object> details;
}
