package com.campusconnect.userservice.exception;

import com.campusconnect.userservice.web.ApiError;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import org.postgresql.util.PSQLException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.time.OffsetDateTime;
import java.util.*;
import java.util.stream.Collectors;

@ControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    private final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private static final Set<String> SENSITIVE_FIELDS = Set.of(
            "password", "currentpassword", "newpassword",
            "confirmpassword", "token", "refreshtoken", "secret"
    );

    private String resolveTraceId(HttpServletRequest request) {
        String header = request.getHeader("X-Trace-Id");
        return (header != null && !header.isBlank()) ? header : UUID.randomUUID().toString();
    }

    private ApiError build(String error, String message, String traceId, Map<String, Object> details) {
        return ApiError.builder()
                .error(error)
                .message(message)
                .timestamp(OffsetDateTime.now())
                .traceId(traceId)
                .details(details)
                .build();
    }

    // 400 - Validation errors from @Valid
    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex,
            HttpHeaders headers,
            HttpStatusCode status,
            WebRequest request) {

        HttpServletRequest servletReq = (HttpServletRequest) request.resolveReference(WebRequest.REFERENCE_REQUEST);
        String traceId = resolveTraceId(servletReq);

        List<Map<String, String>> fieldErrors = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(fe -> {
                    Map<String, String> map = new LinkedHashMap<>();
                    map.put("field", fe.getField());
                    map.put("message", fe.getDefaultMessage());

                    // Redact sensitive values
                    if (!SENSITIVE_FIELDS.contains(fe.getField().toLowerCase(Locale.ROOT))) {
                        map.put("rejectedValue",
                                Objects.toString(fe.getRejectedValue(), ""));
                    } else {
                        map.put("rejectedValue", "[REDACTED]");
                    }
                    return map;
                })
                .collect(Collectors.toList());

        Map<String, Object> details = Map.of("fieldErrors", fieldErrors);

        ApiError body = build("VALIDATION_ERROR", "Request validation failed", traceId, details);
        log.warn("Validation failed (traceId={}): {}", traceId, ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    // 400 - Constraint violations
    @ExceptionHandler(ConstraintViolationException.class)
    protected ResponseEntity<ApiError> handleConstraintViolation(
            ConstraintViolationException ex,
            HttpServletRequest request) {

        String traceId = resolveTraceId(request);

        Map<String, Object> details = Map.of("violations",
                ex.getConstraintViolations().stream()
                        .map(cv -> Map.of("path", cv.getPropertyPath().toString(),
                                "message", cv.getMessage()))
                        .toList()
        );

        ApiError body = build("CONSTRAINT_VIOLATION", "Constraint violation", traceId, details);
        log.warn("Constraint violation (traceId={}): {}", traceId, ex.getMessage());
        return ResponseEntity.badRequest().body(body);
    }

    // 409 - Duplicate resource
    @ExceptionHandler(DuplicateResourceException.class)
    protected ResponseEntity<ApiError> handleDuplicate(
            DuplicateResourceException ex, HttpServletRequest request) {

        String traceId = resolveTraceId(request);
        Map<String, Object> details = Map.of("resource", ex.getResource(), "key", ex.getKey());

        ApiError body = build("DUPLICATE_RESOURCE", ex.getMessage(), traceId, details);

        log.warn("Duplicate resource (traceId={}): {}", traceId, ex.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(body);
    }

    // 404
    @ExceptionHandler(EntityNotFoundException.class)
    protected ResponseEntity<ApiError> handleNotFound(EntityNotFoundException ex, HttpServletRequest request) {
        String traceId = resolveTraceId(request);
        ApiError body = build("NOT_FOUND", ex.getMessage(), traceId, null);
        log.info("Not found (traceId={}): {}", traceId, ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(body);
    }

    // 409 - DB constraint violation
    @ExceptionHandler(DataIntegrityViolationException.class)
    protected ResponseEntity<ApiError> handleDataIntegrity(DataIntegrityViolationException ex, HttpServletRequest request) {
        String traceId = resolveTraceId(request);

        ApiError body = build(
                "DATA_INTEGRITY_VIOLATION",
                "Database constraint violated",
                traceId,
                Map.of("dbMessage", "[REDACTED]")
        );

        log.warn("Data integrity violation (traceId={})", traceId);
        return ResponseEntity.status(HttpStatus.CONFLICT).body(body);
    }

    // 400 - malformed JSON
    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(
            HttpMessageNotReadableException ex,
            HttpHeaders headers,
            HttpStatusCode status,
            WebRequest request) {

        HttpServletRequest servletReq = (HttpServletRequest) request.resolveReference(WebRequest.REFERENCE_REQUEST);
        String traceId = resolveTraceId(servletReq);

        ApiError body = build("MALFORMED_REQUEST", "Malformed JSON request",
                traceId, Map.of("cause", "[REDACTED]"));

        log.warn("Malformed request (traceId={}): {}", traceId, ex.getMessage());
        return ResponseEntity.badRequest().body(body);
    }

    // 401
    @ExceptionHandler(AuthenticationException.class)
    protected ResponseEntity<ApiError> handleAuth(AuthenticationException ex, HttpServletRequest request) {
        String traceId = resolveTraceId(request);

        ApiError body = build("UNAUTHENTICATED", "Authentication failed", traceId, null);

        log.warn("Authentication failed (traceId={})", traceId);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
    }

    // 403
    @ExceptionHandler(org.springframework.security.access.AccessDeniedException.class)
    protected ResponseEntity<ApiError> handleAccessDenied(
            org.springframework.security.access.AccessDeniedException ex, HttpServletRequest request) {

        String traceId = resolveTraceId(request);

        ApiError body = build("FORBIDDEN", "Access denied", traceId, null);

        log.warn("Access denied (traceId={})", traceId);
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(body);
    }

    // 503
    @ExceptionHandler(PSQLException.class)
    protected ResponseEntity<ApiError> handlePostgres(PSQLException ex, HttpServletRequest request) {
        String traceId = resolveTraceId(request);

        ApiError body = build(
                "DATABASE_ERROR",
                "Database unavailable",
                traceId,
                Map.of("pgMessage", "[REDACTED]")
        );

        log.error("Database error (traceId={})", traceId);
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(body);
    }

    // 500 fallback
    @ExceptionHandler(Exception.class)
    protected ResponseEntity<ApiError> handleAll(Exception ex, HttpServletRequest request) {
        String traceId = resolveTraceId(request);

        ApiError body = build("INTERNAL_ERROR", "An unexpected error occurred",
                traceId, null);

        log.error("Unhandled exception (traceId={}) {}", traceId, ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }

    @ExceptionHandler(SecurityException.class)
    protected ResponseEntity<ApiError> handleSecurity(SecurityException ex, HttpServletRequest req) {
        String traceId = resolveTraceId(req);
        ApiError body = ApiError.builder()
                .code("INVALID_TOKEN")
                .message("Invalid or reused refresh token")
                .traceId(traceId)
                .build();
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
    }

}
