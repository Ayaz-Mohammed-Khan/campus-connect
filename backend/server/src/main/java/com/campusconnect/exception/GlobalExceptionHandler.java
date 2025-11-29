package com.campusconnect.exception;

import jakarta.persistence.EntityNotFoundException;
import org.slf4j.MDC;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.*;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.net.URI;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    // Helper: Add traceId and timestamp to every error response
    private ProblemDetail enrich(ProblemDetail problem, WebRequest request) {
        problem.setProperty("timestamp", Instant.now());
        String traceId = request.getHeader("X-Trace-Id");
        if (traceId != null) {
            problem.setProperty("traceId", traceId);
        }

        if (problem.getDetail() != null) {
            MDC.put("errorDetail", problem.getDetail());
        }

        return problem;
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex, HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        ProblemDetail problem = ex.getBody();
        Map<String, String> fieldErrors = new HashMap<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            fieldErrors.put(error.getField(), error.getDefaultMessage());
        }
        problem.setProperty("fieldErrors", fieldErrors);
        problem.setDetail("Validation failed for one or more fields.");
        return ResponseEntity.status(status).body(enrich(problem, request));
    }

    // 🚀 NEW: Handle Account Lockout
    @ExceptionHandler(LockedException.class)
    public ResponseEntity<ProblemDetail> handleLocked(LockedException ex, WebRequest request) {
        // Using 429 Too Many Requests as it semantically fits "try again later"
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.TOO_MANY_REQUESTS, ex.getMessage());
        problem.setTitle("Account Locked");
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(enrich(problem, request));
    }

    // 🚀 NEW: Handle Bad Credentials explicitly (401)
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ProblemDetail> handleBadCredentials(BadCredentialsException ex, WebRequest request) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "Invalid email or password");
        problem.setTitle("Authentication Failed");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(enrich(problem, request));
    }

    @ExceptionHandler(DuplicateResourceException.class)
    public ResponseEntity<ProblemDetail> handleDuplicate(DuplicateResourceException ex, WebRequest request) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, ex.getMessage());
        problem.setTitle("Duplicate Resource");
        problem.setType(URI.create("urn:problem-type:duplicate-resource"));
        problem.setProperty("resource", ex.getResource());
        problem.setProperty("key", ex.getKey());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(enrich(problem, request));
    }

    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleNotFound(EntityNotFoundException ex, WebRequest request) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
        problem.setTitle("Resource Not Found");
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(enrich(problem, request));
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ProblemDetail> handleAuth(AuthenticationException ex, WebRequest request) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "Authentication failed");
        problem.setTitle("Unauthorized");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(enrich(problem, request));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ProblemDetail> handleAccessDenied(AccessDeniedException ex, WebRequest request) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, "Access denied");
        problem.setTitle("Forbidden");
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(enrich(problem, request));
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ProblemDetail> handleDataIntegrity(DataIntegrityViolationException ex, WebRequest request) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, "Database constraint violation");
        problem.setTitle("Data Integrity Violation");
        return ResponseEntity.status(HttpStatus.CONFLICT).body(enrich(problem, request));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleAll(Exception ex, WebRequest request) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred");
        problem.setTitle("Internal Server Error");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(enrich(problem, request));
    }

    // 🚀 NEW: Explicit handler for our "No-Rollback" Exception
    @ExceptionHandler(TokenReuseException.class)
    public ResponseEntity<ProblemDetail> handleTokenReuse(TokenReuseException ex, WebRequest request) {
        // Return 401 Unauthorized
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, ex.getMessage());
        problem.setTitle("Security Error");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(enrich(problem, request));
    }

    // 🚀 NEW: Specific Handler for Expired Tokens
    @ExceptionHandler(CredentialsExpiredException.class)
    public ResponseEntity<ProblemDetail> handleCredentialsExpired(CredentialsExpiredException ex, WebRequest request) {
        // We trust the message here because we threw it explicitly in UserAuthService
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, ex.getMessage());
        problem.setTitle("Token Expired");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(enrich(problem, request));
    }

    // 🚀 NEW: Handler for Generic Security Exceptions (e.g. "Invalid refresh token")
    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<ProblemDetail> handleSecurityException(SecurityException ex, WebRequest request) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, ex.getMessage());
        problem.setTitle("Security Error");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(enrich(problem, request));
    }
}