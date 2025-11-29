package com.campusconnect.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class TokenReuseException extends RuntimeException {
    public TokenReuseException(String message) {
        super(message);
    }
}