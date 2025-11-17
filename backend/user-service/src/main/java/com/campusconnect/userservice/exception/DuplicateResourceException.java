package com.campusconnect.userservice.exception;

public class DuplicateResourceException extends RuntimeException {
    private final String resource;
    private final String key;

    public DuplicateResourceException(String resource, String key, String message) {
        super(message);
        this.resource = resource;
        this.key = key;
    }

    public DuplicateResourceException(String resource, String key) {
        super(resource + " already exists: " + key);
        this.resource = resource;
        this.key = key;
    }

    public String getResource() {
        return resource;
    }

    public String getKey() {
        return key;
    }
}
