package com.campusconnect.modules.auth.events;

import java.util.UUID;

// Simple data carrier. Records allow immutable data transfer.
public record TokenReuseEvent(UUID userId) {
}