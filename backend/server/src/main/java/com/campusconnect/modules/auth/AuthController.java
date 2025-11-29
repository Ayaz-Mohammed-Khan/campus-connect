package com.campusconnect.modules.auth;

import com.campusconnect.modules.auth.dto.AuthResponse;
import com.campusconnect.modules.auth.dto.LoginRequest;
import com.campusconnect.modules.auth.dto.RefreshRequest;
import com.campusconnect.modules.auth.services.UserAuthService;
import com.campusconnect.modules.user.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserAuthService authService;
    private final UserService userService;

    @PostMapping("/login")
    @ResponseStatus(HttpStatus.OK)
    public AuthResponse login(@Valid @RequestBody LoginRequest request, HttpServletRequest req) {
        return authService.login(
                request.email(), // Record Accessor
                request.password(),
                getClientIp(req),
                sanitizeUserAgent(req.getHeader("User-Agent"))
        );
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT) // 204 No Content is standard for logout
    public void logout(@Valid @RequestBody RefreshRequest request) {
        // We reuse the existing revocation service logic
        authService.logout(request.refreshToken());
    }

    @PostMapping("/refresh")
    @ResponseStatus(HttpStatus.OK)
    public AuthResponse refresh(@Valid @RequestBody RefreshRequest request, HttpServletRequest req) {
        return authService.refresh(
                request.refreshToken(),
                getClientIp(req),
                sanitizeUserAgent(req.getHeader("User-Agent"))
        );
    }

    @GetMapping("/me")
    public Object me() {
        return userService.getCurrentUserResponse();
    }

    private String sanitizeUserAgent(String ua) {
        if (ua == null) return "Unknown";
        ua = ua.trim();
        return ua.length() > 512 ? ua.substring(0, 512) : ua;
    }

    private String getClientIp(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return req.getRemoteAddr() != null ? req.getRemoteAddr() : "Unknown";
    }
}