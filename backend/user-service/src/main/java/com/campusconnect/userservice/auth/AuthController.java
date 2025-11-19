package com.campusconnect.userservice.auth;

import com.campusconnect.userservice.auth.dto.AuthResponse;
import com.campusconnect.userservice.auth.dto.LoginRequest;
import com.campusconnect.userservice.auth.dto.RefreshRequest;
import com.campusconnect.userservice.user.UserService;
import jakarta.servlet.http.HttpServletRequest;
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
    public AuthResponse login(@RequestBody LoginRequest request, HttpServletRequest req) {
        String ip = getClientIp(req);
        String ua = sanitizeUserAgent(req.getHeader("User-Agent"));
        return authService.login(request.getEmail(), request.getPassword(), ip, ua);
    }

    @PostMapping("/refresh")
    @ResponseStatus(HttpStatus.OK)
    public AuthResponse refresh(@RequestBody RefreshRequest request, HttpServletRequest req) {
        String ip = getClientIp(req);
        String ua = sanitizeUserAgent(req.getHeader("User-Agent"));
        return authService.refresh(request.getRefreshToken(), ip, ua);
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
