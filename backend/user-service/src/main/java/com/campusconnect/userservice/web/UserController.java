package com.campusconnect.userservice.web;

import com.campusconnect.userservice.user.UserService;
import com.campusconnect.userservice.user.dto.CreateUserRequest;
import com.campusconnect.userservice.user.dto.UserResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public UserResponse createUser(@Valid @RequestBody CreateUserRequest request) {
        return userService.createUser(request);
    }

    @GetMapping("/health")
    public String health() {
        return "OK";
    }

    @GetMapping("/me")
    public UserResponse currentUser() {
        return userService.getCurrentUserResponse();
    }



}
