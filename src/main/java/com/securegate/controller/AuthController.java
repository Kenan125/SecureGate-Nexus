package com.securegate.controller;

import com.securegate.model.*;
import com.securegate.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest req) {
        try {
            User user = authService.register(req);
            return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                    "message", "User registered successfully",
                    "userId", user.getId(), "username", user.getUsername()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest req) {
        try {
            return ResponseEntity.ok(authService.login(req));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid username or password"));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String auth) {
        if (auth == null || !auth.startsWith("Bearer "))
            return ResponseEntity.badRequest().body(Map.of("error", "Missing Authorization header"));
        authService.logout(auth.substring(7));
        return ResponseEntity.ok(Map.of("message", "Logged out successfully. Token revoked."));
    }
}
