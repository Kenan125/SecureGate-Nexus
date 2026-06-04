package com.securegate.auth.controller;

import com.securegate.auth.model.*;
import com.securegate.auth.service.AuthService;
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

    /**
     * POST /auth/register
     * Register a new user account.
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        try {
            User user = authService.register(request);
            return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                    "message", "User registered successfully",
                    "userId", user.getId(),
                    "username", user.getUsername()
            ));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * POST /auth/login
     * Authenticate user, return JWT with minimal payload.
     * INNOVATION #3: JWT contains ONLY user_id + scope (roles). No passwords.
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        try {
            TokenResponse token = authService.login(request);
            log.info("Login successful: username={}", request.getUsername());
            return ResponseEntity.ok(token);
        } catch (IllegalArgumentException e) {
            log.warn("Login failed: username={}, reason={}", request.getUsername(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid username or password"));
        }
    }

    /**
     * POST /auth/logout
     * INNOVATION #1: Revoke JWT instantly via Redis blacklist.
     * Client sends the still-valid JWT. Server adds its jti to Redis blacklist.
     * Gateway will reject this token on subsequent requests.
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing or invalid Authorization header"));
        }

        String token = authHeader.substring(7);
        try {
            authService.logout(token);
            return ResponseEntity.ok(Map.of("message", "Logged out successfully. Token revoked."));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * GET /auth/validate
     * Endpoint for gateway to validate token + check blacklist in one call.
     * Returns user info if token is valid and not revoked.
     */
    @GetMapping("/validate")
    public ResponseEntity<?> validate(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Missing Authorization header"));
        }

        String token = authHeader.substring(7);
        try {
            if (authService.isTokenRevoked(token)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Token has been revoked"));
            }

            var claims = authService.getTokenClaims(token);
            return ResponseEntity.ok(Map.of(
                    "sub", claims.getSubject(),
                    "scope", claims.getClaim("scope"),
                    "jti", claims.getJWTID(),
                    "valid", true
            ));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid token: " + e.getMessage()));
        }
    }
}
