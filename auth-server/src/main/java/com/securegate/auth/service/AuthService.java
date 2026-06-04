package com.securegate.auth.service;

import com.securegate.auth.model.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final JwtService jwtService;
    private final TokenBlacklistService tokenBlacklistService;
    private final PasswordEncoder passwordEncoder;

    // In-memory user store. Replace with database in production.
    private final Map<String, User> userStore = new ConcurrentHashMap<>();

    /**
     * Register a new user. Password is BCrypt hashed before storage.
     */
    public User register(RegisterRequest request) {
        if (userStore.containsKey(request.getUsername())) {
            throw new IllegalArgumentException("Username already exists: " + request.getUsername());
        }

        User user = User.builder()
                .id(UUID.randomUUID().toString())
                .username(request.getUsername())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole() != null ? request.getRole() : "ROLE_USER")
                .build();

        userStore.put(user.getUsername(), user);
        log.info("User registered: username={}, id={}", user.getUsername(), user.getId());
        return user;
    }

    /**
     * Authenticate user with username/password.
     * Returns JWT token pair on success.
     *
     * JWT payload contains ONLY: sub (userId), scope (roles), iat, exp, jti.
     * INNOVATION #3: No passwords, emails, or PII in token body.
     */
    public TokenResponse login(LoginRequest request) {
        User user = userStore.get(request.getUsername());
        if (user == null) {
            throw new IllegalArgumentException("Invalid username or password");
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new IllegalArgumentException("Invalid username or password");
        }

        try {
            // INNOVATION #3: Only user_id + role in JWT. No passwords or PII.
            String accessToken = jwtService.createAccessToken(user.getId(), user.getRole());

            return TokenResponse.builder()
                    .accessToken(accessToken)
                    .tokenType("Bearer")
                    .expiresIn(900) // 15 minutes
                    .build();
        } catch (Exception e) {
            log.error("Failed to create JWT for user {}", user.getId(), e);
            throw new RuntimeException("Token generation failed", e);
        }
    }

    /**
     * Logout: Extract jti from JWT and add to Redis blacklist.
     * INNOVATION #1: Instant token revocation — token becomes invalid immediately,
     * even though its JWT signature is still mathematically valid.
     */
    public void logout(String token) {
        try {
            var claims = jwtService.parseClaims(token);
            String jti = claims.getJWTID();
            long remainingTtl = jwtService.getRemainingTtlSeconds(claims.getExpirationTime());

            tokenBlacklistService.blacklist(jti, remainingTtl);
            log.info("User logged out: jti={}, blacklist ttl={}s", jti, remainingTtl);
        } catch (Exception e) {
            log.error("Logout failed: {}", e.getMessage());
            throw new RuntimeException("Logout failed: " + e.getMessage(), e);
        }
    }

    /**
     * Check if a token is revoked via Redis blacklist.
     */
    public boolean isTokenRevoked(String token) {
        try {
            var claims = jwtService.parseClaims(token);
            return tokenBlacklistService.isBlacklisted(claims.getJWTID());
        } catch (Exception e) {
            return true; // invalid token = treat as revoked
        }
    }

    public User findUserByUsername(String username) {
        return userStore.get(username);
    }

    /**
     * Get parsed claims from a JWT token string.
     */
    public com.nimbusds.jwt.JWTClaimsSet getTokenClaims(String token) {
        return jwtService.parseClaims(token);
    }
}
