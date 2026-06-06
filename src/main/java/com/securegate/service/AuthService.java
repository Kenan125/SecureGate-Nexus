package com.securegate.service;

import com.nimbusds.jwt.JWTClaimsSet;
import com.securegate.model.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Authentication service handling user registration, login, and logout.
 *
 * Uses an in-memory ConcurrentHashMap for user storage (production should
 * use a database). Passwords are hashed with BCrypt.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final JwtService jwtService;
    private final TokenBlacklistService blacklistService;
    private final PasswordEncoder passwordEncoder;

    @Value("${jwt.access-token-expiry:900}")
    private long accessTokenExpirySeconds;

    /** In-memory user store. Replace with a database in production. */
    private final Map<String, User> users = new ConcurrentHashMap<>();

    /**
     * Register a new user.
     *
     * @param req registration request with username, password, and optional role
     * @return the created User (without password hash exposure)
     * @throws IllegalArgumentException if username already exists
     */
    public User register(RegisterRequest req) {
        if (users.containsKey(req.getUsername())) {
            throw new IllegalArgumentException("Username already exists: " + req.getUsername());
        }

        String role = (req.getRole() != null && !req.getRole().isBlank())
                ? req.getRole()
                : "ROLE_USER";

        User user = User.builder()
                .id(UUID.randomUUID().toString())
                .username(req.getUsername())
                .passwordHash(passwordEncoder.encode(req.getPassword()))
                .role(role)
                .build();

        users.put(user.getUsername(), user);
        log.info("User registered: username={}, role={}", user.getUsername(), role);
        return user;
    }

    /**
     * Authenticate a user and return a signed JWT access token.
     *
     * @param req login request with username and password
     * @return TokenResponse containing the JWT
     * @throws IllegalArgumentException if credentials are invalid
     */
    public TokenResponse login(LoginRequest req) {
        User user = users.get(req.getUsername());
        if (user == null) {
            log.warn("Login failed: unknown username={}", req.getUsername());
            throw new IllegalArgumentException("Invalid username or password");
        }

        if (!passwordEncoder.matches(req.getPassword(), user.getPasswordHash())) {
            log.warn("Login failed: bad password for username={}", req.getUsername());
            throw new IllegalArgumentException("Invalid username or password");
        }

        String token = jwtService.createAccessToken(user.getId(), user.getRole());
        log.info("Login successful: username={}, userId={}", req.getUsername(), user.getId());

        return TokenResponse.builder()
                .accessToken(token)
                .tokenType("Bearer")
                .expiresIn(accessTokenExpirySeconds)
                .build();
    }

    /**
     * Revoke a token by adding its jti to the Redis blacklist with
     * a TTL matching the token's remaining lifetime.
     *
     * @param token the serialized JWT to revoke
     */
    public void logout(String token) {
        JWTClaimsSet claims = jwtService.parseClaims(token);
        String jti = claims.getJWTID();
        long ttl = jwtService.getRemainingTtlSeconds(claims.getExpirationTime());
        blacklistService.blacklist(jti, ttl);
        log.info("Logout: token revoked, jti={}, ttl={}s", jti, ttl);
    }

    /**
     * Parse a token and return its claims (without signature verification).
     *
     * @param token the serialized JWT
     * @return parsed claims set
     */
    public JWTClaimsSet getTokenClaims(String token) {
        return jwtService.parseClaims(token);
    }
}
