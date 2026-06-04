package com.securegate.service;

import com.nimbusds.jwt.JWTClaimsSet;
import com.securegate.model.*;
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
    private final TokenBlacklistService blacklistService;
    private final PasswordEncoder passwordEncoder;
    private final Map<String, User> users = new ConcurrentHashMap<>();

    public User register(RegisterRequest req) {
        if (users.containsKey(req.getUsername()))
            throw new IllegalArgumentException("Username already exists");
        User user = User.builder()
                .id(UUID.randomUUID().toString())
                .username(req.getUsername())
                .passwordHash(passwordEncoder.encode(req.getPassword()))
                .role(req.getRole() != null ? req.getRole() : "ROLE_USER")
                .build();
        users.put(user.getUsername(), user);
        log.info("User registered: {}", user.getUsername());
        return user;
    }

    public TokenResponse login(LoginRequest req) {
        User user = users.get(req.getUsername());
        if (user == null || !passwordEncoder.matches(req.getPassword(), user.getPasswordHash()))
            throw new IllegalArgumentException("Invalid username or password");

        String token = jwtService.createAccessToken(user.getId(), user.getRole());
        return TokenResponse.builder().accessToken(token).tokenType("Bearer").expiresIn(900).build();
    }

    public void logout(String token) {
        JWTClaimsSet claims = jwtService.parseClaims(token);
        long ttl = jwtService.getRemainingTtlSeconds(claims.getExpirationTime());
        blacklistService.blacklist(claims.getJWTID(), ttl);
        log.info("User logged out: jti={}", claims.getJWTID());
    }

    public JWTClaimsSet getTokenClaims(String token) {
        return jwtService.parseClaims(token);
    }
}
