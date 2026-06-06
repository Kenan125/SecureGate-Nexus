package com.securegate.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

/**
 * Secure data endpoint — only accessible with a valid, non-revoked JWT
 * that has passed through the entire proactive filter chain:
 *   1. AlgorithmValidationFilter
 *   2. TokenBlacklistFilter
 *   3. JwtAuthFilter
 */
@RestController
@RequestMapping("/api/v1/secure")
@Slf4j
public class SecureDataController {

    @GetMapping("/data")
    public ResponseEntity<Map<String, Object>> getSecureData(Authentication authentication) {
        log.info("Secure data accessed by user={}", authentication.getName());

        return ResponseEntity.ok(Map.of(
                "message", "You have accessed secure data successfully!",
                "authenticatedUser", authentication.getName(),
                "authorities", authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList(),
                "timestamp", Instant.now().toString(),
                "data", Map.of(
                        "secretCode", "SGX-2026-SECURE",
                        "clearance", "LEVEL-4",
                        "vaultStatus", "SEALED"
                )
        ));
    }
}
