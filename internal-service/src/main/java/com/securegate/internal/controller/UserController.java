package com.securegate.internal.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/users")
@Slf4j
public class UserController {

    /**
     * Get the current user's profile from the gateway-injected context.
     * This endpoint is accessible to all authenticated users.
     */
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser(Authentication auth) {
        log.debug("Profile requested for userId={}", auth.getName());
        return ResponseEntity.ok(Map.of(
                "userId", auth.getName(),
                "roles", auth.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList()
        ));
    }

    /**
     * Admin-only endpoint: list all users and their roles.
     */
    @GetMapping("/admin")
    public ResponseEntity<?> adminEndpoint(Authentication auth) {
        // Access controlled by @PreAuthorize in SecurityConfig
        log.info("Admin endpoint accessed by userId={}", auth.getName());
        return ResponseEntity.ok(Map.of(
                "message", "Admin access granted",
                "accessedBy", auth.getName(),
                "roles", auth.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList()
        ));
    }
}
