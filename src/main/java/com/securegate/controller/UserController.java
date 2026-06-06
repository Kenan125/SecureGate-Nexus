package com.securegate.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/users")
@Slf4j
public class UserController {

    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser(Authentication auth) {
        return ResponseEntity.ok(Map.of(
                "userId", auth.getName(),
                "roles", auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList()));
    }

    @GetMapping("/admin")
    public ResponseEntity<?> adminEndpoint(Authentication auth) {
        return ResponseEntity.ok(Map.of(
                "message", "Admin access granted",
                "accessedBy", auth.getName()));
    }
}
