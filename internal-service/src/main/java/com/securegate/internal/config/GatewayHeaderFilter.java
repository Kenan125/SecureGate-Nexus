package com.securegate.internal.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Extracts user context from gateway-forwarded headers.
 *
 * The API Gateway injects X-User-Id and X-User-Scopes after JWT verification.
 * Internal services trust the gateway — they do NOT handle raw JWTs directly.
 *
 * This means internal services are NOT directly accessible:
 * requests without X-User-Id (i.e., bypassing the gateway) will be rejected.
 */
@Slf4j
public class GatewayHeaderFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain filterChain)
            throws ServletException, IOException {

        String userId = request.getHeader("X-User-Id");
        String scopes = request.getHeader("X-User-Scopes");

        if (userId == null || userId.isEmpty()) {
            // No X-User-Id = request did NOT come through gateway
            // This prevents direct access to internal services
            log.warn("Request without X-User-Id header — possible direct access attempt");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write(
                    "{\"error\":\"Access denied: must go through API Gateway\"}");
            return;
        }

        // Build Spring Security authentication from gateway headers
        List<SimpleGrantedAuthority> authorities = (scopes != null && !scopes.isEmpty())
                ? Arrays.stream(scopes.split("\\s+"))
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList())
                : List.of(new SimpleGrantedAuthority("ROLE_USER"));

        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(userId, null, authorities);

        SecurityContextHolder.getContext().setAuthentication(auth);

        log.debug("User context set from gateway: userId={}, authorities={}", userId, authorities);
        filterChain.doFilter(request, response);
    }
}
