package com.securegate.filter;

import com.securegate.service.TokenBlacklistService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * INNOVATION #1: Instant Token Revocation.
 * Runs SECOND. Extracts jti from JWT, checks in-memory blacklist.
 */
@Component
@Order(-90)
@RequiredArgsConstructor
@Slf4j
public class TokenBlacklistFilter extends OncePerRequestFilter {

    private final TokenBlacklistService blacklistService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain chain) throws ServletException, IOException {
        String auth = request.getHeader("Authorization");
        String path = request.getRequestURI();

        if (auth == null || !auth.startsWith("Bearer ")) {
            if (path.startsWith("/auth/register") || path.startsWith("/auth/login")) {
                chain.doFilter(request, response);
                return;
            }
            sendError(response, 401, "Missing Authorization header");
            return;
        }

        try {
            String token = auth.substring(7);
            String jti = extractJti(token);
            if (jti == null) {
                sendError(response, 401, "Invalid token: missing jti");
                return;
            }

            if (blacklistService.isBlacklisted(jti)) {
                log.warn("REVOKED TOKEN: jti={}", jti);
                sendError(response, 401, "Token has been revoked. Please login again.");
                return;
            }
            chain.doFilter(request, response);
        } catch (Exception e) {
            sendError(response, 401, "Invalid token format");
        }
    }

    private String extractJti(String token) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) return null;
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        int start = payload.indexOf("\"jti\"");
        if (start == -1) return null;
        int colon = payload.indexOf(":", start);
        int q1 = -1, q2 = -1;
        for (int i = colon + 1; i < payload.length(); i++) {
            if (payload.charAt(i) == '"') {
                if (q1 == -1) q1 = i + 1;
                else { q2 = i; break; }
            }
        }
        return q2 > q1 ? payload.substring(q1, q2) : null;
    }

    private void sendError(HttpServletResponse response, int status, String msg) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"" + msg + "\"}");
    }
}
