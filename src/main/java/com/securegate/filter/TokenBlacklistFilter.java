package com.securegate.filter;

import com.nimbusds.jwt.SignedJWT;
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
import java.text.ParseException;

/**
 * Token Blacklist Filter — runs SECOND in the security chain.
 *
 * Implements INSTANT TOKEN REVOCATION by checking Redis for blacklisted
 * JWT IDs (jti). If the token has been revoked (logout), the request
 * is blocked before it reaches the controller layer.
 */
@Component
@Order(-90)
@RequiredArgsConstructor
@Slf4j
public class TokenBlacklistFilter extends OncePerRequestFilter {

    private static final String ERROR_BODY =
            "{\"error\":\"Security Alert: This token has been revoked. Please login again.\"}";

    private final TokenBlacklistService blacklistService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain chain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        String path = request.getRequestURI();

        // Allow public auth endpoints through without a token
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            if (isPublicPath(path)) {
                chain.doFilter(request, response);
                return;
            }
            sendError(response, HttpServletResponse.SC_UNAUTHORIZED,
                    "{\"error\":\"Missing Authorization header\"}");
            return;
        }

        try {
            String token = authHeader.substring(7);
            String jti = extractJti(token);

            if (jti == null || jti.isEmpty()) {
                log.warn("BLACKLIST FILTER: Token missing jti claim, IP={}",
                        request.getRemoteAddr());
                sendError(response, HttpServletResponse.SC_UNAUTHORIZED,
                        "{\"error\":\"Invalid token: missing JWT ID (jti)\"}");
                return;
            }

            if (blacklistService.isBlacklisted(jti)) {
                log.warn("BLACKLIST FILTER: Revoked token detected — jti={}, IP={}",
                        jti, request.getRemoteAddr());
                sendError(response, HttpServletResponse.SC_UNAUTHORIZED, ERROR_BODY);
                return;
            }

            // Token is not blacklisted — proceed to next filter
            chain.doFilter(request, response);

        } catch (ParseException e) {
            log.warn("BLACKLIST FILTER: Malformed JWT, IP={}",
                    request.getRemoteAddr());
            sendError(response, HttpServletResponse.SC_UNAUTHORIZED,
                    "{\"error\":\"Invalid JWT format\"}");
        }
    }

    private String extractJti(String token) throws ParseException {
        SignedJWT jwt = SignedJWT.parse(token);
        return jwt.getJWTClaimsSet().getJWTID();
    }

    private boolean isPublicPath(String path) {
        return path.startsWith("/api/v1/auth/register")
                || path.startsWith("/api/v1/auth/login");
    }

    private void sendError(HttpServletResponse response, int status, String body)
            throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(body);
    }
}
