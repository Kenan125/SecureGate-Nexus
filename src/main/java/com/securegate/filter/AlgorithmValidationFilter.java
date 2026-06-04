package com.securegate.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;

/**
 * INNOVATION #2: Algorithm Manipulation Filter.
 * Runs FIRST. Decodes JWT header, checks "alg" claim BEFORE signature verification.
 * Blocks: alg=none, HS256/384/512, missing alg. Only RS256 allowed.
 */
@Component
@Order(-100)
@Slf4j
public class AlgorithmValidationFilter extends OncePerRequestFilter {

    private static final Set<String> BLOCKED = Set.of("none", "None", "NONE");
    private static final String ALLOWED = "RS256";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain chain) throws ServletException, IOException {
        String auth = request.getHeader("Authorization");
        String path = request.getRequestURI();

        // Skip public endpoints
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
            String alg = extractAlg(token);

            if (alg == null || alg.isEmpty()) {
                log.warn("JWT missing alg header from {}", request.getRemoteAddr());
                sendError(response, 401, "Security violation: JWT header missing 'alg' claim");
                return;
            }
            if (BLOCKED.contains(alg)) {
                log.warn("ALG=NONE ATTACK from {}", request.getRemoteAddr());
                sendError(response, 401, "Security violation: 'none' algorithm detected");
                return;
            }
            if (!ALLOWED.equals(alg)) {
                log.warn("ALG CONFUSION: alg={} from {}", alg, request.getRemoteAddr());
                sendError(response, 401, "Security violation: Algorithm '" + alg + "' not allowed");
                return;
            }
            chain.doFilter(request, response);
        } catch (Exception e) {
            sendError(response, 401, "Invalid JWT format");
        }
    }

    private String extractAlg(String token) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) return null;
        String header = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        int start = header.indexOf("\"alg\"");
        if (start == -1) return null;
        int colon = header.indexOf(":", start);
        int q1 = -1, q2 = -1;
        for (int i = colon + 1; i < header.length(); i++) {
            if (header.charAt(i) == '"') {
                if (q1 == -1) q1 = i + 1;
                else { q2 = i; break; }
            }
        }
        return q2 > q1 ? header.substring(q1, q2) : null;
    }

    private void sendError(HttpServletResponse response, int status, String msg) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"" + msg + "\"}");
    }
}
