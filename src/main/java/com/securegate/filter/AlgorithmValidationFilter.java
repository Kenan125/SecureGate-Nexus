package com.securegate.filter;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.text.ParseException;
import java.util.Set;

/**
 * PROACTIVE Algorithm Validation Filter — runs FIRST in the security chain.
 *
 * Decodes the JWT header and inspects the "alg" parameter BEFORE any
 * cryptographic signature verification to:
 *   1. Block Algorithm Confusion attacks (HS256/HS384/HS512 when RS256 expected)
 *   2. Block the "none" algorithm attack
 *   3. Block tokens with missing algorithm claims
 *
 * This saves CPU by rejecting malicious tokens early and prevents logical bypasses.
 */
@Component
@Order(-100)
@Slf4j
public class AlgorithmValidationFilter extends OncePerRequestFilter {

    private static final Set<String> SYMMETRIC_ALGORITHMS = Set.of(
            "HS256", "HS384", "HS512",
            "hs256", "hs384", "hs512");
    private static final Set<String> NONE_ALGORITHMS = Set.of(
            "none", "None", "NONE");
    private static final JWSAlgorithm EXPECTED_ALGORITHM = JWSAlgorithm.RS256;

    private static final String ERROR_BODY =
            "{\"error\":\"Security Violation: Invalid or manipulated algorithm detected\"}";

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

            // Parse with Nimbus to reliably extract the header algorithm
            SignedJWT jwt = SignedJWT.parse(token);
            Algorithm alg = jwt.getHeader().getAlgorithm();

            if (alg == null) {
                log.warn("PROACTIVE BLOCK: Missing 'alg' in JWT header from IP={}",
                        request.getRemoteAddr());
                sendError(response, HttpServletResponse.SC_UNAUTHORIZED, ERROR_BODY);
                return;
            }

            String algName = alg.getName();

            if (NONE_ALGORITHMS.contains(algName)) {
                log.warn("PROACTIVE BLOCK: Algorithm Confusion — 'none' attack from IP={}",
                        request.getRemoteAddr());
                sendError(response, HttpServletResponse.SC_UNAUTHORIZED, ERROR_BODY);
                return;
            }

            if (SYMMETRIC_ALGORITHMS.contains(algName)) {
                log.warn("PROACTIVE BLOCK: Algorithm Confusion — symmetric {} when RS256 expected, IP={}",
                        algName, request.getRemoteAddr());
                sendError(response, HttpServletResponse.SC_UNAUTHORIZED, ERROR_BODY);
                return;
            }

            if (!EXPECTED_ALGORITHM.equals(alg)) {
                log.warn("PROACTIVE BLOCK: Unexpected algorithm '{}' when RS256 expected, IP={}",
                        algName, request.getRemoteAddr());
                sendError(response, HttpServletResponse.SC_UNAUTHORIZED, ERROR_BODY);
                return;
            }

            // Algorithm is valid RS256 — pass to next filter
            chain.doFilter(request, response);

        } catch (ParseException e) {
            log.warn("PROACTIVE BLOCK: Malformed JWT — cannot parse, IP={}",
                    request.getRemoteAddr());
            sendError(response, HttpServletResponse.SC_UNAUTHORIZED, ERROR_BODY);
        }
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
