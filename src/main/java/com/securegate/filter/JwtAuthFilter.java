package com.securegate.filter;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.securegate.config.RSAKeyConfig;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * JWT Authentication Filter — runs THIRD in the security chain.
 *
 * Performs cryptographic signature verification using the RSA Public Key,
 * validates expiration, and populates the Spring Security Context with
 * the authenticated user's identity and authorities.
 *
 * STRICT PAYLOAD RULE: Only sub, scope, jti, iat, exp are extracted.
 * No PII, emails, or passwords are forwarded.
 */
@Component
@Order(-80)
@RequiredArgsConstructor
@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter {

    private final RSAKeyConfig rsaKeyConfig;

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

            // Parse and verify with RSA public key
            SignedJWT signedJwt = SignedJWT.parse(token);
            JWSVerifier verifier = new RSASSAVerifier(rsaKeyConfig.getPublicKey());

            if (!signedJwt.verify(verifier)) {
                log.warn("JWT AUTH FILTER: Signature verification FAILED, IP={}",
                        request.getRemoteAddr());
                sendError(response, HttpServletResponse.SC_UNAUTHORIZED,
                        "{\"error\":\"Invalid token signature\"}");
                return;
            }

            JWTClaimsSet claims = signedJwt.getJWTClaimsSet();

            // Verify expiration
            Date expiration = claims.getExpirationTime();
            if (expiration != null && expiration.before(new Date())) {
                log.debug("JWT AUTH FILTER: Token expired, exp={}", expiration);
                sendError(response, HttpServletResponse.SC_UNAUTHORIZED,
                        "{\"error\":\"Token has expired. Please login again.\"}");
                return;
            }

            // Extract STRICT payload fields (sub, scope only — no PII)
            String userId = claims.getSubject();
            String scope = claims.getStringClaim("scope");

            if (userId == null || userId.isEmpty()) {
                sendError(response, HttpServletResponse.SC_UNAUTHORIZED,
                        "{\"error\":\"Invalid token: missing subject\"}");
                return;
            }

            List<SimpleGrantedAuthority> authorities = (scope != null && !scope.isEmpty())
                    ? Arrays.stream(scope.split("\\s+"))
                            .map(SimpleGrantedAuthority::new)
                            .toList()
                    : List.of();

            // Populate Spring Security Context
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(userId, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            log.debug("JWT AUTH FILTER: Authenticated user={}, scope={}, jti={}",
                    userId, scope, claims.getJWTID());

            chain.doFilter(request, response);

        } catch (ParseException e) {
            log.warn("JWT AUTH FILTER: Malformed JWT, IP={}",
                    request.getRemoteAddr());
            sendError(response, HttpServletResponse.SC_UNAUTHORIZED,
                    "{\"error\":\"Invalid token format\"}");
        } catch (Exception e) {
            log.error("JWT AUTH FILTER: Unexpected error during verification", e);
            sendError(response, HttpServletResponse.SC_UNAUTHORIZED,
                    "{\"error\":\"Token verification failed\"}");
        } finally {
            // SecurityContext is cleared automatically per-request by Spring Security.
            // No explicit clear needed here for stateless filter chain.
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
