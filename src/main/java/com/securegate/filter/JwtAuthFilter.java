package com.securegate.filter;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;

/**
 * Runs THIRD. RSA signature verify with public key, set Spring Security context.
 * INNOVATION #3: Only sub + scope extracted. No raw token forwarded.
 */
@Component
@Order(-80)
@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter {

    @Value("${jwt.public-key-path}")
    private String publicKeyPath;
    private volatile RSAPublicKey cachedKey;

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
            SignedJWT jwt = SignedJWT.parse(auth.substring(7));
            if (!jwt.verify(new RSASSAVerifier(getPublicKey()))) {
                sendError(response, 401, "Invalid token signature");
                return;
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            Date exp = claims.getExpirationTime();
            if (exp != null && exp.before(new Date())) {
                sendError(response, 401, "Token has expired");
                return;
            }

            String userId = claims.getSubject();
            String scope = (String) claims.getClaim("scope");
            List<SimpleGrantedAuthority> authorities = (scope != null)
                    ? Arrays.stream(scope.split("\\s+")).map(SimpleGrantedAuthority::new).toList()
                    : List.of();

            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(userId, null, authorities));
            log.debug("JWT verified: sub={}, scope={}", userId, scope);
            chain.doFilter(request, response);
        } catch (Exception e) {
            sendError(response, 401, "Token verification failed");
        }
    }

    private RSAPublicKey getPublicKey() throws Exception {
        if (cachedKey != null) return cachedKey;
        synchronized (this) {
            if (cachedKey != null) return cachedKey;
            String content = Files.readString(Path.of(publicKeyPath))
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] bytes = Base64.getDecoder().decode(content);
            cachedKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(bytes));
            log.info("RSA public key loaded");
            return cachedKey;
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/auth/register") || path.startsWith("/auth/login");
    }

    private void sendError(HttpServletResponse response, int status, String msg) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"" + msg + "\"}");
    }
}
