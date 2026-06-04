package com.securegate.gateway.filter;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

/**
 * Runs THIRD in the filter chain. Verifies JWT signature using RSA public key.
 *
 * At this point, AlgorithmValidationFilter has already confirmed the alg is
 * RS256/RS512, and TokenBlacklistFilter has confirmed the token is not revoked.
 *
 * This filter:
 * 1. Verifies the RSA signature with the public key
 * 2. Checks token expiration (exp claim)
 * 3. Extracts user_id (sub) and scopes (scope) from the verified payload
 * 4. Forwards these as headers (X-User-Id, X-User-Scopes) to downstream services
 *
 * INNOVATION #3: The payload contains ONLY sub + scope at this point.
 * No passwords or secrets can leak even if token is intercepted.
 */
@Component
@Slf4j
public class JwtAuthFilter implements GlobalFilter, Ordered {

    @Value("${jwt.public-key-path}")
    private String publicKeyPath;

    private volatile RSAPublicKey cachedPublicKey;
    private final Object keyLock = new Object();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            String path = exchange.getRequest().getURI().getPath();
            if (path.startsWith("/auth/register") || path.startsWith("/auth/login")) {
                return chain.filter(exchange);
            }
            return unauthorized(exchange, "Missing Authorization header");
        }

        String token = authHeader.substring(7);

        try {
            SignedJWT signedJwt = SignedJWT.parse(token);

            // Verify RSA signature with public key
            RSAPublicKey publicKey = getPublicKey();
            JWSVerifier verifier = new RSASSAVerifier(publicKey);

            if (!signedJwt.verify(verifier)) {
                log.warn("JWT SIGNATURE VERIFICATION FAILED from {}",
                        exchange.getRequest().getRemoteAddress());
                return unauthorized(exchange, "Invalid token signature");
            }

            // Check expiration
            Date expiration = signedJwt.getJWTClaimsSet().getExpirationTime();
            if (expiration != null && expiration.before(new Date())) {
                log.debug("JWT expired: exp={}", expiration);
                return unauthorized(exchange, "Token has expired");
            }

            // Extract minimal claims for downstream propagation
            String userId = signedJwt.getJWTClaimsSet().getSubject();
            String scope = (String) signedJwt.getJWTClaimsSet().getClaim("scope");

            // Forward user context to internal services via headers
            ServerWebExchange mutatedExchange = exchange.mutate()
                    .request(r -> r.headers(headers -> {
                        headers.add("X-User-Id", userId != null ? userId : "unknown");
                        headers.add("X-User-Scopes", scope != null ? scope : "");
                        // NEVER forward the raw token to internal services
                        // Internal services trust the gateway's verification
                    }))
                    .build();

            log.debug("JWT verified: sub={}, scope={}", userId, scope);
            return chain.filter(mutatedExchange);

        } catch (Exception e) {
            log.error("JWT verification error: {}", e.getMessage());
            return unauthorized(exchange, "Token verification failed");
        }
    }

    /**
     * Load and cache the RSA public key from file.
     */
    private RSAPublicKey getPublicKey() throws IOException {
        if (cachedPublicKey != null) {
            return cachedPublicKey;
        }
        synchronized (keyLock) {
            if (cachedPublicKey != null) {
                return cachedPublicKey;
            }
            try {
                String keyContent = Files.readString(Path.of(publicKeyPath))
                        .replace("-----BEGIN PUBLIC KEY-----", "")
                        .replace("-----END PUBLIC KEY-----", "")
                        .replaceAll("\\s", "");

                byte[] keyBytes = Base64.getDecoder().decode(keyContent);
                X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PublicKey publicKey = keyFactory.generatePublic(spec);
                cachedPublicKey = (RSAPublicKey) publicKey;
                log.info("RSA public key loaded and cached");
                return cachedPublicKey;
            } catch (Exception e) {
                throw new IOException("Failed to load RSA public key", e);
            }
        }
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        String body = String.format("{\"error\":\"unauthorized\",\"message\":\"%s\"}", message);
        DataBuffer buffer = exchange.getResponse()
                .bufferFactory()
                .wrap(body.getBytes(StandardCharsets.UTF_8));
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }

    @Override
    public int getOrder() {
        return -80; // Run THIRD, after blacklist check
    }
}
