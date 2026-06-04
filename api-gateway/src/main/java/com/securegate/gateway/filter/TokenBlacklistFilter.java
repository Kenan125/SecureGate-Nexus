package com.securegate.gateway.filter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * INNOVATION #1 - Instant Token Revocation via Redis Blacklist.
 *
 * Runs SECOND in the filter chain. After algorithm validation passes,
 * extracts the JWT ID (jti) from the token and checks Redis blacklist.
 *
 * If the token's jti is found in Redis, the token has been revoked
 * (user logged out) — return 401 even though the signature is still valid.
 *
 * This solves the fundamental weakness of stateless JWTs:
 * without server-side state, there is no way to revoke a token before
 * its natural expiration.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class TokenBlacklistFilter implements GlobalFilter, Ordered {

    private static final String BLACKLIST_PREFIX = "blacklist:";

    private final ReactiveStringRedisTemplate redisTemplate;

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
            String jti = extractJti(token);
            if (jti == null) {
                log.warn("JWT missing jti claim");
                return unauthorized(exchange, "Invalid token: missing jti claim");
            }

            // Check Redis blacklist. Reactive (non-blocking) lookup.
            return redisTemplate.hasKey(BLACKLIST_PREFIX + jti)
                    .flatMap(isBlacklisted -> {
                        if (Boolean.TRUE.equals(isBlacklisted)) {
                            log.warn("REVOKED TOKEN DETECTED: jti={} is blacklisted", jti);
                            return unauthorized(exchange,
                                    "Token has been revoked. Please login again.");
                        }
                        log.debug("Token not in blacklist: jti={}", jti);
                        return chain.filter(exchange);
                    });

        } catch (Exception e) {
            log.error("Blacklist filter error: {}", e.getMessage());
            return unauthorized(exchange, "Invalid token format");
        }
    }

    /**
     * Extract the jti (JWT ID) from the token payload WITHOUT verifying signature.
     * jti is a unique identifier set by the auth server at token creation time.
     */
    private String extractJti(String token) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) {
            return null;
        }

        byte[] payloadBytes = Base64.getUrlDecoder().decode(parts[1]);
        String payloadJson = new String(payloadBytes, StandardCharsets.UTF_8);

        // Extract jti from JSON payload
        String jtiKey = "\"jti\"";
        int idx = payloadJson.indexOf(jtiKey);
        if (idx == -1) {
            return null;
        }

        int colonIdx = payloadJson.indexOf(":", idx);
        int valueStart = -1;
        for (int i = colonIdx + 1; i < payloadJson.length(); i++) {
            char c = payloadJson.charAt(i);
            if (c == '"') {
                if (valueStart == -1) {
                    valueStart = i + 1;
                } else {
                    return payloadJson.substring(valueStart, i);
                }
            }
        }
        return null;
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
        return -90; // Run SECOND, after algorithm validation
    }
}
