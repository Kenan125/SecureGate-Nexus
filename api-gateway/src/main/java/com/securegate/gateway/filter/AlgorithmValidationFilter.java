package com.securegate.gateway.filter;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Set;

/**
 * INNOVATION #2 - Algorithm Manipulation Filter.
 *
 * Runs FIRST in the filter chain. Decodes the JWT header (unverified)
 * and checks the "alg" claim before any signature verification.
 *
 * MITIGATES:
 * - "alg": "none" attack: Attacker sets algorithm to none, JWT library
 *   might skip signature verification entirely.
 * - Algorithm Confusion attack: Attacker changes RS256 to HS256, tricking
 *   the server into using the public key as an HMAC secret.
 *
 * ONLY asymmetric algorithms (RS256, RS512) are allowed through this gateway.
 */
@Component
@Slf4j
public class AlgorithmValidationFilter implements GlobalFilter, Ordered {

    // ONLY asymmetric algorithms allowed. Symmetric (HS*) blocked.
    // "none" explicitly blocked. Missing or unknown alg blocked.
    private static final Set<String> ALLOWED_ALGORITHMS = Set.of("RS256", "RS512");
    private static final Set<String> BLOCKED_ALGORITHMS = Set.of("none", "None", "NONE");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");

        // Skip filter for public endpoints (no token)
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            String path = exchange.getRequest().getURI().getPath();
            if (path.startsWith("/auth/register") || path.startsWith("/auth/login")) {
                return chain.filter(exchange);
            }
            return unauthorized(exchange, "Missing or malformed Authorization header");
        }

        try {
            String token = authHeader.substring(7);
            String alg = extractAlgorithm(token);

            // Check for "none" algorithm attack
            if (BLOCKED_ALGORITHMS.contains(alg)) {
                log.warn("ALGORITHM ATTACK DETECTED: alg=none in JWT from {}",
                        exchange.getRequest().getRemoteAddress());
                return unauthorized(exchange,
                        "Security violation: 'none' algorithm detected. JWT must be signed.");
            }

            // Check for algorithm confusion (symmetric algorithms)
            if (alg != null && (alg.startsWith("HS") || !ALLOWED_ALGORITHMS.contains(alg))) {
                log.warn("ALGORITHM CONFUSION ATTACK DETECTED: alg={} from {}",
                        alg, exchange.getRequest().getRemoteAddress());
                return unauthorized(exchange,
                        "Security violation: Algorithm '" + alg + "' is not allowed. Only RS256/RS512 permitted.");
            }

            // Missing algorithm
            if (alg == null || alg.isEmpty()) {
                log.warn("JWT missing 'alg' header from {}",
                        exchange.getRequest().getRemoteAddress());
                return unauthorized(exchange,
                        "Security violation: JWT header missing 'alg' claim.");
            }

            log.debug("Algorithm check passed: alg={}", alg);
            return chain.filter(exchange);

        } catch (Exception e) {
            log.error("Algorithm filter error: {}", e.getMessage());
            return unauthorized(exchange, "Invalid JWT format: unable to parse header");
        }
    }

    /**
     * Extract the "alg" claim from the JWT header WITHOUT verifying signature.
     * This is an unverified decode — the attacker controls this value.
     * That's exactly why we must validate it BEFORE signature verification.
     */
    private String extractAlgorithm(String token) throws Exception {
        // JWT format: header.payload.signature
        String[] parts = token.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("Invalid JWT format");
        }

        // Base64-decode the header (URL-safe, no verification)
        byte[] headerBytes = Base64.getUrlDecoder().decode(parts[0]);
        String headerJson = new String(headerBytes, StandardCharsets.UTF_8);

        // Simple JSON parsing to extract "alg" (avoiding full JSON library for performance)
        String algKey = "\"alg\"";
        int algIdx = headerJson.indexOf(algKey);
        if (algIdx == -1) {
            return null;
        }

        int colonIdx = headerJson.indexOf(":", algIdx);
        int valueStart = -1;
        for (int i = colonIdx + 1; i < headerJson.length(); i++) {
            char c = headerJson.charAt(i);
            if (c == '"') {
                if (valueStart == -1) {
                    valueStart = i + 1;
                } else {
                    return headerJson.substring(valueStart, i);
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
        return -100; // Run FIRST before all other filters
    }
}
