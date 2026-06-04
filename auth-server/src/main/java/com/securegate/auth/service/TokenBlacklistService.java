package com.securegate.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/**
 * INNOVATION #1 - Instant Token Revocation with Redis.
 *
 * Stores JWT IDs (jti) in Redis blacklist on logout.
 * Gateway checks this blacklist before routing any request.
 *
 * Solves the biggest vulnerability of Stateless JWTs:
 * tokens that remain valid after user logs out.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TokenBlacklistService {

    private static final String BLACKLIST_PREFIX = "blacklist:";

    private final StringRedisTemplate redisTemplate;

    /**
     * Add a token's jti to the Redis blacklist with TTL matching
     * the token's remaining lifetime.
     */
    public void blacklist(String jti, long remainingTtlSeconds) {
        String key = BLACKLIST_PREFIX + jti;
        redisTemplate.opsForValue().set(key, "revoked", remainingTtlSeconds, TimeUnit.SECONDS);
        log.debug("Token blacklisted: jti={}, ttl={}s", jti, remainingTtlSeconds);
    }

    /**
     * Check if a token's jti is in the blacklist.
     * Returns true if token is revoked.
     */
    public boolean isBlacklisted(String jti) {
        String key = BLACKLIST_PREFIX + jti;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }
}
