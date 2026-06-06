package com.securegate.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * Instant token revocation via Redis.
 *
 * Stores blacklisted JWT IDs (jti) with Redis TTL matching the token's
 * remaining lifetime. When TTL expires, the entry automatically evaporates
 * from Redis — no cleanup cron needed.
 *
 * Redis key format: blacklist:<jti> → "revoked"
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TokenBlacklistService {

    private static final String KEY_PREFIX = "blacklist:";
    private static final String VALUE = "revoked";

    private final StringRedisTemplate redisTemplate;

    /**
     * Add a token to the blacklist with a TTL matching its remaining lifetime.
     *
     * @param jti        the JWT ID to revoke
     * @param ttlSeconds seconds until the token naturally expires
     */
    public void blacklist(String jti, long ttlSeconds) {
        if (ttlSeconds <= 0) {
            log.debug("Token jti={} already expired, skip blacklist", jti);
            return;
        }
        String key = KEY_PREFIX + jti;
        redisTemplate.opsForValue().set(key, VALUE, Duration.ofSeconds(ttlSeconds));
        log.info("Token revoked in Redis: jti={}, ttl={}s", jti, ttlSeconds);
    }

    /**
     * Check if a token ID has been revoked.
     *
     * @param jti the JWT ID to check
     * @return true if the token is blacklisted (revoked), false otherwise
     */
    public boolean isBlacklisted(String jti) {
        String key = KEY_PREFIX + jti;
        Boolean exists = redisTemplate.hasKey(key);
        boolean blacklisted = Boolean.TRUE.equals(exists);
        if (blacklisted) {
            log.warn("BLACKLISTED TOKEN DETECTED: jti={}", jti);
        }
        return blacklisted;
    }
}
