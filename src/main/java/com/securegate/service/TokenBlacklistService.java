package com.securegate.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/**
 * INNOVATION #1: Redis-based instant token revocation.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TokenBlacklistService {

    private static final String PREFIX = "blacklist:";
    private final StringRedisTemplate redisTemplate;

    public void blacklist(String jti, long ttlSeconds) {
        redisTemplate.opsForValue().set(PREFIX + jti, "revoked", ttlSeconds, TimeUnit.SECONDS);
        log.debug("Token blacklisted: jti={}, ttl={}s", jti, ttlSeconds);
    }

    public boolean isBlacklisted(String jti) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(PREFIX + jti));
    }
}
