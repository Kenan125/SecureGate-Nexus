package com.securegate.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * INNOVATION #1: Instant token revocation via in-memory blacklist.
 * Pure Java — no Redis, no native binaries. Works on any OS with any JDK.
 */
@Service
@Slf4j
public class TokenBlacklistService {

    private final Map<String, Long> blacklist = new ConcurrentHashMap<>();

    public void blacklist(String jti, long ttlSeconds) {
        blacklist.put(jti, System.currentTimeMillis() + ttlSeconds * 1000);
        log.debug("Token blacklisted: jti={}, ttl={}s", jti, ttlSeconds);
    }

    public boolean isBlacklisted(String jti) {
        Long expiresAt = blacklist.get(jti);
        if (expiresAt == null) return false;
        if (System.currentTimeMillis() > expiresAt) {
            blacklist.remove(jti);
            return false;
        }
        return true;
    }

    @Scheduled(fixedRate = 60_000)
    public void evictExpired() {
        long now = System.currentTimeMillis();
        blacklist.entrySet().removeIf(e -> e.getValue() <= now);
    }
}
