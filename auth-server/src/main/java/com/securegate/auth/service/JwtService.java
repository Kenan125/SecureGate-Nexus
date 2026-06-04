package com.securegate.auth.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

/**
 * JWT creation service using RSA asymmetric encryption.
 *
 * INNOVATION #3 - Secure Payload Rule:
 * JWT payload contains ONLY: sub (userId), scope (roles), iat, exp, jti.
 * NO passwords, emails, or PII — Base64 is encoding, not encryption.
 *
 * INNOVATION #1 - Each JWT gets unique jti for Redis-based revocation support.
 */
@Service
@Slf4j
public class JwtService {

    @Value("${jwt.private-key-path}")
    private String privateKeyPath;

    @Value("${jwt.access-token-expiry}")
    private long accessTokenExpiry;

    @Value("${jwt.issuer}")
    private String issuer;

    /**
     * Create a signed JWT with minimal payload.
     * Algorithm: RS256 (RSA + SHA-256).
     * NEVER includes passwords, emails, or PII in payload.
     */
    public String createAccessToken(String userId, String role) throws JOSEException, IOException {
        PrivateKey privateKey = loadPrivateKey();
        JWSSigner signer = new RSASSASigner(privateKey);

        long now = System.currentTimeMillis();
        String jti = UUID.randomUUID().toString();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(userId)                    // INNOVATION #3: only user_id
                .claim("scope", role)               // INNOVATION #3: only roles
                .jwtID(jti)                         // INNOVATION #1: unique ID for blacklist
                .issuer(issuer)
                .issueTime(new Date(now))
                .expirationTime(new Date(now + accessTokenExpiry * 1000))
                .build();

        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                claimsSet
        );
        signedJwt.sign(signer);

        String token = signedJwt.serialize();
        log.debug("JWT created: sub={}, jti={}, exp={}s", userId, jti, accessTokenExpiry);
        return token;
    }

    /**
     * Parse and extract claims from a JWT string.
     * Used for logout (extract jti) and refresh token operations.
     */
    public JWTClaimsSet parseClaims(String token) {
        try {
            SignedJWT signedJwt = SignedJWT.parse(token);
            return signedJwt.getJWTClaimsSet();
        } catch (Exception e) {
            log.error("Failed to parse JWT: {}", e.getMessage());
            throw new RuntimeException("Invalid token format", e);
        }
    }

    /**
     * Calculate remaining TTL in seconds for a given expiration time.
     */
    public long getRemainingTtlSeconds(Date expiration) {
        long remaining = (expiration.getTime() - System.currentTimeMillis()) / 1000;
        return Math.max(remaining, 0);
    }

    private PrivateKey loadPrivateKey() throws IOException {
        try {
            String keyContent = Files.readString(Path.of(privateKeyPath))
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] keyBytes = Base64.getDecoder().decode(keyContent);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(spec);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Failed to load RSA private key from " + privateKeyPath, e);
        }
    }
}
