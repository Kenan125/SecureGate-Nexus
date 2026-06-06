package com.securegate.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.securegate.config.RSAKeyConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.UUID;

/**
 * JWT creation and parsing service using RSA RS256 asymmetric keys.
 *
 * STRICT PAYLOAD RULE: The JWT payload contains ONLY public identifiers:
 *   - sub  : User UUID (not username, not email)
 *   - scope: Roles (e.g., "ROLE_USER ROLE_ADMIN")
 *   - jti  : Unique JWT ID for revocation
 *   - iat  : Issued At timestamp
 *   - exp  : Expiration timestamp
 *   - iss  : Issuer identifier
 *
 * NEVER include PII, emails, passwords, or sensitive data in the payload.
 * Base64 encoding is NOT encryption.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class JwtService {

    private final RSAKeyConfig rsaKeyConfig;

    @Value("${jwt.access-token-expiry:900}")
    private long accessTokenExpirySeconds;

    @Value("${jwt.issuer:securegate-nexus}")
    private String issuer;

    /**
     * Create a signed RS256 JWT access token.
     *
     * @param userId the user's UUID (used as 'sub' claim)
     * @param role   the user's role(s), space-separated (e.g., "ROLE_USER")
     * @return serialized JWT string
     */
    public String createAccessToken(String userId, String role) {
        try {
            JWSSigner signer = new RSASSASigner(rsaKeyConfig.getPrivateKey());

            long nowMillis = System.currentTimeMillis();
            Date now = new Date(nowMillis);
            Date exp = new Date(nowMillis + accessTokenExpirySeconds * 1000);

            String jti = UUID.randomUUID().toString();

            // STRICT PAYLOAD: only public identifiers
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(userId)           // sub: user UUID
                    .claim("scope", role)     // scope: roles
                    .jwtID(jti)               // jti: unique token ID
                    .issueTime(now)           // iat: issued at
                    .expirationTime(exp)      // exp: expiration
                    .issuer(issuer)           // iss: issuer
                    .build();

            SignedJWT signedJwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                    claims);
            signedJwt.sign(signer);

            String token = signedJwt.serialize();
            log.debug("JWT created: sub={}, jti={}, exp={}, scope={}",
                    userId, jti, exp, role);
            return token;

        } catch (Exception e) {
            log.error("JWT creation failed for user={}", userId, e);
            throw new RuntimeException("JWT creation failed", e);
        }
    }

    /**
     * Parse a JWT string and extract its claims (without verifying signature).
     * Used by the logout flow to extract jti and expiration.
     *
     * @param token the serialized JWT string
     * @return the parsed claims set
     */
    public JWTClaimsSet parseClaims(String token) {
        try {
            return SignedJWT.parse(token).getJWTClaimsSet();
        } catch (Exception e) {
            log.warn("Failed to parse JWT claims", e);
            throw new RuntimeException("Invalid token format", e);
        }
    }

    /**
     * Calculate the remaining time-to-live in seconds for a token.
     *
     * @param expiration the token's expiration date
     * @return remaining seconds (minimum 0)
     */
    public long getRemainingTtlSeconds(Date expiration) {
        if (expiration == null) return 0;
        long remaining = (expiration.getTime() - System.currentTimeMillis()) / 1000;
        return Math.max(remaining, 0);
    }
}
