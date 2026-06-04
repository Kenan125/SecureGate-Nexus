package com.securegate.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

/**
 * JWT creation with RSA RS256. INNOVATION #3: payload only sub + scope.
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

    public String createAccessToken(String userId, String role) {
        try {
            PrivateKey privateKey = loadPrivateKey();
            JWSSigner signer = new RSASSASigner(privateKey);

            long now = System.currentTimeMillis();
            String jti = UUID.randomUUID().toString();

            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(userId)
                    .claim("scope", role)
                    .jwtID(jti)
                    .issuer(issuer)
                    .issueTime(new Date(now))
                    .expirationTime(new Date(now + accessTokenExpiry * 1000))
                    .build();

            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), claims);
            jwt.sign(signer);
            log.debug("JWT created: sub={}, jti={}", userId, jti);
            return jwt.serialize();
        } catch (Exception e) {
            throw new RuntimeException("JWT creation failed", e);
        }
    }

    public JWTClaimsSet parseClaims(String token) {
        try {
            return SignedJWT.parse(token).getJWTClaimsSet();
        } catch (Exception e) {
            throw new RuntimeException("Invalid token format", e);
        }
    }

    public long getRemainingTtlSeconds(Date expiration) {
        return Math.max((expiration.getTime() - System.currentTimeMillis()) / 1000, 0);
    }

    private PrivateKey loadPrivateKey() throws Exception {
        String content = Files.readString(Path.of(privateKeyPath))
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] keyBytes = Base64.getDecoder().decode(content);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }
}
