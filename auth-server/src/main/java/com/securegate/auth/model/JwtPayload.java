package com.securegate.auth.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * JWT payload structure.
 * INNOVATION #3 - Secure Payload Rule:
 * Only user_id and scopes (roles). Never passwords, emails, or PII.
 * Base64 is encoding, NOT encryption. Payload is readable by anyone with the token.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class JwtPayload {
    private String sub;       // user_id (subject)
    private String scope;     // roles (e.g., "ROLE_USER ROLE_ADMIN")
    private String jti;       // JWT ID for blacklist/revocation
    private long iat;         // issued at (epoch seconds)
    private long exp;         // expiration (epoch seconds)
}
