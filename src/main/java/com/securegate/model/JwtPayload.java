package com.securegate.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * JWT payload. INNOVATION #3: only sub + scope. No passwords, emails, PII.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class JwtPayload {
    private String sub;    // user_id
    private String scope;  // roles
    private String jti;    // JWT ID for blacklist
    private long iat;
    private long exp;
}
