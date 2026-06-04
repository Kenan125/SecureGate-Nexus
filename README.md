# SecureGate Nexus

API Security Gateway â€” JWT authentication with RSA asymmetric encryption, Redis-based instant token revocation, algorithm manipulation filter, and secure payload enforcement.

**Single Spring Boot application. No Docker, no external Redis â€” everything self-contained.**

## Architecture

```
Client â”€â”€â–º SecureGate Nexus (:8080)
              â”‚
              â”œâ”€â”€ Filter Chain:
              â”‚   [1] AlgorithmValidationFilter  â€” block alg:none, HS*, missing alg
              â”‚   [2] TokenBlacklistFilter       â€” Redis EXISTS blacklist:<jti>
              â”‚   [3] JwtAuthFilter              â€” RSA signature verify, set SecurityContext
              â”‚
              â”œâ”€â”€ /auth/*     â€” register, login, logout
              â”œâ”€â”€ /api/orders â€” CRUD (protected)
              â””â”€â”€ /api/users  â€” profile, admin (protected)
              
              Embedded Redis (:6370) â€” token blacklist, auto-started
```

## Project Structure

```
SecureGate Nexus/
â”œâ”€â”€ pom.xml
â”œâ”€â”€ src/main/resources/application.yml
â”œâ”€â”€ src/main/java/com/securegate/
â”‚   â”œâ”€â”€ SecureGateApplication.java
â”‚   â”œâ”€â”€ config/
â”‚   â”‚   â”œâ”€â”€ SecurityConfig.java            # Filter chain + role-based access
â”‚   â”‚   â””â”€â”€ RedisConfig.java               # Embedded Redis startup
â”‚   â”œâ”€â”€ filter/
â”‚   â”‚   â”œâ”€â”€ AlgorithmValidationFilter.java  # Innovation #2: alg:none/confusion
â”‚   â”‚   â”œâ”€â”€ TokenBlacklistFilter.java       # Innovation #1: Redis blacklist check
â”‚   â”‚   â””â”€â”€ JwtAuthFilter.java              # RSA verify + Spring Security context
â”‚   â”œâ”€â”€ controller/
â”‚   â”‚   â”œâ”€â”€ AuthController.java             # /auth/register, /login, /logout
â”‚   â”‚   â”œâ”€â”€ OrderController.java            # /api/orders CRUD
â”‚   â”‚   â””â”€â”€ UserController.java             # /api/users/me, /api/users/admin
â”‚   â”œâ”€â”€ service/
â”‚   â”‚   â”œâ”€â”€ AuthService.java                # BCrypt auth, JWT, logout
â”‚   â”‚   â”œâ”€â”€ JwtService.java                 # RSA RS256 signing (Nimbus)
â”‚   â”‚   â””â”€â”€ TokenBlacklistService.java      # Redis SETEX/EXISTS
â”‚   â””â”€â”€ model/
â”‚       â”œâ”€â”€ JwtPayload.java, LoginRequest.java, RegisterRequest.java
â”‚       â”œâ”€â”€ TokenResponse.java, User.java, Order.java
â”œâ”€â”€ generate-keys.ps1
â””â”€â”€ README.md
```

**22 files total.** Focused on security logic, not infrastructure.

## 3 Security Innovations

| # | Innovation | Mechanism | Mitigates |
|---|-----------|-----------|-----------|
| 1 | **Instant Token Revocation** | Redis blacklist by `jti`, filter checks before auth | Stateless JWT cannot be revoked after logout |
| 2 | **Algorithm Manipulation Filter** | Decodes JWT header, blocks `alg:none` and symmetric (HS*) algorithms | Algorithm confusion attack, none-algorithm bypass |
| 3 | **Secure Payload Rule** | JWT contains ONLY `sub` + `scope` + `iat` + `exp` + `jti` | Base64 â‰  encryption, payload is public |

## Filter Chain Order

```
Request â†’ [1] AlgorithmValidationFilter
              Block: alg=none, HS256/384/512, missing alg
              Allow: RS256 only
       â†’ [2] TokenBlacklistFilter
              Redis EXISTS blacklist:<jti> â†’ 401 if revoked
       â†’ [3] JwtAuthFilter
              RSA signature verify with public key
              Set Spring Security context (userId + roles)
       â†’ Controller
```

## Step-by-Step Setup

### Prerequisites

- **Java 17+** ([Adoptium](https://adoptium.net/))
- **Git for Windows** (for OpenSSL â€” key generation only)

No Docker. No external Redis. No database. Embedded Redis starts/stops with the app.

### Step 1 â€” Generate RSA Keys

```powershell
.\generate-keys.ps1
```

Creates `keys/private.pem` (keep secret) and `keys/public.pem`.

### Step 2 â€” Run the Application

```powershell
mvnw spring-boot:run
```

First run downloads Maven dependencies (~2 min). Embedded Redis starts automatically on port 6370.

Wait for: `Started SecureGateApplication in X seconds`

### Step 3 â€” Test

```powershell
# Register
Invoke-WebRequest -Uri http://localhost:8080/auth/register `
  -Method POST -ContentType "application/json" `
  -Body '{"username":"alice","password":"secret123"}' -UseBasicParsing
# Expected: 201 Created

# Login â†’ get JWT
$r = Invoke-WebRequest -Uri http://localhost:8080/auth/login `
  -Method POST -ContentType "application/json" `
  -Body '{"username":"alice","password":"secret123"}' -UseBasicParsing
$token = ($r.Content | ConvertFrom-Json).accessToken

# Access protected API
Invoke-WebRequest -Uri http://localhost:8080/api/orders `
  -Headers @{"Authorization"="Bearer $token"} -UseBasicParsing
# Expected: 200 OK, []

# Create order
Invoke-WebRequest -Uri http://localhost:8080/api/orders `
  -Method POST -ContentType "application/json" `
  -Headers @{"Authorization"="Bearer $token"} `
  -Body '{"product":"Widget","quantity":5}' -UseBasicParsing
# Expected: 201 Created
```

### Step 4 â€” Verify All 3 Security Innovations

#### Innovation #1: Instant Token Revocation

```powershell
# Logout â†’ token goes to Redis blacklist
Invoke-WebRequest -Uri http://localhost:8080/auth/logout `
  -Method POST -Headers @{"Authorization"="Bearer $token"} -UseBasicParsing
# â†’ 200 "Logged out successfully. Token revoked."

# Same token â†’ BLOCKED (even though signature still valid!)
Invoke-WebRequest -Uri http://localhost:8080/api/orders `
  -Headers @{"Authorization"="Bearer $token"} -UseBasicParsing
# â†’ 401 "Token has been revoked. Please login again."
```

#### Innovation #2: Algorithm Manipulation Filter

```powershell
# alg=none attack (JWT with no signature)
Invoke-WebRequest -Uri http://localhost:8080/api/orders `
  -Headers @{"Authorization"="Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ.abc"} -UseBasicParsing
# â†’ 401 "Security violation: 'none' algorithm detected"
```

#### Innovation #3: Secure Payload

Decode any JWT at [jwt.io](https://jwt.io). Payload contains only: `sub`, `scope`, `iat`, `exp`, `jti`, `iss`. No passwords, emails, or PII â€” Base64 is encoding, not encryption.

### Step 5 â€” Admin Role Test

```powershell
# Register admin
Invoke-WebRequest -Uri http://localhost:8080/auth/register `
  -Method POST -ContentType "application/json" `
  -Body '{"username":"admin","password":"admin123!","role":"ROLE_ADMIN"}' -UseBasicParsing

# Login as admin
$ar = Invoke-WebRequest -Uri http://localhost:8080/auth/login `
  -Method POST -ContentType "application/json" `
  -Body '{"username":"admin","password":"admin123!"}' -UseBasicParsing
$at = ($ar.Content | ConvertFrom-Json).accessToken

# Access admin endpoint
Invoke-WebRequest -Uri http://localhost:8080/api/users/admin `
  -Headers @{"Authorization"="Bearer $at"} -UseBasicParsing
# â†’ 200 "Admin access granted"
```

## JWT Payload (Secure Payload Rule)

```json
{
  "sub": "user-uuid",
  "scope": "ROLE_USER",
  "iat": 1686000000,
  "exp": 1686000900,
  "jti": "unique-token-id",
  "iss": "securegate-nexus"
}
```

## Key Design Decisions

- **RSA 2048-bit** RS256 asymmetric signing â€” private key signs, public key verifies
- **Embedded Redis** â€” starts/stops with app, no Docker/install needed
- **jti-based blacklist** â€” O(1) Redis lookup per request, auto-expires with token
- **No raw JWT forwarding** â€” JwtAuthFilter sets Spring Security context directly
- **22 files total** â€” security logic, not infrastructure overhead

## References

- IEEE: "Enhancing Security in Data Exchange: Mitigating Risks & Solutions in Base64 Encoding and JSON Web Tokens"
- IEEE: "Research on API Security Gateway and Data Access Control Model for Multi-tenant Full-stack Systems"