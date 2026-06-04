# SecureGate Nexus

API Security Gateway -- JWT authentication with RSA asymmetric encryption, Redis-based instant token revocation, algorithm manipulation filter, and secure payload enforcement.

**Single Spring Boot application. No Docker, no external Redis -- everything self-contained.**

## Architecture

```
Client --> SecureGate Nexus (:8080)
              |
              +-- Filter Chain:
              |   [1] AlgorithmValidationFilter  -- block alg:none, HS*, missing alg
              |   [2] TokenBlacklistFilter       -- Redis EXISTS blacklist:<jti>
              |   [3] JwtAuthFilter              -- RSA signature verify, set SecurityContext
              |
              +-- /auth/*     -- register, login, logout
              +-- /api/orders -- CRUD (protected)
              +-- /api/users  -- profile, admin (protected)
              
              Embedded Redis (:6370) -- token blacklist, auto-started
```

## Project Structure

```
SecureGate Nexus/
+-- pom.xml
+-- src/main/resources/application.yml
+-- src/main/java/com/securegate/
|   +-- SecureGateApplication.java
|   +-- config/
|   |   +-- SecurityConfig.java            # Filter chain + role-based access
|   |   +-- RedisConfig.java               # Embedded Redis startup
|   +-- filter/
|   |   +-- AlgorithmValidationFilter.java  # Innovation #2: alg:none/confusion
|   |   +-- TokenBlacklistFilter.java       # Innovation #1: Redis blacklist check
|   |   +-- JwtAuthFilter.java              # RSA verify + Spring Security context
|   +-- controller/
|   |   +-- AuthController.java             # /auth/register, /login, /logout
|   |   +-- OrderController.java            # /api/orders CRUD
|   |   +-- UserController.java             # /api/users/me, /api/users/admin
|   +-- service/
|   |   +-- AuthService.java                # BCrypt auth, JWT, logout
|   |   +-- JwtService.java                 # RSA RS256 signing (Nimbus)
|   |   +-- TokenBlacklistService.java      # Redis SETEX/EXISTS
|   +-- model/
|       +-- JwtPayload.java, LoginRequest.java, RegisterRequest.java
|       +-- TokenResponse.java, User.java, Order.java
+-- generate-keys.ps1
+-- README.md
```

**22 files total.** Focused on security logic, not infrastructure.

## 3 Security Innovations

| # | Innovation | Mechanism | Mitigates |
|---|-----------|-----------|-----------|
| 1 | **Instant Token Revocation** | Redis blacklist by `jti`, filter checks before auth | Stateless JWT cannot be revoked after logout |
| 2 | **Algorithm Manipulation Filter** | Decodes JWT header, blocks `alg:none` and symmetric (HS*) algorithms | Algorithm confusion attack, none-algorithm bypass |
| 3 | **Secure Payload Rule** | JWT contains ONLY `sub` + `scope` + `iat` + `exp` + `jti` | Base64 != encryption, payload is public |

## Filter Chain Order

```
Request -> [1] AlgorithmValidationFilter
              Block: alg=none, HS256/384/512, missing alg
              Allow: RS256 only
       -> [2] TokenBlacklistFilter
              Redis EXISTS blacklist:<jti> -> 401 if revoked
       -> [3] JwtAuthFilter
              RSA signature verify with public key
              Set Spring Security context (userId + roles)
       -> Controller
```

## Step-by-Step Setup

### Prerequisites

- **Java 17+** ([Adoptium](https://adoptium.net/))
- **Git for Windows** (for OpenSSL -- key generation only)

No Docker. No external Redis. No database. Embedded Redis starts/stops with the app.

### Step 1 -- Generate RSA Keys

```powershell
.\generate-keys.ps1
```

Creates `keys/private.pem` (keep secret) and `keys/public.pem`.

### Step 2 -- Run the Application

```powershell
mvnw spring-boot:run
```

First run downloads Maven dependencies (~2 min). Embedded Redis starts automatically on port 6370.

Wait for: `Started SecureGateApplication in X seconds`

### Step 3 -- Test

```powershell
# Register
Invoke-WebRequest -Uri http://localhost:8080/auth/register `
  -Method POST -ContentType "application/json" `
  -Body '{"username":"alice","password":"secret123"}' -UseBasicParsing
# Expected: 201 Created

# Login -> get JWT
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

### Step 4 -- Verify All 3 Security Innovations

#### Innovation #1: Instant Token Revocation

```powershell
# Logout -> token goes to Redis blacklist
Invoke-WebRequest -Uri http://localhost:8080/auth/logout `
  -Method POST -Headers @{"Authorization"="Bearer $token"} -UseBasicParsing
# -> 200 "Logged out successfully. Token revoked."

# Same token -> BLOCKED (even though signature still valid!)
Invoke-WebRequest -Uri http://localhost:8080/api/orders `
  -Headers @{"Authorization"="Bearer $token"} -UseBasicParsing
# -> 401 "Token has been revoked. Please login again."
```

#### Innovation #2: Algorithm Manipulation Filter

```powershell
# alg=none attack (JWT with no signature)
Invoke-WebRequest -Uri http://localhost:8080/api/orders `
  -Headers @{"Authorization"="Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ.abc"} -UseBasicParsing
# -> 401 "Security violation: 'none' algorithm detected"
```

#### Innovation #3: Secure Payload

Decode any JWT at [jwt.io](https://jwt.io). Payload contains only: `sub`, `scope`, `iat`, `exp`, `jti`, `iss`. No passwords, emails, or PII -- Base64 is encoding, not encryption.

### Step 5 -- Admin Role Test

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
# -> 200 "Admin access granted"
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

- **RSA 2048-bit** RS256 asymmetric signing -- private key signs, public key verifies
- **Embedded Redis** -- starts/stops with app, no Docker/install needed
- **jti-based blacklist** -- O(1) Redis lookup per request, auto-expires with token
- **No raw JWT forwarding** -- JwtAuthFilter sets Spring Security context directly
- **22 files total** -- security logic, not infrastructure overhead

## References

- IEEE: "Enhancing Security in Data Exchange: Mitigating Risks & Solutions in Base64 Encoding and JSON Web Tokens"
- IEEE: "Research on API Security Gateway and Data Access Control Model for Multi-tenant Full-stack Systems"
