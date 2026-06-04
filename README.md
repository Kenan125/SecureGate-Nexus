# SecureGate Nexus

API Security Gateway with JWT authentication, Redis-based instant token revocation, algorithm manipulation detection, and secure payload enforcement.

## Architecture

```
Client ──► API Gateway (:8080) ──► Auth Server (:8081)
               │                        │
               │              ┌─────────┘
               │              ▼
               │         Redis (:6379)
               │         [Token Blacklist]
               │
               └──────► Internal Service (:8082)
                           /api/orders
                           /api/users
```

## 3 Security Innovations

| # | Innovation | Mechanism | Mitigates |
|---|-----------|-----------|-----------|
| 1 | **Instant Token Revocation** | Redis blacklist by `jti`, gateway checks before routing | Stateless JWT cannot be revoked after logout |
| 2 | **Algorithm Manipulation Filter** | Gateway decodes JWT header, blocks `alg:none` and symmetric (HS*) algorithms | Algorithm confusion attack, none-algorithm bypass |
| 3 | **Secure Payload Rule** | JWT contains ONLY `sub` + `scope` + `iat` + `exp` + `jti` | Base64 ≠ encryption, payload is public |

## Filter Chain Order

```
Request → [1] AlgorithmValidationFilter (order: -100)
              Block: alg=none, HS256/384/512, missing alg
              Allow: RS256, RS512 only
       → [2] TokenBlacklistFilter (order: -90)
              Redis EXISTS blacklist:<jti> → 401 if revoked
       → [3] JwtAuthFilter (order: -80)
              RSA signature verify with public key
              Check exp, extract sub+scope
              Forward X-User-Id, X-User-Scopes to internal
       → Internal Service
```

## Step-by-Step Setup (Windows/PowerShell)

### Prerequisites

Install these before starting:

- **[Docker Desktop](https://www.docker.com/products/docker-desktop/)** — for Redis + containerized services
- **[Git for Windows](https://git-scm.com/download/win)** — includes OpenSSL (for RSA keys)
- **[Java 17+](https://adoptium.net/)** — if running services locally without Docker

Verify installs:

```powershell
docker --version          # Docker version 24+
java --version            # openjdk 17+
git --version             # needed for OpenSSL
```

### Step 1 — Generate RSA Key Pair

The auth server signs JWTs with an RSA private key. The gateway and internal services verify with the public key.

```powershell
.\generate-keys.ps1
```

This creates `keys/private.pem` (keep secret) and `keys/public.pem` (shared).

> If you see "openssl not found", the script auto-detects Git's bundled OpenSSL. If it still fails, install Git for Windows or run manually:
> ```powershell
> & "C:\Program Files\Git\usr\bin\openssl.exe" genpkey -algorithm RSA -out keys\private.pem -pkeyopt rsa_keygen_bits:2048
> & "C:\Program Files\Git\usr\bin\openssl.exe" rsa -in keys\private.pem -pubout -out keys\public.pem
> ```

### Step 2 — Start All Services with Docker

```powershell
docker-compose up --build
```

First run downloads images (~300MB Maven + JRE) and builds all 3 Java services. Subsequent runs use cached layers — much faster.

Wait until you see all 4 services ready:

```
securegate-redis     | Ready to accept connections tcp
securegate-auth      | Started AuthServerApplication in X seconds
securegate-gateway   | Started GatewayApplication in X seconds
securegate-internal  | Started InternalServiceApplication in X seconds
```

### Step 3 — Test with a New Terminal

**Open a second PowerShell window** (keep docker running in the first one).

> **Note:** PowerShell's built-in `curl` is an alias for `Invoke-WebRequest`. Use `-UseBasicParsing` to suppress security warnings. You can also use Git's real curl:
> ```powershell
> & "C:\Program Files\Git\mingw64\bin\curl.exe" <args...>
> ```

#### 3.1 — Register a User

```powershell
Invoke-WebRequest -Uri http://localhost:8080/auth/register `
  -Method POST `
  -ContentType "application/json" `
  -Body '{"username":"alice","password":"secret123"}' `
  -UseBasicParsing
```

**Expected:** `201 Created` with `userId` and `username`.

#### 3.2 — Login to Get JWT Token

```powershell
$response = Invoke-WebRequest -Uri http://localhost:8080/auth/login `
  -Method POST `
  -ContentType "application/json" `
  -Body '{"username":"alice","password":"secret123"}' `
  -UseBasicParsing

$data = $response.Content | ConvertFrom-Json
$token = $data.accessToken
$token  # prints your JWT
```

**Expected:** `200 OK` with `accessToken`, `tokenType: "Bearer"`, `expiresIn: 900`.

#### 3.3 — Access Protected API

```powershell
Invoke-WebRequest -Uri http://localhost:8080/api/orders `
  -Headers @{"Authorization"="Bearer $token"} `
  -UseBasicParsing
```

**Expected:** `200 OK` with `[]` (empty order list for new user).

#### 3.4 — Create an Order

```powershell
Invoke-WebRequest -Uri http://localhost:8080/api/orders `
  -Method POST `
  -ContentType "application/json" `
  -Headers @{"Authorization"="Bearer $token"} `
  -Body '{"product":"Widget","quantity":5}' `
  -UseBasicParsing
```

**Expected:** `201 Created` with order details.

### Step 4 — Verify Security Innovations

#### Innovation #1: Instant Token Revocation

```powershell
# Logout — adds token jti to Redis blacklist
Invoke-WebRequest -Uri http://localhost:8080/auth/logout `
  -Method POST `
  -Headers @{"Authorization"="Bearer $token"} `
  -UseBasicParsing
# Expected: 200 "Logged out successfully. Token revoked."

# Try to use the SAME token again
Invoke-WebRequest -Uri http://localhost:8080/api/orders `
  -Headers @{"Authorization"="Bearer $token"} `
  -UseBasicParsing
# Expected: 401 "Token has been revoked. Please login again."
```

> This proves the token is dead even though its JWT signature is still mathematically valid. Redis blacklist blocks it.

#### Innovation #2: Algorithm Manipulation Filter

```powershell
# alg=none attack (unsafe JWT with no signature)
Invoke-WebRequest -Uri http://localhost:8080/api/orders `
  -Headers @{"Authorization"="Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ.abc"} `
  -UseBasicParsing
# Expected: 401 "Security violation: 'none' algorithm detected"
```

> The gateway decodes the JWT header BEFORE signature verification and rejects `alg:none` and any symmetric algorithm (HS256/HS384/HS512).

#### Innovation #3: Direct Access Blocked

```powershell
# Try to bypass gateway — call internal service directly on port 8082
Invoke-WebRequest -Uri http://localhost:8082/api/orders -UseBasicParsing
# Expected: 401 "Access denied: must go through API Gateway"
```

> Internal service checks for `X-User-Id` header (injected by gateway after JWT verification). Direct access has no such header — rejected.

### Step 5 — Admin Role Test (Optional)

Register an admin user and test role-based access:

```powershell
# Register admin
Invoke-WebRequest -Uri http://localhost:8080/auth/register `
  -Method POST -ContentType "application/json" `
  -Body '{"username":"admin","password":"admin123!","role":"ROLE_ADMIN"}' `
  -UseBasicParsing

# Login as admin
$adminResp = Invoke-WebRequest -Uri http://localhost:8080/auth/login `
  -Method POST -ContentType "application/json" `
  -Body '{"username":"admin","password":"admin123!"}' `
  -UseBasicParsing
$adminToken = ($adminResp.Content | ConvertFrom-Json).accessToken

# Access admin endpoint
Invoke-WebRequest -Uri http://localhost:8080/api/users/admin `
  -Headers @{"Authorization"="Bearer $adminToken"} `
  -UseBasicParsing
# Expected: 200 with admin access message
```

### Step 6 — Stop Services

```powershell
# In the docker terminal, press Ctrl+C
# Or:
docker-compose down
```

### Troubleshooting

| Problem | Solution |
|---------|----------|
| "openssl not found" | Script auto-detects Git's OpenSSL. If fails, install Git for Windows |
| Docker build fails "mvnw not found" | Fixed — uses multi-stage Dockerfile with Maven image directly |
| curl/PowerShell syntax error | Use `-UseBasicParsing` with `Invoke-WebRequest`, or Git's `curl.exe` |
| Port 8080/8081/8082/6379 already in use | Stop other services: `docker ps`, `docker stop <id>` |
| "Connection refused" | Wait for all services to finish starting (~30-60 seconds first run) |
| Token revoked after re-login | You're using old token. Get fresh token from Step 3.2 |

## Module Structure

| Module | Port | Description |
|--------|------|-------------|
| `api-gateway/` | 8080 | Spring Cloud Gateway with 3 security filters |
| `auth-server/` | 8081 | Login/Register/Logout, RSA JWT signing |
| `internal-service/` | 8082 | Protected APIs behind gateway |
| Redis | 6379 | Token blacklist (Docker) |

## JWT Payload (Secure Payload Rule)

```json
{
  "sub": "user-uuid",          // user_id ONLY
  "scope": "ROLE_USER",       // roles ONLY
  "iat": 1686000000,
  "exp": 1686000900,
  "jti": "unique-token-id",
  "iss": "securegate-auth-server"
}
```

**Never in payload:** passwords, emails, PII, session tokens, internal IDs.

## Key Security Decisions

- **RSA 2048-bit** asymmetric signing (RS256)
- **PKCS#8** private key format for Java interoperability
- **Reactive Redis** (Lettuce) for non-blocking blacklist checks in Gateway
- **jti-based** blacklist: O(1) lookup, constant memory, auto-expires with TTL
- **Gateway → Internal**: X-User-Id/X-User-Scopes headers, never raw JWT
- **No direct internal access**: GatewayHeaderFilter rejects requests without X-User-Id

## References

- IEEE: "Enhancing Security in Data Exchange: Mitigating Risks & Solutions in Base64 Encoding and JSON Web Tokens"
- IEEE: "Research on API Security Gateway and Data Access Control Model for Multi-tenant Full-stack Systems"
