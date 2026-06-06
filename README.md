# SecureGate Nexus

API Security Gateway — JWT authentication with RSA-256 asymmetric encryption, Redis-backed instant token revocation, proactive algorithm manipulation filter, and strict secure payload enforcement.

**Single-module monolithic Spring Boot application. Java 21. Requires Docker Redis.**

---

## Architecture

```
Client ──▶ SecureGate Nexus (:8080)
              │
              ├── Proactive Filter Chain:
              │   [1] AlgorithmValidationFilter  — blocks alg=none, HS256/384/512, missing alg
              │   [2] TokenBlacklistFilter       — Redis blacklist lookup by jti
              │   [3] JwtAuthFilter              — RSA-256 signature verify → SecurityContext
              │
              ├── /api/v1/auth/*      — register, login, logout (public)
              ├── /api/v1/secure/data — protected demo endpoint
              ├── /api/v1/orders/*    — CRUD (authenticated)
              └── /api/v1/users/*     — profile, admin (authenticated)
                   │
Redis (:6379) ◀── token blacklist (jti → auto-expire by TTL)
```

---

## Project Structure

```
SecureGate Nexus/
├── pom.xml
├── application.yml
├── README.md
├── generate-keys.ps1                          # optional: pre-generate RSA keys (OpenSSL)
├── run.cmd                                    # one-click build+run
├── keys/
│   ├── private.pem                            # auto-generated at startup if missing
│   └── public.pem
└── src/main/java/com/securegate/
    ├── SecureGateApplication.java             # @SpringBootApplication
    ├── config/
    │   ├── RSAKeyConfig.java                  # 2048-bit RSA keypair auto-generation
    │   └── SecurityConfig.java                # Filter chain, CSRF disabled, STATELESS
    ├── filter/
    │   ├── AlgorithmValidationFilter.java      # [1] Proactive alg inspection
    │   ├── TokenBlacklistFilter.java           # [2] Redis jti revocation check
    │   └── JwtAuthFilter.java                  # [3] RSA signature verify + SecurityContext
    ├── controller/
    │   ├── AuthController.java                 # POST /api/v1/auth/{register,login,logout}
    │   ├── SecureDataController.java           # GET  /api/v1/secure/data
    │   ├── OrderController.java                # CRUD /api/v1/orders
    │   └── UserController.java                 # GET  /api/v1/users/{me,admin}
    ├── service/
    │   ├── AuthService.java                    # BCrypt auth, user store, login/logout
    │   ├── JwtService.java                     # RSA-256 JWT creation (Nimbus)
    │   └── TokenBlacklistService.java          # Redis StringRedisTemplate blacklist
    └── model/
        ├── LoginRequest.java
        ├── RegisterRequest.java
        ├── TokenResponse.java
        ├── User.java
        ├── Order.java
        └── JwtPayload.java
```

**19 source files.** Production-ready, no placeholders, no TODOs.

---

## 3 Security Innovations

| # | Innovation | Mechanism | Mitigates |
|---|-----------|-----------|-----------|
| 1 | **Instant Token Revocation** | Redis blacklist by `jti` with TTL matching token lifetime — checked by filter BEFORE authentication | Stateless JWT normally cannot be revoked after logout |
| 2 | **Algorithm Manipulation Filter** | Decodes JWT header, inspects `alg` parameter BEFORE signature verification — blocks `none`, HS256/384/512, missing alg | Algorithm Confusion Attack (CWE-347), none-algorithm bypass |
| 3 | **Secure Payload Rule** | JWT contains ONLY `sub` + `scope` + `iat` + `exp` + `jti` + `iss`. No usernames, emails, passwords, or PII | Base64 is encoding, NOT encryption — payload is public |

---

## Filter Chain Order

```
Request
  │
  ▼
[1] AlgorithmValidationFilter  @Order(-100)
    ├── No auth header + public path? → pass through
    ├── Decode JWT header, extract "alg"
    ├── alg = null/missing?   → 401  {"error":"Security Violation: Invalid or manipulated algorithm detected"}
    ├── alg = "none"?          → 401  (same)
    ├── alg = HS256/384/512?  → 401  (same)
    └── alg = RS256?          → pass to next filter
  │
  ▼
[2] TokenBlacklistFilter       @Order(-90)
    ├── Extract "jti" from JWT payload
    ├── Check Redis: EXISTS blacklist:<jti>?
    │   ├── YES → 401  {"error":"Security Alert: This token has been revoked. Please login again."}
    │   └── NO  → pass to next filter
  │
  ▼
[3] JwtAuthFilter              @Order(-80)
    ├── Verify RSA-256 signature with public key
    ├── Check exp (expiration)
    ├── Extract sub + scope (STRICT: no PII)
    └── Set Spring SecurityContext (UsernamePasswordAuthenticationToken)
  │
  ▼
Controller (authorized)
```

---

## Setup & Run

### Prerequisites

- **Java 21** (JDK)
- **Docker** (for Redis)

> ⚠️ **Windows folder naming:** Avoid parentheses `(1)` in your project path — they break `mvnw.cmd`. Use a simple folder name like `SecureGate-Nexus`.

### Step 1 — Start Redis

```powershell
docker run -d --name redis -p 6379:6379 redis:7-alpine
```

### Step 2 — Run the Application

```powershell
.\mvnw.cmd clean spring-boot:run
```

On first startup, RSA keys are auto-generated into `keys/private.pem` and `keys/public.pem`.
Wait for: `Started SecureGateApplication in X seconds`

### Step 3 — Test the Full Flow

```powershell
# Register a user
curl.exe -s -X POST http://localhost:8080/api/v1/auth/register -H "Content-Type: application/json" --% -d "{\"username\":\"alice\",\"password\":\"alice123456\"}"

# Login → copy the accessToken
curl.exe -s -X POST http://localhost:8080/api/v1/auth/login -H "Content-Type: application/json" --% -d "{\"username\":\"alice\",\"password\":\"alice123456\"}"

# Access secure data (paste real token)
curl.exe -s http://localhost:8080/api/v1/secure/data -H "Authorization: Bearer TOKEN"

# Logout → revoke token in Redis
curl.exe -s -X POST http://localhost:8080/api/v1/auth/logout -H "Authorization: Bearer TOKEN"

# Try again → BLOCKED!
curl.exe -s http://localhost:8080/api/v1/secure/data -H "Authorization: Bearer TOKEN"
# → {"error":"Security Alert: This token has been revoked. Please login again."}
```

---

## Postman Guide

### Step 1 — Create a Postman Environment

1. Open Postman → **Environments** (left sidebar) → **Create Environment**
2. Name it `SecureGate Nexus Local`
3. Add these variables:

| Variable | Type | Initial Value | Current Value |
|----------|------|---------------|---------------|
| `baseUrl` | default | `http://localhost:8080` | `http://localhost:8080` |
| `token` | default | *(leave empty)* | *(leave empty)* |

4. Click **Save**, then select this environment from the dropdown (top-right).

---

### Step 2 — Register a User

| Field | Value |
|-------|-------|
| **Method** | `POST` |
| **URL** | `{{baseUrl}}/api/v1/auth/register` |
| **Headers** | `Content-Type`: `application/json` |
| **Body** (raw JSON) | See below |

```json
{
    "username": "alice",
    "password": "alice123456"
}
```

**Expected response** (201 Created):
```json
{
    "message": "User registered successfully",
    "userId": "0840e33e-8332-46be-b623-ed28798e1d14",
    "username": "alice"
}
```

> 💡 To register as admin, add `"role": "ROLE_ADMIN"` to the body.

---

### Step 3 — Login & Save Token

| Field | Value |
|-------|-------|
| **Method** | `POST` |
| **URL** | `{{baseUrl}}/api/v1/auth/login` |
| **Headers** | `Content-Type`: `application/json` |
| **Body** (raw JSON) | Same as register |

**Expected response** (200 OK):
```json
{
    "accessToken": "eyJhbGciOiJSUzI1NiJ9.eyJpc3Mi...",
    "tokenType": "Bearer",
    "expiresIn": 900
}
```

#### Auto-save the token with Postman Script

In the **Tests** tab of the login request, paste:

```javascript
var json = pm.response.json();
pm.environment.set("token", json.accessToken);
```

Now every request that needs auth will automatically use the latest token.

---

### Step 4 — Access Secure Data

| Field | Value |
|-------|-------|
| **Method** | `GET` |
| **URL** | `{{baseUrl}}/api/v1/secure/data` |
| **Headers** | `Authorization`: `Bearer {{token}}` |

**Expected response** (200 OK):
```json
{
    "message": "You have accessed secure data successfully!",
    "authenticatedUser": "0840e33e-8332-46be-b623-ed28798e1d14",
    "authorities": ["ROLE_USER"],
    "timestamp": "2026-06-06T20:29:29.775135700Z",
    "data": {
        "secretCode": "SGX-2026-SECURE",
        "clearance": "LEVEL-4",
        "vaultStatus": "SEALED"
    }
}
```

---

### Step 5 — Logout (Revoke Token)

| Field | Value |
|-------|-------|
| **Method** | `POST` |
| **URL** | `{{baseUrl}}/api/v1/auth/logout` |
| **Headers** | `Authorization`: `Bearer {{token}}` |

**Expected response** (200 OK):
```json
{
    "message": "Logged out successfully. Token revoked.",
    "jti": "883b6dfa-27c6-4dbf-93b1-295eac10ce29"
}
```

---

### Step 6 — Verify Revocation (Same Token → Blocked)

Run **Step 4** again with the same token.

**Expected response** (401 Unauthorized):
```json
{
    "error": "Security Alert: This token has been revoked. Please login again."
}
```

---

### Step 7 — Test Algorithm Attack (Manual)

| Field | Value |
|-------|-------|
| **Method** | `GET` |
| **URL** | `{{baseUrl}}/api/v1/secure/data` |
| **Headers** | `Authorization`: `Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ.abc` |

**Expected response** (401 Unauthorized):
```json
{
    "error": "Security Violation: Invalid or manipulated algorithm detected"
}
```

---

### All Requests at a Glance

| # | Method | URL | Headers | Body | Auth |
|---|--------|-----|---------|------|------|
| 1 | `POST` | `{{baseUrl}}/api/v1/auth/register` | `Content-Type: application/json` | `{"username":"alice","password":"alice123456"}` | None |
| 2 | `POST` | `{{baseUrl}}/api/v1/auth/login` | `Content-Type: application/json` | `{"username":"alice","password":"alice123456"}` | None |
| 3 | `GET` | `{{baseUrl}}/api/v1/secure/data` | `Authorization: Bearer {{token}}` | — | JWT |
| 4 | `POST` | `{{baseUrl}}/api/v1/auth/logout` | `Authorization: Bearer {{token}}` | — | JWT |
| 5 | `GET` | `{{baseUrl}}/api/v1/users/me` | `Authorization: Bearer {{token}}` | — | JWT |
| 6 | `GET` | `{{baseUrl}}/api/v1/users/admin` | `Authorization: Bearer {{token}}` | — | JWT (ROLE_ADMIN) |
| 7 | `GET` | `{{baseUrl}}/api/v1/orders` | `Authorization: Bearer {{token}}` | — | JWT |
| 8 | `POST` | `{{baseUrl}}/api/v1/orders` | `Content-Type: application/json` + `Authorization: Bearer {{token}}` | `{"product":"Widget","quantity":5}` | JWT |
| 9 | `DELETE` | `{{baseUrl}}/api/v1/orders/{id}` | `Authorization: Bearer {{token}}` | — | JWT |

---

## API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/v1/auth/register` | None | Register new user |
| `POST` | `/api/v1/auth/login` | None | Login, returns JWT |
| `POST` | `/api/v1/auth/logout` | Bearer | Revoke token in Redis |
| `GET` | `/api/v1/secure/data` | Bearer | Demo secure endpoint |
| `GET` | `/api/v1/users/me` | Bearer | Current user profile |
| `GET` | `/api/v1/users/admin` | Bearer (ROLE_ADMIN) | Admin-only endpoint |
| `GET` | `/api/v1/orders` | Bearer | List user's orders |
| `POST` | `/api/v1/orders` | Bearer | Create order |
| `GET` | `/api/v1/orders/{id}` | Bearer | Get order by ID |
| `DELETE` | `/api/v1/orders/{id}` | Bearer | Delete order |

---

## JWT Payload (Strict Payload Rule)

```json
{
  "sub": "0840e33e-8332-46be-b623-ed28798e1d14",
  "scope": "ROLE_USER",
  "iat": 1780777726,
  "exp": 1780778626,
  "jti": "883b6dfa-27c6-4dbf-93b1-295eac10ce29",
  "iss": "securegate-nexus"
}
```

**Never included:** usernames, emails, passwords, personal data. Base64 is encoding, not encryption.

---

## Configuration

All settings in `src/main/resources/application.yml`:

```yaml
server:
  port: 8080

spring:
  data:
    redis:
      host: localhost
      port: 6379

jwt:
  keys-dir: keys
  access-token-expiry: 900       # seconds (15 minutes)
  issuer: securegate-nexus
```

---

## Security Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Java 21** | LTS release, avoids Redis/Lettuce compatibility issues with Java 25 |
| **RSA-256 (RS256)** | Asymmetric — private key signs, public key verifies. No shared secrets |
| **Nimbus JOSE+JWT** | Same library Spring Security uses internally for OAuth2/JWT |
| **Redis for blacklist** | Instant revocation, automatic TTL cleanup, survives app restart |
| **Proactive alg filter first** | Saves CPU — rejects bad tokens before expensive RSA verification |
| **Single module** | Maximum reliability, simple deployment, one `mvn` command |
```

## Key Design Decisions

- **RSA 2048-bit** RS256 asymmetric signing -- private key signs, public key verifies
- **jti-based blacklist** -- O(1) in-memory lookup per request, auto-expires with token TTL
- **Pure Java** -- no native binaries, no database, works on any OS with Java 25
- **No raw JWT forwarding** -- JwtAuthFilter sets Spring Security context directly
- **20 files total** -- security logic, not infrastructure overhead

## References

- IEEE: "Enhancing Security in Data Exchange: Mitigating Risks & Solutions in Base64 Encoding and JSON Web Tokens"
- IEEE: "Research on API Security Gateway and Data Access Control Model for Multi-tenant Full-stack Systems"
