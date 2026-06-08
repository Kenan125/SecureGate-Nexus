# SecureGate Nexus

API Security Gateway with web dashboard — JWT authentication with RSA-256 asymmetric encryption, Redis-backed instant token revocation, proactive algorithm manipulation filter, and strict secure payload enforcement.

**Single-module monolithic Spring Boot application. Java 21. Requires Docker Redis.**

---

## Architecture

```
Browser ──▶ SecureGate Nexus (:8080)
              │
              ├── Static Pages:
              │   ├── /index.html      — auto-redirect (checks auth → /home.html or /login.html)
              │   ├── /login.html      — sign-in form
              │   ├── /register.html   — registration form
              │   └── /home.html       — dashboard (token lab, orders CRUD, console)
              │
              ├── Proactive Filter Chain:
              │   [1] AlgorithmValidationFilter  — blocks alg=none, HS256/384/512, missing alg
              │   [2] TokenBlacklistFilter       — Redis blacklist lookup by jti
              │   [3] JwtAuthFilter              — RSA-256 signature verify → SecurityContext
              │
              ├── /api/v1/auth/*      — register, login, logout, token (public + authenticated)
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
├── README.md
├── generate-keys.ps1                          # optional: pre-generate RSA keys (OpenSSL)
├── run.cmd                                    # one-click build+run
├── keys/
│   ├── private.pem                            # auto-generated at startup if missing
│   └── public.pem
├── src/main/resources/
│   ├── application.yml
│   └── static/
│       ├── index.html                         # auto-redirector
│       ├── login.html                         # sign-in page
│       ├── register.html                      # registration page
│       └── home.html                          # dashboard (token lab + orders CRUD)
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
    │   ├── AuthController.java                 # /api/v1/auth/{register,login,logout,token}
    │   ├── SecureDataController.java           # GET /api/v1/secure/data
    │   ├── OrderController.java                # CRUD /api/v1/orders
    │   └── UserController.java                 # GET /api/v1/users/{me,admin}
    ├── service/
    │   ├── AuthService.java                    # BCrypt auth, user store, token refresh
    │   ├── JwtService.java                     # RSA-256 JWT creation (Nimbus)
    │   └── TokenBlacklistService.java          # Redis StringRedisTemplate blacklist
    └── model/
        ├── LoginRequest.java
        ├── RegisterRequest.java                # username, password, email, role
        ├── TokenResponse.java
        ├── User.java                           # id, username, email, passwordHash, role
        ├── Order.java                          # orderId, userId, userName, product, quantity, status
        └── JwtPayload.java
```

**19 source files. 4 static pages.** Production-ready, no placeholders, no TODOs.

---

## Web Dashboard

Open `http://localhost:8080` in a browser after starting the application.

| Page | URL | Description |
|------|-----|-------------|
| Index | `/` or `/index.html` | Auto-detects session → redirects to `/home.html` or `/login.html` |
| Login | `/login.html` | Sign in with username/password. Supports `?registered=1` success banner |
| Register | `/register.html` | Create account (username, email, password). Redirects to login on success |
| Home | `/home.html` | Dashboard: generate tokens, attack lab (alg=none injection), orders CRUD, security console log |

**Auth flow:** Login → token stored in `sessionStorage` → all API calls use `Authorization: Bearer <token>` → sign out clears sessionStorage + revokes token in Redis.

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

### Step 3 — Open the Web Dashboard

Navigate to `http://localhost:8080` in your browser. Register an account, sign in, and explore the dashboard.

### Step 4 — Test via cURL

```powershell
# Register a user
curl.exe -s -X POST http://localhost:8080/api/v1/auth/register -H "Content-Type: application/json" -d "{\"username\":\"alice\",\"email\":\"alice@example.com\",\"password\":\"alice123456\"}"

# Login → copy the accessToken
curl.exe -s -X POST http://localhost:8080/api/v1/auth/login -H "Content-Type: application/json" -d "{\"username\":\"alice\",\"password\":\"alice123456\"}"

# Access secure data (paste real token)
curl.exe -s http://localhost:8080/api/v1/secure/data -H "Authorization: Bearer TOKEN"

# Logout → revoke token in Redis
curl.exe -s -X POST http://localhost:8080/api/v1/auth/logout -H "Authorization: Bearer TOKEN"

# Try again → BLOCKED!
curl.exe -s http://localhost:8080/api/v1/secure/data -H "Authorization: Bearer TOKEN"
# → {"error":"Security Alert: This token has been revoked. Please login again."}
```

---

## API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/v1/auth/register` | None | Register new user (username, email, password, role) |
| `POST` | `/api/v1/auth/login` | None | Login, returns JWT |
| `GET` | `/api/v1/auth/token` | Bearer | Refresh token for authenticated user |
| `POST` | `/api/v1/auth/logout` | Bearer | Revoke token in Redis |
| `GET` | `/api/v1/secure/data` | Bearer | Demo secure endpoint |
| `GET` | `/api/v1/users/me` | Bearer | Current user profile (userId, roles) |
| `GET` | `/api/v1/users/admin` | Bearer (ROLE_ADMIN) | Admin-only endpoint |
| `GET` | `/api/v1/orders` | Bearer | List user's orders |
| `POST` | `/api/v1/orders` | Bearer | Create order `{"product":"...","quantity":N}` |
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
| **Java 21** | LTS release, avoids Redis/Lettuce compatibility issues with newer versions |
| **RSA-256 (RS256)** | Asymmetric — private key signs, public key verifies. No shared secrets |
| **Nimbus JOSE+JWT** | Same library Spring Security uses internally for OAuth2/JWT |
| **Redis for blacklist** | Instant revocation, automatic TTL cleanup, survives app restart |
| **Proactive alg filter first** | Saves CPU — rejects bad tokens before expensive RSA verification |
| **Single module** | Maximum reliability, simple deployment, one `mvn` command |
| **sessionStorage auth** | Token stored per-tab in browser, sent via Authorization header — no cookies, no server-side sessions |
- **No raw JWT forwarding** -- JwtAuthFilter sets Spring Security context directly
- **20 files total** -- security logic, not infrastructure overhead

## References

- IEEE: "Enhancing Security in Data Exchange: Mitigating Risks & Solutions in Base64 Encoding and JSON Web Tokens"
- IEEE: "Research on API Security Gateway and Data Access Control Model for Multi-tenant Full-stack Systems"
