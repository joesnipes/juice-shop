# Threat Model — OWASP Juice Shop

- **Repository:** `juice-shop` (treated as a real production e-commerce / B2B application for this exercise)
- **Threat model version:** 1.0.0
- **Generated:** 2026-05-11
- **Methodology:** STRIDE + attack-surface enumeration + data-flow analysis
- **Scope:** All source under `routes/`, `lib/`, `models/`, `data/`, `server.ts`, `app.ts`, `frontend/`, configuration files, static assets, and accompanying CI/CD assets.

> NOTE FOR REVIEWERS: Although Juice Shop is publicly known as an intentionally vulnerable training application, this threat model treats the codebase exactly as if it were a real production e-commerce platform handling real customers, payments, and B2B partners. Findings should be treated as legitimate security risks, not as "intentional features."

---

## 1. System Overview

OWASP Juice Shop is a Node.js / TypeScript monolithic web application that operates as a **B2C e-commerce site with a B2B order ingestion API**. It uses an Angular single-page frontend served as static assets, an Express HTTP backend, dual datastores (SQLite via Sequelize for relational data, MarsDB for document data — reviews/orders), a Socket.IO real-time channel, an in-process chatbot, a Web3 / Ethereum integration, and various ancillary file-serving endpoints (FTP-style browsing, log file browsing, encryption-key browsing, Swagger UI, Prometheus metrics).

### 1.1 Tech Stack

| Layer            | Technology                                                                                                            |
| ---------------- | --------------------------------------------------------------------------------------------------------------------- |
| Runtime          | Node.js 20–24, TypeScript 5                                                                                           |
| HTTP server      | Express 4.22, http (no TLS termination in-app)                                                                        |
| Auth             | Custom RSA-signed JWT (`jsonwebtoken@0.4.0` — extremely old, `express-jwt@0.1.3` — extremely old), MD5 password hashes, optional TOTP (`otplib`) |
| Relational DB    | SQLite (`sqlite3`) via Sequelize 6                                                                                    |
| Document DB      | MarsDB (in-process Mongo-like store) for `reviews` and `orders`                                                       |
| Realtime         | Socket.IO 3.1 (CORS hard-coded to `http://localhost:4200`)                                                            |
| File processing  | `multer`, `unzipper@0.9.15`, `libxmljs2`, `js-yaml@3.x`, `pdfkit`, `notevil`, `vm` sandbox                             |
| Templating       | `hbs`, `pug` (used dynamically with user input in `userProfile.ts`)                                                   |
| Auto REST        | `finale-rest` — auto-CRUD over Sequelize models (`/api/Users`, `/api/Products`, `/api/Feedbacks`, etc.)               |
| Search           | Raw string-interpolated SQL (`models.sequelize.query` in `routes/search.ts` and `routes/login.ts`)                    |
| Web3             | `ethers@6`, `web3@4` — Sepolia testnet contract listener                                                              |
| Chatbot          | `juicy-chat-bot` — uses `factory.run()` (string evaluation) on user-derived input                                     |
| Metrics          | `prom-client` exposed at `GET /metrics` with no auth                                                                  |
| Logging          | `morgan` combined logs → `logs/access.log.YYYY-MM-DD` (browseable at `/support/logs`)                                 |
| Frontend         | Angular SPA served from `frontend/dist/frontend` via `express.static`                                                 |

### 1.2 Component Diagram (logical)

```
                ┌──────────────────────────────────────────────────┐
                │                External Internet                 │
                └──────────────────────────────────────────────────┘
                  │              │             │            │
        Browser (Angular SPA)  B2B clients  Crawlers/bots  Web3 wallets
                  │              │             │            │
                  ▼              ▼             ▼            ▼
        ╔══════════════════════════════════════════════════════════╗
        ║  Express HTTP server  (server.ts — single trust boundary) ║
        ╠══════════════════════════════════════════════════════════╣
        ║ Public (no auth):                                         ║
        ║   /, /api/Products (GET), /api/Feedbacks (POST/GET),      ║
        ║   /rest/user/login, /rest/user/reset-password,            ║
        ║   /rest/products/search, /rest/products/:id/reviews,      ║
        ║   /rest/track-order/:id, /rest/captcha, /api/Challenges,  ║
        ║   /api/SecurityQuestions, /metrics, /api-docs,            ║
        ║   /ftp/*, /encryptionkeys/*, /support/logs/*,             ║
        ║   /redirect, /promotion, /video, /snippets/*              ║
        ║                                                           ║
        ║ Authenticated (JWT in Authorization or cookie):           ║
        ║   /rest/basket/:id, /api/BasketItems, /api/Users (GET),   ║
        ║   /rest/wallet/*, /rest/user/data-export, /profile,       ║
        ║   /rest/2fa/*, /api/PrivacyRequests, /api/Cards,          ║
        ║   /api/Addresss, /b2b/v2/orders, /rest/chatbot/*,         ║
        ║   /rest/products/reviews (PATCH/POST)                     ║
        ║                                                           ║
        ║ Role-gated (accounting):                                  ║
        ║   /rest/order-history/orders,                             ║
        ║   /rest/order-history/:id/delivery-status,                ║
        ║   /api/Quantitys/:id   (also IP-allowlisted to a single   ║
        ║                          unreachable address)             ║
        ╚══════════════════════════════════════════════════════════╝
                  │                       │                │
                  ▼                       ▼                ▼
        ┌──────────────────┐   ┌────────────────────┐  ┌────────────────────┐
        │  SQLite (Sequel- │   │ MarsDB (in-proc.)  │  │  Filesystem        │
        │  ize) – Users,   │   │ reviews, orders    │  │  /ftp, /uploads,   │
        │  Products,       │   │ (No-SQL via        │  │  /encryptionkeys,  │
        │  Wallets, Cards, │   │  $where: this.x)   │  │  /logs, /frontend  │
        │  Addresses, …    │   │                    │  │   (writable)       │
        └──────────────────┘   └────────────────────┘  └────────────────────┘
                  │
                  ▼
        ┌──────────────────────────────────────────────────────────┐
        │ External services / network egress (NO ALLOWLIST):       │
        │   • Arbitrary `fetch()` of user-supplied URL             │
        │     (profileImageUrlUpload, chatbot trainingData)        │
        │   • Ethereum Sepolia via Alchemy WebSocket (hard-coded   │
        │     API key in routes/web3Wallet.ts)                     │
        │   • Google OAuth                                         │
        └──────────────────────────────────────────────────────────┘
                                  ▲
                                  │
                          Socket.IO clients
                          (CORS limited to http://localhost:4200 only —
                           ignored by non-browser clients)
```

### 1.3 Entry Points (attack surface inventory)

| Type            | Path                                                  | Auth                   | Notes                                                                                  |
| --------------- | ----------------------------------------------------- | ---------------------- | -------------------------------------------------------------------------------------- |
| HTML/static     | `/*` (Angular)                                        | None                   | SPA shell; routes mounted under `app.use(express.static(...))`                         |
| REST custom     | `POST /rest/user/login`                               | None                   | **Raw SQL string interpolation** of `email` and `password` (`routes/login.ts:34`)      |
| REST custom     | `POST /rest/user/reset-password`                      | None                   | Rate-limited by `X-Forwarded-For` header (spoofable); weak security-question scheme    |
| REST custom     | `GET /rest/user/change-password`                      | Token from header      | Accepts new password via **query string**, no current-password requirement enforced if not provided |
| REST custom     | `GET /rest/products/search?q=`                        | None                   | **Raw SQL string interpolation**, classic UNION-based SQLi (`routes/search.ts:23`)     |
| REST custom     | `GET /rest/track-order/:id`                           | None                   | **NoSQL `$where` JS injection** (`routes/trackOrder.ts:18`)                            |
| REST custom     | `GET /rest/products/:id/reviews`                      | None                   | **NoSQL `$where` JS injection** (`routes/showProductReviews.ts:36`)                    |
| REST custom     | `PATCH /rest/products/reviews`                        | JWT                    | **Mass-assignment NoSQL** — body `{id, message}` used directly as filter with `multi:true` |
| REST custom     | `PUT /rest/products/:id/reviews`                      | None *(per server.ts)* | Author taken from body, not token (forged review)                                      |
| REST custom     | `POST /rest/basket/:id/checkout`                      | JWT                    | Uses `req.body.UserId` (client-controlled) for wallet decrement                        |
| REST custom     | `PUT /rest/basket/:id/coupon/:coupon`                 | JWT (via `/rest/basket`) | Decodes coupon with weak HMAC/z85 encoding                                            |
| REST custom     | `GET /rest/basket/:id`                                | JWT                    | **IDOR** — `id` taken from URL, not from token                                         |
| REST custom     | `GET /rest/wallet/balance`, `PUT /rest/wallet/balance` | JWT                   | `req.body.UserId` is client-supplied (set by `appendUserId()`, but easily overridden)  |
| REST custom     | `POST /rest/user/data-export`                         | JWT                    | Trusts `req.body.UserId` to look up memories (cross-tenant leak risk)                  |
| REST custom     | `POST /rest/chatbot/respond`                          | JWT                    | Body `req.body.query` passed to `bot.factory.run()` — string eval primitive            |
| REST custom     | `POST /b2b/v2/orders`                                 | JWT                    | Executes `safeEval(orderLinesData)` from `notevil` — known sandbox escapes             |
| File upload     | `POST /file-upload`                                   | None                   | Accepts ZIP / XML / YAML; XML parsed with `noent:true` (XXE), YAML loaded unsafely     |
| File upload     | `POST /profile/image/file`                            | None middleware        | Disk-stored under predictable filename derived from token user id                      |
| File upload     | `POST /profile/image/url`                             | None middleware        | **SSRF** — server `fetch()`es arbitrary URL, writes response to disk                   |
| File upload     | `POST /rest/memories`                                 | JWT (`appendUserId`)   | Image upload, mime filter only                                                          |
| Browse / static | `GET /ftp/*`, `GET /ftp/quarantine/*`                 | None                   | Public **directory listing** + arbitrary file download (filtered to `.md`/`.pdf` with poison null byte issue) |
| Browse / static | `GET /encryptionkeys/*`                               | None                   | Directory listing of RSA keypairs and other secrets                                    |
| Browse / static | `GET /support/logs/*`                                 | None                   | Directory listing of access logs (PII / token leakage)                                 |
| Browse / static | `GET /.well-known/*`                                  | None                   | Browseable                                                                             |
| Docs            | `GET /api-docs`                                        | None                   | Swagger UI for B2B API                                                                 |
| Metrics         | `GET /metrics`                                        | None                   | Full Prometheus metrics exposed                                                        |
| Config          | `GET /rest/admin/application-configuration`           | None                   | **Returns entire `config` object** (`routes/appConfiguration.ts`)                      |
| Redirect        | `GET /redirect?to=`                                   | None                   | Allowlist uses `String.includes()` — bypassable                                        |
| Profile         | `GET /profile`                                        | Cookie                 | Pug template **dynamically compiled with user-controlled username**; SSTI via `#{...}` |
| Profile         | `POST /profile`                                       | Cookie                 | No CSRF token (the app specifically detects CSRF via `Origin/Referer` match)           |
| Auto-REST       | `GET/POST/PUT/DELETE /api/<Model>s/:id`               | Mixed (see below)      | Auto-CRUD via `finale-rest` — every Sequelize model is exposed                         |
| Web3            | `POST /rest/web3/submitKey`                           | None                   | Triggers NFT challenge unlock                                                          |
| Web3            | `POST /rest/web3/walletNFTVerify` / `walletExploitAddress` | None              | Calls into Ethereum via hard-coded Alchemy WSS endpoint and API key                    |
| Socket.IO       | `ws://host/socket.io`                                 | None                   | Server-pushed notifications; clients can emit `verifyLocalXssChallenge`, etc.          |
| CLI / startup   | `lib/startup/customizeApplication`, `customizeEasterEgg` | n/a                | Fetches/applies remote files on boot                                                   |

---

## 2. Trust Boundaries

There are **only two effective trust boundaries** in the deployed system:

### 2.1 Boundary A — Internet ↔ Express process (the main one)
- All HTTP, Socket.IO, and B2B traffic crosses this boundary.
- Mediated by: `helmet.noSniff()`, `helmet.frameguard()`, `compression()`, `cors()` (wide-open: `app.use(cors())`), `bodyParser` (URL-encoded *and* `text/*` then re-parsed as JSON), `morgan` access log, an aggressive **URL slash-collapse middleware** (`req.url = req.url.replace(/[/]+/g, '/')`) that itself can produce parser-confusion vulnerabilities, and `expressJwt({secret: publicKey})`.
- `helmet.xssFilter()` is **explicitly disabled** with the comment "no protection from persisted XSS via RESTful API" — this is a real-world deployment risk and not just a training artifact.
- CORS is wide open (`app.use(cors())` with no options) — every origin is allowed with credentials by default in `cors` v2. Socket.IO CORS is hard-coded to `http://localhost:4200`, an obvious dev leftover.
- `x-powered-by` is disabled, but `X-Recruiting` is added (information disclosure, low impact).

### 2.2 Boundary B — Express process ↔ Local filesystem & external services
- The same Node process reads/writes to `ftp/`, `uploads/`, `frontend/dist/...`, `logs/`, `encryptionkeys/`, and `data/chatbot/`. There is **no separation of privilege**: the same OS user reads RSA private keys, writes uploaded files, and serves them back.
- The process can make **arbitrary outbound HTTP** (`profileImageUrlUpload`, chatbot `download(trainingFile)`, `customizeApplication`) — no egress allowlist.
- The process can open arbitrary websocket connections (`web3Wallet.ts` → Alchemy Sepolia).

### 2.3 Internal "soft" boundaries (within the process, not security-enforced)
- Role separation: `customer`, `deluxe`, `accounting`, `admin`. Enforced only by:
  - `security.isAuthorized()` — checks JWT signature with the **public** key but accepts the `none` algorithm in some paths (via the very old `express-jwt@0.1.3`, see `package.json`).
  - `security.isAccounting()` — manually decodes JWT and checks `decodedToken.data.role`.
  - `security.isDeluxe()` — same approach plus an HMAC over `email + 'deluxe'` using the **JWT private key as the HMAC secret** (a key-reuse antipattern).
  - `security.denyAll()` — issues a fresh-random `expressJwt` secret per request (`secret: '' + Math.random()`), but the request only fails if a token is *present*; **anonymous requests with no token bypass `denyAll`** in some versions of `express-jwt`. This should be verified by the auditor.
- Per-user data scoping is achieved by `security.appendUserId()` injecting `req.body.UserId` from the token map. Because handlers then read `req.body.UserId` rather than the token directly, any client that supplies its own `UserId` via JSON body on a request *without* `appendUserId()` in front of it bypasses the check.

---

## 3. Data Flows & Sensitive Data Handling

### 3.1 Sensitive data inventory

| Category | Where stored | At-rest protection |
| -------- | ------------ | ------------------ |
| User credentials (email + password) | `Users` table (SQLite) | **MD5 unsalted hash** (`lib/insecurity.ts:43`). Trivially crackable with rainbow tables / GPU. |
| Password-reset answers              | `SecurityAnswers` table | HMAC-SHA256 with **hard-coded shared secret** `'pa4qacea4VK9t9nGv7yZtwmj'` (`insecurity.ts:44`). All deployments share the same key. |
| JWT signing key                     | `encryptionkeys/jwt.pub` and **hard-coded in `insecurity.ts:23`** | RSA-1024 (too short by current NIST guidance), private key checked into source code, also browseable at `/encryptionkeys/`. |
| TOTP secret                         | `Users.totpSecret`     | Plaintext. Excluded from `/api/Users` GET via `finale` `excludeAttributes`, but accessible via direct SQLi or via `user.update()` paths. |
| Payment cards                       | `Cards` table          | Stored in plaintext (no PAN tokenization). |
| Addresses                           | `Addresses` table      | Plaintext. |
| Orders & reviews                    | MarsDB (in-process)    | Email partially obfuscated (`replace(/[aeiou]/gi,'*')`) in `orders` — **reversible / minimal entropy reduction**. |
| Wallet balances                     | `Wallets` table        | Plaintext integer; updated based on `req.body.UserId`. |
| Access logs (with tokens, IPs)      | `logs/access.log.*`    | Plaintext, **publicly browseable at `/support/logs/`**. |
| Chatbot training data               | `data/chatbot/*.json`  | Overwritten on startup by `download()` of `application.chatBot.trainingData` if it's a URL — RCE-by-config primitive. |
| Premium content key                 | `encryptionkeys/premium.key` | Browseable. |
| CTF key (`ctf.key`)                 | Repo root              | Checked in to the repo. |

### 3.2 Key data flows

1. **Login flow** — Browser → `POST /rest/user/login` → `models.sequelize.query("SELECT * FROM Users WHERE email = '${email}' AND password = '${md5(password)}' …")` → MD5 compare → JWT issued (`RS256`, 6h expiry) → in-memory `authenticatedUsers.tokenMap` (lost on restart). **Two distinct issues**: SQLi in `email`/`password`, and the in-memory session map means `appendUserId()` silently fails after a restart for valid tokens.

2. **Search flow** — Browser → `GET /rest/products/search?q=` → string-interpolated SQL → returns full row including translation flags. UNION-based extraction of `Users` and `sqlite_master` is detected as a CTF challenge but is a real exploit.

3. **Order placement** — Browser → `POST /rest/basket/:id/checkout` → reads `BasketModel` by id (no ownership check), generates PDF written to **public `ftp/` directory** with a name derived from `hash(email).slice(0,4)` (4 hex chars = 65k namespace; predictable order IDs), then writes order to MarsDB with the email partially masked but everything else cleartext.

4. **Profile image (URL)** — Browser → `POST /profile/image/url` with `imageUrl=<any URL>` → server performs `fetch(url)` → response stream piped to local file under `frontend/dist/frontend/assets/public/images/uploads/<userId>.<ext>` → DB row updated. On error, the raw URL string is saved as the profile image (`profileImage: url`), causing **stored XSS / open-redirect / phishing payloads** to be returned in every profile response and re-rendered in `getUserProfile` via `pug.compile`.

5. **Profile page render** — Browser → `GET /profile` → loads Pug template from disk → string-replaces `_username_` with the user-controlled username — if the username matches `#{...}`, the inner string is run through `eval()` (`routes/userProfile.ts:62`). The page is then compiled with `pug.compile(template)`. Both the `eval` and the dynamic Pug compilation are SSTI/RCE primitives.

6. **B2B order** — B2B client → `POST /b2b/v2/orders` with `orderLinesData` (string) → `safeEval(orderLinesData)` (the `notevil` library). `notevil` has historically had sandbox escapes; even without an escape, infinite loops cause DoS (`rceOccupyChallenge`).

7. **Chatbot** — Browser → `POST /rest/chatbot/respond` → `bot.factory.run("currentUser('${user.id}')")` and `bot.respond(req.body.query, user.id)` — `juicy-chat-bot` internally uses a state-machine evaluator over training data; the user's *name* and *query* both flow into evaluation contexts, plus dispatch of `botUtils[response.handler]` allows arbitrary key lookup of exported functions.

8. **File upload (ZIP)** — `POST /file-upload` → `unzipper@0.9.15` (old, has had path-traversal advisories) → entries written to `uploads/complaints/<fileName>`. The protection is `if (absolutePath.includes(path.resolve('.')))`, which is a substring check (not a `startsWith` check) and can be bypassed with crafted names that contain the project root anywhere in their resolved path.

9. **Redirect** — Browser → `GET /redirect?to=<url>` → `isRedirectAllowed` does `allowed = allowed || url.includes(allowedUrl)` — anyone with a URL like `https://attacker.example/?x=https://github.com/juice-shop/juice-shop` satisfies the check. Open redirect → phishing.

10. **Socket.IO** — Connected browser receives all challenge-solved notifications and can emit `verifyLocalXssChallenge` etc. CORS is hard-coded to `http://localhost:4200`, but **Socket.IO CORS does not apply to non-browser clients**, so attackers can connect from any tool.

11. **Metrics scrape** — Any unauthenticated client → `GET /metrics` → Prometheus exposition of internal counters (request counts per route, file-upload sizes, error rates). Useful for reconnaissance and timing attacks.

12. **Config disclosure** — Browser → `GET /rest/admin/application-configuration` (no auth) → entire `node-config` object including OAuth client IDs, social URLs, internal switches, possibly secrets if added in future.

---

## 4. Authentication & Authorization Mechanisms (in detail)

### 4.1 Authentication
- **Primary credential**: email + password. Password hashed with **MD5, no salt, no pepper** (`security.hash`). Cracking the entire user table from a database dump is trivial.
- **Session**: stateless JWT (`RS256`, 6 h expiry). However, the server *also* maintains an in-memory `authenticatedUsers.tokenMap` and many handlers (`changePassword`, `updateUserProfile`, `dataExport`, `getUserProfile`) trust this map rather than re-verifying the JWT. After a restart, **valid tokens are silently treated as logged-out** — and conversely, a token can be artificially "registered" if any code path calls `authenticatedUsers.put()` without re-verifying it.
- **JWT private key is hard-coded** in `lib/insecurity.ts:23` and also stored in `encryptionkeys/jwt.key` (the directory is browseable). Anyone with read access to the repo or `/encryptionkeys/` can mint arbitrary admin tokens.
- **`express-jwt` is pinned to `0.1.3`** (from 2015) — vulnerable to the classic `alg:none` confusion (CVE-2015-9235). `verify.jwtChallenges()` actively *checks for* this in incoming tokens, confirming the exposure.
- `jsonwebtoken@0.4.0` is similarly ancient and likely vulnerable to algorithm confusion.
- **2FA** uses `otplib` with a `window: 1` (acceptable). The TOTP secret is stored in plaintext in the DB. The setup token reuses the application JWT signing key — anyone who can mint a JWT can mint a setup token of any user.
- **OAuth (Google)**: only client ID configured; full OAuth flow handled in frontend with a long list of authorized redirects (`config/default.yml`) some of which are HTTP (`http://192.168.99.100:3000`) — these should be removed in any non-training deployment.

### 4.2 Authorization
- Authorization decisions rely on `req.body.UserId`, which is set by `appendUserId()` only when the middleware is applied. Several handlers (`getWalletBalance`, `addWalletBalance`, `dataExport`, `getAddress*`, `delAddressById`) do not re-derive the user from the token — they trust the body. A client can substitute the value for **any other user's ID** on requests that don't have `appendUserId` applied (or on requests that have both `appendUserId` and a body with explicit `UserId`, depending on body-parser ordering).
- `finale-rest` exposes auto-CRUD for every model. The guards in `server.ts` block specific verbs per route, but the route table is large and partly commented out (`// app.put('/api/Products/:id', security.isAuthorized())` — Product edits are entirely unauthenticated). **`GET /api/Users/:id` is `isAuthorized()` only — any logged-in user can read any other user's profile (including hashed password) unless `excludeAttributes` catches the field.** The exclusion is `['password','totpSecret']` for `User`, which protects only those two — `email`, `role`, `deluxeToken`, `lastLoginIp` etc. are still returned. `deluxeToken` is sensitive because it can be replayed.
- Role checks (`isAccounting`, `isDeluxe`) parse the JWT manually and key off `decoded.data.role`. Because `data` originates from a `RS256`-signed token, this is secure *if* the signing key remains secret. But (a) the key is in the repo, and (b) `express-jwt@0.1.3` accepts `alg: none`, making forgery trivial.
- The `/api/Quantitys/:id` endpoint is guarded by `IpFilter(['123.456.789'], { mode: 'allow' })` — the address is invalid; the filter effectively denies everyone *or* allows everyone depending on `express-ipfilter`'s parsing — needs review.
- The recycle item endpoint runs `JSON.parse(req.params.id)` and passes the result directly into a Sequelize `where` clause — **server-side request-body injection into ORM** (e.g., `id` = `{"$gt":0}` style payloads, NoSQL-injection-equivalent through Sequelize operators).

---

## 5. STRIDE Threat Analysis

Severity scale: **CRITICAL** (RCE, full account takeover, mass data theft), **HIGH** (privilege escalation, IDOR, persistent XSS, sensitive data leak), **MEDIUM** (DoS, info disclosure, reflected XSS), **LOW** (best-practice/hardening misses).

### 5.1 Spoofing Identity

| ID  | Threat                                                                                                                  | Affected components                                                            | Severity |
| --- | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ | -------- |
| S-1 | **JWT forgery via `alg: none`** — `express-jwt@0.1.3` accepts unsigned tokens; attacker forges admin token.             | `lib/insecurity.ts`, all `isAuthorized`-protected routes                       | CRITICAL |
| S-2 | **JWT signing key disclosure** — RSA private key is hard-coded in `lib/insecurity.ts:23` and lives in browseable `/encryptionkeys/`. | `lib/insecurity.ts`, `routes/keyServer.ts`                                | CRITICAL |
| S-3 | **JWT algorithm confusion (HS256 vs RS256)** — verifier uses `publicKey` as both verification key and as HMAC secret if HS256 is forced. | `lib/insecurity.ts:isAuthorized`, `routes/verify.ts:jwtChallenges`        | CRITICAL |
| S-4 | **MD5 password hashes** — a single DB exfil yields plaintext passwords; credential stuffing on the live site.           | `lib/insecurity.ts:hash`, `models/user.ts`                                     | CRITICAL |
| S-5 | **`req.body.UserId` trust** — endpoints accept user ID from request body; any authenticated user can act as any other. | `routes/wallet.ts`, `routes/dataExport.ts`, `routes/address.ts`, `routes/order.ts:140`, `routes/deluxe.ts` | HIGH     |
| S-6 | **Reset-password rate limit keyed off `X-Forwarded-For`** — easily bypassable behind any proxy or directly with spoofed header. | `server.ts:343-347`                                                       | HIGH     |
| S-7 | **Login SQLi enables auth bypass** — `' OR 1=1--` style payload returns first user (typically `admin`).                  | `routes/login.ts:34`                                                            | CRITICAL |
| S-8 | **Forged review author** — `createProductReviews` saves `req.body.author` rather than the authenticated email.           | `routes/createProductReviews.ts`                                                | MEDIUM   |
| S-9 | **Socket.IO origin spoofing** — server-pushed notifications and `verify*Challenge` events accessible from any non-browser client. | `lib/startup/registerWebsocketEvents.ts`                                  | MEDIUM   |
| S-10| **Hard-coded HMAC secret for security answers**: `pa4qacea4VK9t9nGv7yZtwmj` — an attacker who learns the secret (it's in the public repo) can compute any user's expected HMAC. | `lib/insecurity.ts:hmac`, `routes/resetPassword.ts`                       | HIGH     |
| S-11| **Deluxe HMAC re-uses the JWT private key as HMAC secret** (`deluxeToken`).                                              | `lib/insecurity.ts:deluxeToken`                                                 | MEDIUM   |

### 5.2 Tampering with Data

| ID  | Threat                                                                                                                 | Affected components                                                              | Severity |
| --- | ---------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | -------- |
| T-1 | **SQL injection (UNION)** in product search.                                                                            | `routes/search.ts:23`                                                            | CRITICAL |
| T-2 | **SQL injection in login** (also a spoofing primitive, S-7).                                                            | `routes/login.ts:34`                                                             | CRITICAL |
| T-3 | **NoSQL injection (`$where`)** in track-order and product-reviews — server-side JS execution against MarsDB.            | `routes/trackOrder.ts:18`, `routes/showProductReviews.ts:36`                     | HIGH     |
| T-4 | **NoSQL mass update** — `updateProductReviews` runs `{multi:true}` with `_id` taken from body (no ownership check).      | `routes/updateProductReviews.ts:17-21`                                           | HIGH     |
| T-5 | **Sequelize operator injection** via `JSON.parse(req.params.id)` in recycle lookup.                                      | `routes/recycles.ts:14`                                                          | HIGH     |
| T-6 | **XML External Entities** (`noent: true` in `libxml.parseXml`).                                                          | `routes/fileUpload.ts:83`                                                        | HIGH     |
| T-7 | **YAML deserialization** (`yaml.load` from `js-yaml@3` with default schema — pre-4.x has unsafe behaviour).              | `routes/fileUpload.ts:117`                                                       | HIGH     |
| T-8 | **Zip slip / path traversal** in zip handler — `absolutePath.includes(path.resolve('.'))` is a substring check.          | `routes/fileUpload.ts:42-48`                                                     | HIGH     |
| T-9 | **Poison null byte** in `servePublicFiles` — `cutOffPoisonNullByte` is invoked *after* `endsWithAllowlistedFileType`, allowing access to non-allowlisted files via `name.md%00.something`. | `routes/fileServer.ts:27-33`                                                | HIGH     |
| T-10| **Mass-assignment on user registration** — `POST /api/Users` allows specifying `role: 'admin'` (the `verify.registerAdminChallenge` only *detects* it).                                  | `server.ts:419`, finale-rest auto-CRUD                                          | CRITICAL |
| T-11| **Product editing without auth** — `app.put('/api/Products/:id', security.isAuthorized())` is commented out.             | `server.ts:369`                                                                  | HIGH     |
| T-12| **Coupon tampering** — z85-decoded coupons and base64 `couponData` campaigns; no integrity check beyond a regex.         | `routes/order.ts:182-198`, `lib/insecurity.ts:99-121`                            | MEDIUM   |
| T-13| **CSRF on `POST /profile`** — there is no CSRF token; the only CSRF "check" is logging when the `Origin` header matches `htmledit.squarefree.com`. | `routes/updateUserProfile.ts:30`                                       | HIGH     |
| T-14| **Coupon code & wallet manipulation race** — TOCTOU between balance check and decrement in `placeOrder`.                  | `routes/order.ts:141-156`                                                        | MEDIUM   |
| T-15| **Profile-image stored XSS** — when `fetch` fails, raw URL string saved as `profileImage`; later concatenated into `Content-Security-Policy` header (`userProfile.ts:88`), enabling CSP bypass and XSS. | `routes/profileImageUrlUpload.ts:36`, `routes/userProfile.ts:88`     | HIGH     |

### 5.3 Repudiation

| ID  | Threat                                                                                                                | Affected components                                                  | Severity |
| --- | --------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | -------- |
| R-1 | **Logs are publicly browseable** at `/support/logs/` — also makes log injection more dangerous (attackers can read evidence and craft cover-ups). | `server.ts:281-283`, `routes/logfileServer.ts`               | HIGH     |
| R-2 | **No tamper-proof audit trail** — orders are written to a local in-process MarsDB collection; on restart the collection rebuilds from `datacreator.ts`. | `data/mongodb.ts`, `data/datacreator.ts`                | HIGH     |
| R-3 | **Order IDs are predictable** (`hash(email).slice(0,4) + randomHex(16)`) — enumerable for repudiation defence.         | `routes/order.ts:41`                                                  | MEDIUM   |
| R-4 | **Many sensitive flows return generic errors via `next(error)`** plus `errorhandler()` middleware which is the dev-only `errorhandler` package — leaks stack traces, but more importantly the *application* does not record who performed the action against an immutable log. | `server.ts:676`                                          | MEDIUM   |
| R-5 | **Username can be set to a pug expression** (`#{...}`) by the user, then rendered as a template — the rendered output appears in HTTP logs but the original input is hard to attribute (different user IDs render different effects). | `routes/userProfile.ts`                                       | LOW      |
| R-6 | **No password-change confirmation email** — silent password change endpoint at `GET /rest/user/change-password` accepts new password in query string (which gets logged in plaintext in `logs/access.log`). | `routes/changePassword.ts`                                | HIGH     |

### 5.4 Information Disclosure

| ID  | Threat                                                                                                                  | Affected components                                                  | Severity |
| --- | ----------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | -------- |
| I-1 | **Directory listing & file download at `/ftp/`** — exposes `acquisitions.md`, `package.json.bak`, `coupons_2013.md.bak`, `incident-support.kdbx`, `suspicious_errors.yml`, encrypted announcement. | `server.ts:269-271`, `routes/fileServer.ts`           | CRITICAL |
| I-2 | **Directory listing at `/encryptionkeys/`** — exposes JWT keys and premium content key.                                 | `server.ts:277-278`, `routes/keyServer.ts`                            | CRITICAL |
| I-3 | **Directory listing at `/support/logs/`** — exposes raw access logs containing JWTs in `Authorization` headers and passwords in query strings (from `changePassword`). | `server.ts:281-283`, `routes/logfileServer.ts`        | CRITICAL |
| I-4 | **Full config dump at `/rest/admin/application-configuration`** (unauthenticated).                                       | `routes/appConfiguration.ts`                                          | HIGH     |
| I-5 | **`/metrics` endpoint** unauthenticated — leaks request paths, file-upload sizes, internal counters.                     | `server.ts:718`, `routes/metrics.ts`                                  | MEDIUM   |
| I-6 | **`/api-docs` Swagger UI** unauthenticated — full B2B API documentation.                                                  | `server.ts:286`                                                       | LOW      |
| I-7 | **Verbose error responses** via the dev-only `errorhandler` package as global error middleware — stack traces, file paths, line numbers. | `server.ts:676`                                                       | HIGH     |
| I-8 | **`/api/Users/:id` returns most user fields** for any authenticated caller — emails, roles, last login IP, deluxe tokens. | `server.ts:362-365`, `models/user.ts`                                  | HIGH     |
| I-9 | **`/api/Feedbacks` GET unauthenticated** returns all feedback rows including `UserId`.                                    | `server.ts:360` (only `/api/Feedbacks/:id` is gated)                  | MEDIUM   |
| I-10| **`b2b/v2/orders` returns `cid` echoed from request** — enables blind enumeration; combined with `safeEval` errors, leaks internal state.                                          | `routes/b2bOrder.ts`                                                  | MEDIUM   |
| I-11| **Email partial-masking is reversible** (`replace(/[aeiou]/gi, '*')`) and used as a *lookup key* for orders — anyone who can submit any email lookup can find orders for any user via brute force of consonants. | `routes/dataExport.ts:22`, `routes/order.ts:164`                  | HIGH     |
| I-12| **CSP includes `unsafe-eval` and trust value derived from user-controlled `profileImage`**.                              | `routes/userProfile.ts:88`                                            | HIGH     |
| I-13| **`/rest/saveLoginIp`** records `X-Forwarded-For`, which is then served back in `/api/Users` responses — IP attribution can be falsified and read. | `routes/saveLoginIp.ts`, `models/user.ts`                  | MEDIUM   |
| I-14| **Hard-coded Alchemy API key for Sepolia** in `routes/web3Wallet.ts:18` — exposes the key to the world and to anyone who reads the repo. | `routes/web3Wallet.ts`                                          | MEDIUM   |

### 5.5 Denial of Service

| ID  | Threat                                                                                                                  | Affected components                                                  | Severity |
| --- | ----------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | -------- |
| D-1 | **No global rate limiting** — only `/rest/user/reset-password` and `/rest/2fa/*` have limiters, and the reset-password limiter is keyed off a spoofable header. | `server.ts:343, 458, 465, 471`                                     | HIGH     |
| D-2 | **YAML bomb / billion-laughs** via `/file-upload` (.yml). The `vm` timeout of 2000 ms attempts to bound execution but still permits 2 s of pure CPU per request. | `routes/fileUpload.ts:117`                                          | HIGH     |
| D-3 | **XML XXE-induced DoS / `noent` recursive entity expansion**.                                                            | `routes/fileUpload.ts:83`                                            | HIGH     |
| D-4 | **NoSQL `$where` `sleep()` loop** — `global.sleep` defined in `showProductReviews.ts`, capped at 2 s, but an attacker can chain many requests cheaply. | `routes/showProductReviews.ts:17-26`                                | MEDIUM   |
| D-5 | **B2B `safeEval` infinite loop** — `rceOccupyChallenge` exists precisely because `notevil` permits unbounded loops; the 2 s timeout is on the outer `vm.runInContext`, not on `safeEval`'s internal AST walker (depends on `notevil` version). | `routes/b2bOrder.ts`                                       | HIGH     |
| D-6 | **ReDoS via `unionSqlInjectionChallenge` substring checks** and other unbounded regex in `utils.containsOrEscaped`.       | `lib/utils.ts`                                                       | MEDIUM   |
| D-7 | **In-memory session map** grows without bound on each successful login (`authenticatedUsers.tokenMap[token] = user`) — eventually OOM. | `lib/insecurity.ts:authenticatedUsers`                          | MEDIUM   |
| D-8 | **Express `bodyParser.text({ type: '*/*' })`** with default 100 KB but then re-parsed as JSON in a manual middleware — large bodies hit JSON.parse twice. | `server.ts:314-326`                                          | MEDIUM   |
| D-9 | **`uploadToMemory` cap is 200 000 bytes**, but `uploadToDisk` (used for memories) has **no size limit** declared.        | `server.ts:687`                                                      | MEDIUM   |
| D-10| **Zip-bomb potential** — `unzipper@0.9.15` does not enforce a decompressed-size limit.                                    | `routes/fileUpload.ts:38-49`                                         | HIGH     |

### 5.6 Elevation of Privilege

| ID  | Threat                                                                                                                  | Affected components                                                  | Severity |
| --- | ----------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | -------- |
| E-1 | **Admin registration via mass-assignment**: `POST /api/Users` accepts `role:'admin'`.                                    | `server.ts:419`, finale-rest                                          | CRITICAL |
| E-2 | **JWT forgery → admin** (combination of S-1, S-2, S-3).                                                                  | `lib/insecurity.ts`                                                   | CRITICAL |
| E-3 | **Pug SSTI / `eval()` on username** — RCE under the Node process.                                                        | `routes/userProfile.ts:62, 87`                                        | CRITICAL |
| E-4 | **`safeEval` (notevil) RCE in B2B orders** — RCE under the Node process.                                                 | `routes/b2bOrder.ts:23`                                               | CRITICAL |
| E-5 | **YAML / XML deserialization RCE**.                                                                                      | `routes/fileUpload.ts`                                                | CRITICAL |
| E-6 | **Zip slip → arbitrary file write inside project tree**, e.g., overwriting `frontend/dist/frontend/main*.js` to serve malicious JS to every user. | `routes/fileUpload.ts:42-48`                                  | CRITICAL |
| E-7 | **Free deluxe upgrade** by omitting `paymentMode` (`routes/deluxe.ts:44` only verifies signed token, not payment).        | `routes/deluxe.ts`                                                    | HIGH     |
| E-8 | **Accounting role escalation** via JWT forgery → access to `/rest/order-history/orders` and delivery-status toggles.      | `routes/orderHistory.ts`, `lib/insecurity.ts:isAccounting`            | HIGH     |
| E-9 | **Coupon → 99% discount** through forged `couponData` base64 or by tampering with the time-restricted campaign codes.    | `routes/order.ts:182-211`                                             | HIGH     |
| E-10| **Wallet top-up without payment**: `addWalletBalance` validates only that `card.UserId == req.body.UserId` — both client-controlled. | `routes/wallet.ts:24-29`                                | HIGH     |
| E-11| **Chatbot privilege escalation** — `bot.factory.run(query)` allows operator injection; the bot has a function dispatcher (`botUtils[response.handler]`) — handler name reachable through training data. | `routes/chatbot.ts:103-117`, `lib/botUtils.ts`               | HIGH     |
| E-12| **`finale-rest` exposes every model**; verbs deny-listed individually leaves an easy regression risk where adding a model immediately exposes full CRUD. | `server.ts:482-505`                                       | HIGH     |
| E-13| **`denyAll` is `expressJwt({secret: Math.random()})`** — only fails when a token is supplied; in old `express-jwt` an absent token may pass through. | `lib/insecurity.ts:55`                                       | HIGH     |
| E-14| **`saveLoginIp` records `X-Forwarded-For` into `Users.lastLoginIp`** — combined with admin functions that key off IP, an attacker can spoof origin to bypass IP-based controls (e.g., `IpFilter` on `/api/Quantitys/:id`). | `routes/saveLoginIp.ts`                              | MEDIUM   |

---

## 6. Vulnerability Pattern Library (codebase-specific)

### 6.1 SQL Injection (Sequelize raw queries)

```ts
// VULNERABLE — routes/login.ts:34, routes/search.ts:23
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${security.hash(req.body.password)}' AND deletedAt IS NULL`,
  { model: UserModel, plain: true }
)

// SAFE
models.sequelize.query(
  'SELECT * FROM Users WHERE email = ? AND password = ? AND deletedAt IS NULL',
  { replacements: [email, security.hash(password)], model: UserModel, plain: true, type: QueryTypes.SELECT }
)
```
**Search-grep for new instances:** `rg "sequelize\.query\(.+\$\{" routes lib`.

### 6.2 NoSQL `$where` Injection (MarsDB)

```ts
// VULNERABLE — routes/trackOrder.ts:18, routes/showProductReviews.ts:36
db.ordersCollection.find({ $where: `this.orderId === '${id}'` })

// SAFE
db.ordersCollection.find({ orderId: String(id) })   // never use $where on user input
```
**Search-grep:** `rg "\\\$where" routes data lib`.

### 6.3 NoSQL mass-update / operator injection

```ts
// VULNERABLE — routes/updateProductReviews.ts:17
db.reviewsCollection.update({ _id: req.body.id }, { $set: { message: req.body.message } }, { multi: true })

// SAFE
db.reviewsCollection.update(
  { _id: String(req.body.id), author: authenticatedUser.data.email },   // ownership filter
  { $set: { message: String(req.body.message) } },
  { multi: false }
)
```

### 6.4 Reflected / Stored XSS

```ts
// VULNERABLE — routes/userProfile.ts:74-91
template = template.replace(/_username_/g, username)        // raw replace into HTML
const CSP = `img-src 'self' ${user?.profileImage}; script-src 'self' 'unsafe-eval'`
res.set({ 'Content-Security-Policy': CSP })

// SAFE
template = template.replace(/_username_/g, entities.encode(username))   // never inject raw HTML
// drop 'unsafe-eval'; never put user data in CSP header
```
**Note:** `helmet.xssFilter()` is **explicitly disabled** in `server.ts:187`.

### 6.5 Server-Side Template Injection / `eval`

```ts
// VULNERABLE — routes/userProfile.ts:62
username = eval(code)             // code derived from username matching #{(.*)}

// VULNERABLE — routes/b2bOrder.ts:23
safeEval(orderLinesData)          // notevil has known escapes

// SAFE
// Never eval user data. Replace with a strict allow-list parser / JSON Schema.
```

### 6.6 Command-like JS execution via templates

`pug.compile(template)` where `template` contains substituted user data — Pug compiles attribute interpolations like `#{...}` as JavaScript. Always render the template with `locals`, never string-substitute into the template source.

### 6.7 Path traversal / arbitrary file read

```ts
// VULNERABLE — routes/fileServer.ts:33
res.sendFile(path.resolve('ftp/', file))                    // `file` already had %00 cut off

// VULNERABLE — routes/keyServer.ts:14, routes/logfileServer.ts:14, routes/quarantineServer.ts (same pattern)

// SAFE
const safeName = path.basename(file)
if (!ALLOWED_FILES.has(safeName)) return res.sendStatus(403)
res.sendFile(path.resolve('ftp/', safeName))
```

### 6.8 Zip Slip

```ts
// VULNERABLE — routes/fileUpload.ts:42-48
const absolutePath = path.resolve('uploads/complaints/' + fileName)
if (absolutePath.includes(path.resolve('.'))) { ... }   // substring check

// SAFE
const dest = path.resolve('uploads/complaints/')
const out  = path.resolve(dest, path.basename(fileName))
if (!out.startsWith(dest + path.sep)) entry.autodrain()
```

### 6.9 XXE / unsafe XML

```ts
// VULNERABLE — routes/fileUpload.ts:83
libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })   // noent enables entities

// SAFE
libxml.parseXml(data, { noblanks: true, noent: false, nocdata: false, noNet: true })
```

### 6.10 Unsafe YAML

```ts
// VULNERABLE — routes/fileUpload.ts:117 (js-yaml 3.x)
yaml.load(data)   // 3.x default schema permits !!js/function in some configs

// SAFE
yaml.load(data, { schema: yaml.FAILSAFE_SCHEMA })
```

### 6.11 Open Redirect

```ts
// VULNERABLE — lib/insecurity.ts:138
allowed = allowed || url.includes(allowedUrl)     // substring contains

// SAFE
const parsed = new URL(url)
const allowedOrigins = new Set(['https://github.com', ...])
return allowedOrigins.has(parsed.origin)
```

### 6.12 SSRF

```ts
// VULNERABLE — routes/profileImageUrlUpload.ts:24
const response = await fetch(url)             // user-controlled URL, no scheme/host filter

// SAFE
const parsed = new URL(url)
if (!['http:','https:'].includes(parsed.protocol)) throw ...
if (isPrivateAddress(await dns.resolve(parsed.hostname))) throw ...
// fetch with `redirect: 'error'`, max-size, timeout
```

### 6.13 IDOR / missing ownership check

```ts
// VULNERABLE — routes/basket.ts:18, routes/order.ts:36
BasketModel.findOne({ where: { id: req.params.id } })

// SAFE
BasketModel.findOne({ where: { id: req.params.id, UserId: tokenUserId } })
```

### 6.14 Client-controlled UserId

```ts
// VULNERABLE — routes/wallet.ts:12, routes/dataExport.ts:26, routes/address.ts:11
WalletModel.findOne({ where: { UserId: req.body.UserId } })

// SAFE
const userId = authenticatedUser(req).data.id    // derive from verified JWT every time
WalletModel.findOne({ where: { UserId: userId } })
```

### 6.15 Mass-assignment / unwhitelisted attributes

`finale.resource({ model, excludeAttributes: [...] })` in `server.ts:482` blocks output but not *input*. `POST /api/Users` accepts every column including `role`, `deluxeToken`, `lastLoginIp`, `isActive`, `totpSecret`. Always whitelist input fields per verb.

### 6.16 Weak cryptography

```ts
// VULNERABLE — lib/insecurity.ts
export const hash = (data) => crypto.createHash('md5').update(data).digest('hex')
export const hmac = (data) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')

// SAFE
import argon2 from 'argon2'
export const hash = (pw) => argon2.hash(pw, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2 })
export const hmac = (data) => crypto.createHmac('sha256', process.env.HMAC_KEY).update(data).digest('hex')
```

### 6.17 CSRF

Cookie-based session is set via `res.cookie('token', token)` (no `httpOnly`, no `secure`, no `sameSite` flags — see `lib/insecurity.ts:195`, `routes/updateUserProfile.ts:40`). Any browser request from any origin can mutate state. The only "check" is matching `Origin` against `htmledit.squarefree.com` (for challenge detection). Implement `sameSite=Lax` at minimum and CSRF tokens for state-changing routes.

---

## 7. Priority Focus Areas for the Security Auditor

Ordered by exploit value × ease:

1. **`routes/login.ts:34`** — string-interpolated SQL on the login endpoint. Combines SQLi, auth bypass, full user table extraction, and password disclosure (MD5).
2. **`routes/search.ts:23`** — UNION SQLi available without authentication. Plus pivot to read `sqlite_master`.
3. **`lib/insecurity.ts` in its entirety** — hard-coded RSA private key (`:23`), MD5 password hashing (`:43`), hard-coded HMAC secret (`:44`), `expressJwt@0.1.3` enabling `alg:none` (`:54`), `denyAll` based on `Math.random()` (`:55`), `redirectAllowlist` substring check (`:138`), `appendUserId` writing into `req.body.UserId` from a mutable in-memory map.
4. **`server.ts:269-283`** — public directory listings for `/ftp`, `/encryptionkeys`, `/support/logs`. Each leaks materials sufficient to mount further attacks. Combine with `routes/fileServer.ts` poison-null-byte handling.
5. **`server.ts:419-421` and `finale-rest` block (`:482-591`)** — auto-CRUD for every Sequelize model; admin registration via mass-assignment; verbs gated only by per-route deny lists.
6. **`routes/userProfile.ts`** — Pug SSTI + `eval()` on username + CSP header constructed from user-controlled `profileImage`. RCE primitive.
7. **`routes/b2bOrder.ts`** — `notevil`/`safeEval` over user-supplied JS; classic RCE + DoS.
8. **`routes/fileUpload.ts`** — zip slip, XXE (`noent:true`), unsafe YAML, no decompressed-size limit. RCE / arbitrary file write.
9. **`routes/profileImageUrlUpload.ts`** — SSRF via `fetch()` of user-supplied URL + fallback that stores raw URL as `profileImage` (stored XSS / CSP-injection chain into `userProfile.ts`).
10. **`routes/trackOrder.ts` & `routes/showProductReviews.ts`** — NoSQL `$where` JS injection on MarsDB.
11. **`routes/updateProductReviews.ts`** — `multi:true` NoSQL update with body-controlled filter (mass tamper of any review).
12. **`routes/resetPassword.ts` + `server.ts:343`** — rate limit keyed off `X-Forwarded-For`; reset only requires email + (hard-coded HMAC of) answer; trivially brute-forceable.
13. **`routes/changePassword.ts`** — current-password check only runs if `currentPassword` was supplied; combined with cookie-based session and missing CSRF means a single GET to `/rest/user/change-password?new=…` cross-site changes the victim's password.
14. **`routes/appConfiguration.ts`** — unauthenticated full config dump.
15. **`routes/wallet.ts`, `routes/dataExport.ts`, `routes/address.ts`, `routes/deluxe.ts`** — all trust `req.body.UserId`; full IDOR / wallet theft / cross-tenant data export.
16. **`routes/redirect.ts` + `lib/insecurity.ts:isRedirectAllowed`** — open redirect via substring allowlist.
17. **`routes/orderHistory.ts` + `lib/insecurity.ts:isAccounting`** — accounting role gating only by JWT (forgeable per (3)). Verify also `routes/recycles.ts:14` (`JSON.parse(req.params.id)` → Sequelize operator injection).
18. **`routes/chatbot.ts`** — string-interpolated factory commands (`currentUser('${user.id}')`) and dispatch over `botUtils[response.handler]` keyed by training data; also remote-downloads training data on startup.
19. **`routes/web3Wallet.ts`** — hard-coded Alchemy API key; trust-on-first-use of `walletAddress` body field; event-listener leak on each invocation.
20. **`server.ts:182, 188, 202-205, 314-326, 676, 718`** — global misconfigurations:
    - wide-open CORS,
    - URL slash-collapse middleware (parser-confusion),
    - `bodyParser.text({type: '*/*'})` followed by manual JSON re-parse,
    - `errorhandler` (dev-only package) used as production error middleware,
    - unauthenticated `/metrics`.
21. **`encryptionkeys/jwt.key` / `jwt.pub`, `ctf.key`, `data/static/codefixes/*`, `ftp/incident-support.kdbx`, `ftp/package*.json.bak`** — secrets and backups checked into the repo and/or shipped to disk.
22. **`lib/startup/customizeApplication.ts` and `customizeEasterEgg.ts`** — load remote content at boot; review for SSRF / supply-chain risk.

---

## 8. Recommended Security Testing Strategy

1. **Static**: ESLint security plugins (`eslint-plugin-security`, `eslint-plugin-no-unsanitized`), `semgrep` with the `javascript.express` and `javascript.lang.security` rule packs, `njsscan`. Add `gitleaks` to the CI to catch the hard-coded keys we found.
2. **SCA**: `npm audit` and a CycloneDX SBOM is already produced (`bom.json`); enforce thresholds. Pay special attention to `express-jwt@0.1.3`, `jsonwebtoken@0.4.0`, `unzipper@0.9.15`, `sanitize-html@1.4.2`, `js-yaml@3.x`, `marsdb`, `notevil`, `libxmljs2`.
3. **DAST**: OWASP ZAP baseline (a `.zap` configuration directory already exists). Add active scan profiles for SQLi, NoSQLi, SSRF, XSS, open redirect, path traversal, XXE.
4. **Manual**: Authenticated review of each route in the *priority focus areas* list above; specifically craft tests for `req.body.UserId` substitution and JWT `alg:none`.
5. **Runtime**: turn on Helmet defaults (`helmet()` with no options, not just `noSniff/frameguard`), enable HSTS, lock CORS to known origins, deploy a strict CSP, place behind a WAF that strips `X-Forwarded-For` from external clients.

---

## 9. Assumptions & Accepted Risks (for this exercise)

- Treated the application as if deployed at `https://shop.example.com` behind a TLS-terminating proxy with no WAF.
- Assumed environment variable `PORT` and `BASE_PATH` could be set by the operator; not by an attacker.
- Assumed real user data: PII (email, address), payment cards (PAN), order history, wallet balances.
- Assumed multi-tenant: many customers share the same instance.
- Excluded the deliberate "challenge cheating detection" code paths from the auditing surface, but did **not** exclude the underlying functional code paths they exercise — those are the real vulnerabilities.

---

## 10. Changelog

| Version | Date       | Notes              |
| ------- | ---------- | ------------------ |
| 1.0.0   | 2026-05-11 | Initial generation |
