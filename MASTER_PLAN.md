# AuthLens: Master Implementation Plan

> **Zero-Config Local OIDC/OAuth2 Mock Provider, PKCE Flow Inspector & Offline JWT Security Studio**
>
> *Single-binary identity workbench, local OpenID Connect (OIDC) provider, and cryptographic token security suite. Mocks authorization code flows with PKCE, verifies JWTs 100% offline without leaking secrets, and stress-tests backend authentication middleware with automated token tampering attacks.*

---

## 1. Project Overview & Architecture

Integrating modern authentication (OAuth 2.1, OpenID Connect, JWT tokens) into web and mobile backends is fraught with developer friction and security risks:
1. **Cloud Auth Provider Friction**: Setting up Auth0, Clerk, AWS Cognito, or Keycloak for local development requires cloud accounts, redirect URI configurations, and persistent internet access.
2. **Data Leaks via Web-Based Token Decoders**: Developers routinely paste production and staging JWTs into third-party web tools (like `jwt.io`), leaking sensitive claims, user IDs, and signing keys to external servers.
3. **Complex PKI & Signature Verification**: Verifying JWKS endpoints, rotating keys, and debugging asymmetric signature algorithms (RS256, ES256, EdDSA) is difficult without a local sandbox.
4. **Untested Middleware Vulnerabilities**: Developers rarely test whether their backend API correctly rejects malicious tokens: expired timestamps, signature forgery, mismatched audience (`aud`) or issuer (`iss`), and the infamous `alg: none` bypass.

**AuthLens** provides an all-in-one local identity provider and security sandbox:
- **Zero-Config Local OIDC Provider**: Runs on `127.0.0.1:9099`, implementing full OIDC discovery (`/.well-known/openid-configuration`) and JWKS (`/.well-known/jwks.json`).
- **PKCE Flow Inspector**: Traces Authorization Code exchanges in real-time, verifying `code_challenge` derivation (`SHA-256` + Base64URL) from `code_verifier`.
- **100% Offline JWT Cryptographic Inspector**: Decodes and verifies RSA, ECDSA, Ed25519, and HMAC signatures locally with zero external network transmission.
- **Automated Token Tampering & Security Fuzzer**: Generates crafted adversarial tokens (`alg: none`, forged signatures, expired claims) to audit backend middleware resilience.
- **Interactive Web Studio & CLI**: Embedded React 19 studio with one-click user persona switching (Admin, Team Member, Suspended) and token generator.

```
+-----------------------------------------------------------------------------------+
|                                     AUTHLENS                                      |
+-----------------------------------------+-----------------------------------------+
                                          |
        +---------------------------------+---------------------------------+
        |                                                                   |
+-------v-------------------------+                 +-----------------------v-------+
|    Local OIDC Mock Provider     |                 |    Offline JWT Security Suite |
|  * /.well-known/openid-config   |                 |  * RS256, ES256, EdDSA, HS256 |
|  * /.well-known/jwks.json       |                 |  * 100% Local Signature Check |
|  * /oauth/authorize & /token    |                 |  * Claims Expiry & NBF Audit  |
+-------+-------------------------+                 +-----------------------+-------+
        |                                                                   |
        +---------------------------------+---------------------------------+
                                          |
                        +-----------------v-----------------+
                        |     PKCE Flow & Handshake Tracer  |
                        |  * Code Challenge (S256 / Plain)  |
                        |  * Code Verifier Validation       |
                        |  * Real-Time Exchange Timeline    |
                        +-----------------+-----------------+
                                          |
                        +-----------------v-----------------+
                        |    Token Tampering & Fuzzer Lab   |
                        |  * alg: none Attack Generator     |
                        |  * Expired & Future Timestamp Sim |
                        |  * Mismatched aud / iss Claims    |
                        +-----------------+-----------------+
                                          |
                        +-----------------v-----------------+
                        |   Interactive Web Studio & CLI    |
                        |  * Persona Switcher (Admin/Member)|
                        |  * Live Authorization Log         |
                        |  * 1-Click Copy Bearer Token      |
                        +-----------------+-----------------+
```

---

## 2. Directory Structure

```
authlens/
├── cmd/
│   └── authlens/
│       └── main.go
├── internal/
│   ├── oidc/
│   │   ├── server.go             # Gin HTTP router with OIDC endpoints
│   │   ├── discovery.go          # RFC 8414 /.well-known/openid-configuration
│   │   ├── jwks.go               # Dynamic JWKS provider with key rotation
│   │   ├── authorize.go          # /oauth/authorize endpoint with mock consent
│   │   ├── token.go              # /oauth/token endpoint with code exchange
│   │   └── userinfo.go           # /userinfo endpoint
│   ├── pkce/
│   │   ├── verifier.go           # RFC 7636 PKCE validation (S256 & plain)
│   │   └── trace.go              # Step-by-step telemetry for code exchange
│   ├── jwt/
│   │   ├── decoder.go            # Offline header, payload, and signature parser
│   │   ├── validator.go          # Cryptographic verification against local JWKS
│   │   └── key_generator.go      # Generates RSA 2048, ECDSA P-256, Ed25519 pairs
│   ├── fuzzer/
│   │   ├── tamper.go             # Mutation engine for security test vectors
│   │   ├── attacks.go            # alg:none, key confusion, signature stripping
│   │   └── test_runner.go        # HTTP client testing backend API responses
│   └── server/
│       ├── api.go                # REST API for management studio
│       └── static.go             # Embedded Vite frontend assets
├── web/
│   ├── src/
│   │   ├── components/
│   │   │   ├── JwtPlayground.tsx     # Three-color offline JWT inspector (Header/Payload/Sig)
│   │   │   ├── PkceTimeline.tsx      # Step-by-step diagram of OAuth code exchange
│   │   │   ├── PersonaSwitcher.tsx   # Instant 1-click token generation per role
│   │   │   └── FuzzerPanel.tsx       # Automated security attack test vectors
│   │   ├── hooks/
│   │   │   └── useAuthSession.ts
│   │   ├── App.tsx
│   │   └── main.tsx
│   ├── package.json
│   └── vite.config.ts
├── go.mod
├── go.sum
└── README.md
```

---

## 3. Implementation Roadmap

### Phase 1: Local OIDC Discovery & JWKS Engine
- Implement `internal/oidc/jwks.go`:
  - Generate ephemeral RSA 2048 (`RS256`) and ECDSA P-256 (`ES256`) keypairs on startup.
  - Expose `/.well-known/jwks.json` with standard `kid`, `kty`, `use`, `n`, `e`, `crv`, `x`, `y` parameters.
- Implement `internal/oidc/discovery.go`:
  - Return RFC 8414 compliant discovery metadata:
    `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `userinfo_endpoint`, `response_types_supported: ["code"]`, `code_challenge_methods_supported: ["S256"]`.

### Phase 2: OAuth 2.1 PKCE Authorization & Token Exchange
- Implement `internal/oidc/authorize.go`:
  - Handle `GET /oauth/authorize` with query params: `client_id`, `redirect_uri`, `response_type=code`, `scope`, `state`, `code_challenge`, `code_challenge_method=S256`.
  - Provide an automatic consent bypass or instant user approval UI.
- Implement `internal/pkce/verifier.go`:
  - Verify code exchange on `POST /oauth/token`:
    Compute $\text{Base64URL}(\text{SHA-256}(\text{code\_verifier}))$ and match against stored `code_challenge`.
  - Issue cryptographically signed ID tokens and Access tokens with customizable expiration.

### Phase 3: 100% Offline JWT Cryptographic Inspector
- Implement `internal/jwt/decoder.go`:
  - Parse raw JWT tokens into color-coded parts:
    - Red: Jose Header (algorithm, key ID, token type).
    - Purple: Claims Payload (subject, issuer, audience, exp, custom roles).
    - Cyan: Raw cryptographic signature bytes.
- Implement `internal/jwt/validator.go`:
  - Verify signature validity against configured public keys without sending bytes over the internet.
  - Evaluate temporal validity: check `exp` (expiration) and `nbf` (not before) with configurable clock skew.

### Phase 4: Token Tampering & Security Fuzzer
- Implement `internal/fuzzer/attacks.go`:
  - **`alg: none` Attack**: Replaces header with `{"alg": "none", "typ": "JWT"}` and removes signature.
  - **Signature Inversion**: Modifies a payload claim (e.g. `"role": "admin"`) while keeping the original signature.
  - **Expired Token Generator**: Generates validly signed tokens with an `exp` timestamp in the past.
  - **Key Confusion Attack**: Signs HMAC-SHA256 using an RSA public key string as secret.
- Implement automated tester: Send attacks to target backend API endpoint and confirm that all responses return `401 Unauthorized`.

### Phase 5: Web Studio & CLI Diagnostics
- Build modern React 19 interface in `web/`:
  - **Persona Quick Switcher**: 1-click generation of Bearer tokens for `admin@local.test`, `developer@local.test`, or `guest@local.test`.
  - **PKCE Handshake Timeline**: Interactive flow showing browser -> client -> AuthLens authorization sequence.
  - **Offline JWT Editor**: Edit JSON claims in real-time and see signature recalculate automatically.
- Single binary distribution: Embed frontend assets into Go binary with `//go:embed`.

---

## 4. Agent Kickoff Prompt

```markdown
You are implementing **AuthLens**, a zero-config local OIDC/OAuth2 mock provider, PKCE flow inspector, and offline JWT security studio in Go 1.23 + React 19.

### Execution Plan:
1. Initialize Go module `github.com/alexandrmotologa/authlens` in `B:\workgit\authlens`.
2. Implement `internal/oidc/` to serve standard OIDC discovery, JWKS, authorization code flow, and token endpoints on `:9099`.
3. Implement `internal/pkce/verifier.go` to enforce RFC 7636 PKCE validation with SHA-256 code challenge computation.
4. Implement `internal/jwt/` for 100% offline parsing and cryptographic verification of RSA, ECDSA, and HMAC tokens.
5. Implement `internal/fuzzer/` to generate adversarial tokens (alg:none, expired, forged signatures) for testing backend middleware.
6. Build the modern React 19 web studio in `web/` with the offline JWT playground, persona switcher, and PKCE trace visualizer.
7. Implement the CLI entrypoint in `cmd/authlens/main.go` supporting `serve --port 9099` and `verify <token>`.

Maintain 100% production code without mocks, placeholders, or empty handlers.
```
