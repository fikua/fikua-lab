# Fikua Lab — Technical Document

**Project source of truth. Claude agents must read this before working and update it when making significant changes.**

**Last updated:** 2026-02-21

---

## Vision

Fikua Lab is a learning lab and conformance testing platform for Digital Identity protocols. It implements the Issuer-Holder-Verifier triangle following the OpenID Foundation specifications, profiled by HAIP 1.0 and aligned with the EUDI Architecture Reference Framework (ARF) 2.8.

Claude AI agents write the code. Oriol defines specs, validates results, and uses the platform to deepen technical knowledge as a Technical PM specializing in SSI/eIDAS2.

## Goals

1. Pass all 12 OIDF conformance tests (Issuer, Wallet, Verifier)
2. Support multiple configuration profiles (Plain, HAIP) switchable at runtime
3. Serve as portfolio and content generator for oriolcanades.com
4. Contribute to the OIDF ecosystem (conformance feedback, test coverage)

## Brand and visual identity

Fikua Lab shares a visual system with oriolcanades.com. The Fikua ID Suite brand is discontinued — branding pivots between Oriol Canades (person) and Fikua Lab (lab/product).

### Color palette

| Role | Light mode | Dark mode |
|------|-----------|-----------|
| Accent (teal) | `#2A9D8F` | `#2dd4bf` |
| Accent hover | `#238578` | `#5eead4` |
| Highlight (berry) | `#c2185b` | `#f06292` |
| Berry hover | `#a11445` | `#f48fb1` |
| Heading | `#1B263B` | `#e2e8f0` |
| Text | `#3A3A3C` | `#cbd5e1` |
| Muted | `#6B7280` | `#94a3b8` |
| Background | `#ffffff` | `#0f172a` |
| Background alt | `#f8f9fa` | `#1e293b` |
| Border | `#e5e7eb` | `#334155` |

### Color usage

- **Teal:** Primary accent. Links, primary buttons, role icons (Issuer, Wallet, Verifier). Directly connected to the Oriol Canades personal brand.
- **Berry:** Secondary accent. Badges, highlighted numbers, high-energy CTAs. Gives the startup/lab personality.
- **Neutrals (shared):** Same as oriolcanades.com. Creates brand cohesion without being identical.

### Typography

- Sans-serif: `Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif`
- Monospace: `'SF Mono', 'Fira Code', 'JetBrains Mono', 'Menlo', monospace`

## Technical decisions

| Decision | Choice | Reason |
|----------|--------|--------|
| Language | Java 25 (LTS) | Migrated from Java 24. Records, sealed interfaces, virtual threads. Supported until 2033. |
| HTTP Framework | Javalin | Transparent, minimal, no annotations. The lab's purpose is learning protocols, not frameworks. |
| Why not Quarkus | Discarded | Over-engineering for a lab. CDI, Vert.x, ArC add layers that hide what happens on the wire. If migration is needed, fikua-core is 100% framework-agnostic. |
| Frontend build | None (vanilla HTML/CSS/JS) | No Vite, no Node, no build step. Served directly by nginx. |
| Database | PostgreSQL 17 | JSONB for profiles, Flyway for migrations. |
| Certificates | X.509 self-signed (EC P-256) | eIDAS-aligned. No DIDs, no QTSP. |
| Deployment | Docker Compose + nginx | OVH VPS (EU). European data residency. |

## Tech stack

| Component | Technology | Version | Notes |
|-----------|-----------|---------|-------|
| Language | Java | 25 (LTS) | Records, sealed interfaces, virtual threads |
| Build | Gradle (Kotlin DSL) | 8.14 | Multi-module mono-repo |
| HTTP Server | Javalin | 6.6.0 | Minimal, no annotations |
| Database | PostgreSQL | 17 | JSONB profiles, sessions |
| DB Pool | HikariCP | 6.2.1 | Connection pooling |
| Migrations | Flyway | 11.3.1 | Schema versioning |
| JWT/JWK | nimbus-jose-jwt | 10.2 | JWT signing, JWK, SD-JWT |
| JSON | Jackson | 2.18.3 | Serialization |
| Crypto | Bouncy Castle | 1.80 | EC curves, X.509 |
| Frontend | HTML, CSS, JS | vanilla | No build step, served by nginx |
| Containers | Docker + Docker Compose | - | Full stack deployment |
| Reverse Proxy | nginx | alpine | TLS termination, frontend serving |
| Hosting | OVH VPS (EU) | - | European data residency |
| CI/CD | GitHub Actions | - | Build, test + Docker push on main (`.github/workflows/ci.yml`) |
| Certs | OpenSSL | - | Self-signed X.509 (eIDAS-aligned) |

## Architecture

### Key principle: Infrastructure-Application-Domain

The backend follows a layered architecture inspired by hexagonal/ports-and-adapters, organized as independent service modules that share a common protocol library:

```text
fikua-core        Domain — Pure protocol library. ZERO I/O, ZERO state, ZERO framework deps.
                  OID4VCI, OID4VP, SD-JWT, OAuth2, crypto types and validators.
                  Publishable as a standalone JAR. Reusable by any service or framework.

fikua-issuer      Service — Credential Issuer (OID4VCI server-side).
                  Application layer: IssuanceService, ports (NonceStore, JtiStore, etc.)
                  Infrastructure layer: Javalin HTTP controllers, JDBC adapters, PEM key loader.

fikua-wallet      Service — Wallet / Holder (OID4VCI client-side, OID4VP responder).
                  Application layer: HolderService, ports (CredentialStore, IssuerClient, etc.)
                  Infrastructure layer: Javalin HTTP controllers, HTTP client adapters.

fikua-verifier    Service — Verifier (OID4VP server-side).
                  Application layer: VerificationService, ports (SessionStore, etc.)
                  Infrastructure layer: Javalin HTTP controllers, JDBC adapters.

fikua-lab         Orchestrator — Starts 1..N roles in a single process.
                  Reads FIKUA_ROLES env var. Preserves single-Docker deployment.
```

### Layered architecture

Each service module (issuer, wallet, verifier) follows three internal layers:

```text
┌─────────────────────────────────────────────────────────────────────┐
│                     Infrastructure (per service)                     │
│  HTTP Controllers (Javalin) │ JDBC Adapters │ Filesystem loaders    │
│  Thin: parse HTTP, delegate to Application, serialize response      │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │ implements ports
┌──────────────────────────────────▼──────────────────────────────────┐
│                     Application (per service)                       │
│  Use case services │ Port interfaces │ Application models           │
│  Orchestrates domain objects. No HTTP, no SQL, no I/O.              │
│  Ports defined HERE — each service owns its contracts.              │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │ depends on
┌──────────────────────────────────▼──────────────────────────────────┐
│                     Domain (fikua-core, shared)                      │
│  Protocol types │ Validators │ Builders │ Crypto abstractions       │
│  ZERO I/O. ZERO state. ZERO framework deps.                        │
│  Only exception: SigningKey interface (crypto abstraction).          │
└─────────────────────────────────────────────────────────────────────┘
```

**Port ownership:** Each service defines its own port interfaces (e.g., `NonceStore`, `JtiStore` in fikua-issuer). If two services need a similar port, they define their own — no shared port module. This maximizes independence between services.

**SigningKey exception:** The `SigningKey` interface lives in `fikua-core` because domain objects (`SdJwtBuilder`, `DPoPValidator`) need it directly for cryptographic operations.

### Gradle dependency graph

```text
fikua-core              ← nimbus-jose-jwt, jackson, bouncycastle (ZERO framework deps)
    ↑
    ├── fikua-issuer     ← core + Javalin + PostgreSQL + HikariCP
    ├── fikua-wallet     ← core + Javalin (+ HTTP client for OID4VCI)
    ├── fikua-verifier   ← core + Javalin + PostgreSQL + HikariCP
    │
    └── fikua-lab        ← issuer + wallet + verifier (orchestrator)
```

### Deployment modes

A single Docker image supports all three roles. The `FIKUA_ROLES` environment variable controls which services start:

| Mode | FIKUA_ROLES | Docker containers | Use case |
|------|-------------|-------------------|----------|
| Development | `issuer,wallet,verifier` | 1 (all roles) | Local dev, `make local-up` |
| OIDF Testing | One per container | 3 (one role each) | Conformance tests with isolated services |
| Production | Single role | 1 per deployment | Deploy only the role needed |

```yaml
# Example: 3 containers from same image, each with one role
services:
  issuer:
    image: oriolcanades/fikua-lab:latest
    environment:
      FIKUA_ROLES: issuer
      FIKUA_BASE_URL: https://issuer.lab.fikua.com
  wallet:
    image: oriolcanades/fikua-lab:latest
    environment:
      FIKUA_ROLES: wallet
      FIKUA_BASE_URL: https://wallet.lab.fikua.com
  verifier:
    image: oriolcanades/fikua-lab:latest
    environment:
      FIKUA_ROLES: verifier
      FIKUA_BASE_URL: https://verifier.lab.fikua.com
```

### Mono-repo structure

```text
fikua-lab/
├── docs/
│   ├── fikua-lab-dt.md                            # THIS DOCUMENT (source of truth)
│   └── analysis/
│       └── oidf-test-configurations.md            # 12 OIDF tests documented
│
├── suite/
│   ├── frontend/
│   │   ├── landing/                               # Public landing page (teal + berry)
│   │   │   ├── index.html
│   │   │   ├── style.css
│   │   │   └── app.js
│   │   ├── portal/                                # Portal (configuration dashboard)
│   │   │   ├── index.html
│   │   │   ├── style.css
│   │   │   └── app.js
│   │   ├── issuer/                                # Issuer UI
│   │   ├── cert/                                  # Certificate selection (mTLS)
│   │   ├── holder/                                # Wallet UI
│   │   ├── verifier/                              # Verifier UI
│   │   └── shared/                                # Shared assets (404.html, 50x.html, favicon.svg)
│   │
│   └── backend/
│       ├── settings.gradle.kts                    # Module definitions
│       ├── build.gradle.kts                       # Root: Java 25 toolchain
│       ├── gradle.properties                      # Centralized versions
│       │
│       ├── fikua-core/                            # Domain — protocol library (ZERO framework deps)
│       │   ├── build.gradle.kts                   # nimbus-jose-jwt, jackson, bouncycastle
│       │   └── src/main/java/com/fikua/core/
│       │       ├── crypto/                        # SigningKey (interface), KeyOps, JwkUtils
│       │       ├── oauth2/                        # TokenGrant, DPoP, PKCE, errors
│       │       ├── oid4vci/                       # Metadata, offers, credentials, proofs
│       │       ├── oid4vp/                        # VP authorization, DCQL, JAR signing
│       │       ├── sdjwt/                         # SD-JWT build, parse, verify
│       │       └── profile/                       # ProfileConfig, presets, enums
│       │
│       ├── fikua-issuer/                          # Issuer service (app + infra)
│       │   ├── build.gradle.kts                   # core + javalin + postgresql + hikari
│       │   └── src/main/java/com/fikua/issuer/
│       │       ├── app/                           # IssuanceService, ports, models
│       │       └── infra/                         # IssuerServer, controllers, JDBC adapters
│       │
│       ├── fikua-wallet/                          # Wallet service (app + infra)
│       │   ├── build.gradle.kts                   # core + javalin + HTTP client
│       │   └── src/main/java/com/fikua/wallet/
│       │       ├── app/                           # HolderService, ports, models
│       │       └── infra/                         # WalletServer, controllers, HTTP client
│       │
│       ├── fikua-verifier/                        # Verifier service (app + infra)
│       │   ├── build.gradle.kts                   # core + javalin + postgresql + hikari
│       │   └── src/main/java/com/fikua/verifier/
│       │       ├── app/                           # VerificationService, ports, models
│       │       └── infra/                         # VerifierServer, controllers, JDBC adapters
│       │
│       └── fikua-lab/                             # Orchestrator (starts 1..N roles)
│           ├── build.gradle.kts                   # issuer + wallet + verifier
│           └── src/main/java/com/fikua/lab/
│               └── FikuaLab.java                  # main() — reads FIKUA_ROLES, starts services
│
├── deployment/
│   ├── docker/
│   │   └── Dockerfile                             # Multi-stage build (backend only, Java 25)
│   └── envs/
│       ├── local/
│       │   ├── compose.yaml                       # Local dev: backend (build) + postgres
│       │   └── deploy-frontend.sh                 # Serve frontend locally (python HTTP)
│       └── dev/
│           ├── ssh/                               # SSH key Ed25519 (gitignored)
│           ├── .env.example                       # VPS environment variables (shared by scripts)
│           ├── docker/
│           │   └── compose.yaml                   # VPS: backend (pull DockerHub) + postgres
│           ├── nginx/
│           │   └── nginx-lab.conf                 # VPS nginx routing (subdomains)
│           ├── release-docker.sh                  # Build + push Docker image to DockerHub
│           ├── deploy-nginx.sh                    # Deploy nginx config + SSL to VPS
│           ├── deploy-backend.sh                  # Deploy backend to VPS (SSH)
│           └── deploy-frontend.sh                 # Deploy frontend to VPS (SCP)
│
├── Makefile                                       # make help, build, deploy, pull, push, etc.
└── README.md
```

## Domains and DNS

### Base domain

`fikua.com` — Main Fikua domain (registered at Namecheap).

### DNS records

| Type | Name | Value | Purpose |
|------|------|-------|---------|
| URL Redirect | `@` | `https://www.fikua.com/` | Root redirect |
| A | `lab` | `51.38.179.236` | Landing page |
| A | `portal.lab` | `51.38.179.236` | Portal (configuration dashboard) |
| A | `issuer.lab` | `51.38.179.236` | Issuer backend (OID4VCI) |
| A | `wallet.lab` | `51.38.179.236` | Wallet backend (OID4VP) — future |
| A | `cert.lab` | `51.38.179.236` | Certificate selection (mTLS) |
| A | `verifier.lab` | `51.38.179.236` | Verifier backend (OID4VP) — future |

VPS: OVH (IP `51.38.179.236`), Ubuntu, SSH port `49222`.

### Subdomain architecture

```text
lab.fikua.com                    Landing page (nginx static)
portal.lab.fikua.com             Portal — configuration dashboard (nginx static + proxy /admin/)
issuer.lab.fikua.com             Issuer API + UI (/oid4vci/v1/*)
cert.lab.fikua.com               Certificate selection (mTLS, ssl_verify_client)
wallet.lab.fikua.com             Wallet UI + API
verifier.lab.fikua.com           Verifier UI + API
```

Each role subdomain is an independent entry point for the OIDF suite. The suite discovers endpoints via `.well-known` metadata, which in turn advertises URLs with the corresponding path prefix.

### Nginx on VPS

Nginx is a system service (not a Docker container). Installed via `apt` and managed with `systemctl`.

**Key files:**

| File | Purpose |
|------|---------|
| `/etc/nginx/nginx.conf` | Main config (symlink to `/opt/vps/nginx/nginx.conf`) |
| `/etc/nginx/conf.d/lab-fikua.conf` | Fikua Lab server blocks (6 subdomains) |
| `/etc/nginx/conf.d/oriolcanades.conf` | oriolcanades.com server block |
| `/etc/nginx/conf.d/proto.eudistack.net.conf` | proto.eudistack.net server block |
| `/etc/nginx/conf.d/cert.eudistack.net.conf` | cert.eudistack.net server block |
| `/etc/letsencrypt/live/lab.fikua.com/` | Let's Encrypt SSL certificates (6 subdomains) |

**Important dependencies:**

- The main `nginx.conf` defines `limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;` — required by `oriolcanades.conf`
- All `.conf` files in `conf.d/` are included via `include /etc/nginx/conf.d/*.conf;` in `nginx.conf`
- If the main `nginx.conf` is missing or corrupt, nginx cannot start or run `nginx -t`

**Deploy precautions:**

- `make deploy-nginx` uploads `lab-fikua.conf` and requests SSL certificates if they don't exist
- On first deploy (without certificates), the script fails because the config references certificates that don't exist yet
- For the first SSL deploy, do it manually on the VPS: temporarily disable the config, request the cert with `--standalone`, and re-enable (see "Troubleshooting nginx" section)

**Useful VPS commands:**

```bash
sudo nginx -t                     # Verify configuration
sudo systemctl reload nginx       # Reload without downtime
sudo systemctl restart nginx      # Restart (brief downtime)
sudo certbot certificates         # Check SSL certificate status
```

### Troubleshooting nginx

**Problem: `nginx -t` fails with "No such file or directory" for `nginx.conf`**

The `nginx.conf` is a symlink to `/opt/vps/nginx/nginx.conf`. If this file doesn't exist:

```bash
sudo mkdir -p /opt/vps/nginx
sudo tee /opt/vps/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
}

http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    gzip on;

    limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF
```

**Problem: first SSL deploy fails (certificates don't exist)**

The config references certificates that certbot hasn't created yet. Solution:

```bash
# 1. Disable config that needs certs
sudo mv /etc/nginx/conf.d/lab-fikua.conf /etc/nginx/conf.d/lab-fikua.conf.disabled
sudo nginx -t && sudo systemctl reload nginx

# 2. Request certificate (temporarily stops nginx)
sudo certbot certonly --standalone \
  --pre-hook "systemctl stop nginx" \
  --post-hook "systemctl start nginx" \
  -d lab.fikua.com -d portal.lab.fikua.com -d issuer.lab.fikua.com \
  -d cert.lab.fikua.com -d wallet.lab.fikua.com -d verifier.lab.fikua.com \
  --non-interactive --agree-tos -m ocanades@outlook.com

# 3. Re-enable config and start
sudo mv /etc/nginx/conf.d/lab-fikua.conf.disabled /etc/nginx/conf.d/lab-fikua.conf
sudo nginx -t && sudo systemctl start nginx
```

**Problem: "zero size shared memory zone general"**

The `nginx.conf` doesn't define the `limit_req_zone` that `oriolcanades.conf` needs. Add to the `http {}` block in `nginx.conf`:

```nginx
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
```

### Nginx routing

Nginx decides whether to serve static files (frontends) or proxy to the backend. Configuration is at `deployment/envs/dev/nginx/nginx-lab.conf`.

| Subdomain | Path | Destination | Type |
|-----------|------|-------------|------|
| `lab.fikua.com` | `/` | `/opt/vps/frontends/lab/landing/` | Static (landing) |
| `lab.fikua.com` | `/health` | Proxy → backend `:8090` | Health check |
| `portal.lab.fikua.com` | `/` | `/opt/vps/frontends/lab/portal/` | Static (portal) |
| `portal.lab.fikua.com` | `/admin/` | Proxy → backend `:8090` | Admin API |
| `portal.lab.fikua.com` | `/health` | Proxy → backend `:8090` | Health check |
| `portal.lab.fikua.com` | `/reset` | Proxy → backend `:8090` | State reset |
| `issuer.lab.fikua.com` | `/` | `/opt/vps/frontends/lab/issuer/` | Static (issuer UI) |
| `issuer.lab.fikua.com` | `/.well-known/` | Proxy → backend `:8090` | OIDF metadata |
| `issuer.lab.fikua.com` | `/oid4vci/v1/` | Proxy → backend `:8090` | Issuer API |
| `issuer.lab.fikua.com` | `/health` | Proxy → backend `:8090` | Health check |
| `cert.lab.fikua.com` | `/` | `/opt/vps/frontends/lab/cert/` | Static (cert UI) + mTLS |
| `cert.lab.fikua.com` | `/cert-info` | Headers with TLS client certificate data | nginx `return 204` |
| `wallet.lab.fikua.com` | `/` | `/opt/vps/frontends/lab/holder/` | Static (wallet UI) |
| `wallet.lab.fikua.com` | `/oid4vci/` | Proxy → backend `:8090` | Wallet API |
| `wallet.lab.fikua.com` | `/oid4vp/` | Proxy → backend `:8090` | Wallet API |
| `verifier.lab.fikua.com` | `/` | `/opt/vps/frontends/lab/verifier/` | Static (verifier UI) |
| `verifier.lab.fikua.com` | `/oid4vp/` | Proxy → backend `:8090` | Verifier API |
| **All** | `/404.html` | `/opt/vps/frontends/lab/shared/` | 404 error page |
| **All** | `/50x.html` | `/opt/vps/frontends/lab/shared/` | 500/502/503/504 error page |

The backend listens on `127.0.0.1:8090` (exposed by Docker Compose, mapped internally to port `8080` in the container).

### Main URLs

| URL | Purpose |
|-----|---------|
| `https://lab.fikua.com` | Landing page |
| `https://portal.lab.fikua.com` | Portal (configuration dashboard and navigation) |
| `https://issuer.lab.fikua.com/.well-known/openid-credential-issuer` | Credential Issuer Metadata |
| `https://issuer.lab.fikua.com/.well-known/oauth-authorization-server` | Authorization Server Metadata |
| `https://issuer.lab.fikua.com/oid4vci/v1/token` | Token endpoint |
| `https://issuer.lab.fikua.com/oid4vci/v1/credential` | Credential endpoint |

**Credential request format:** Supports both OID4VCI 1.0 Final `proofs` (plural: `{"proofs": {"jwt": ["eyJ..."]}}`) and draft `proof` (singular: `{"proof": {"proof_type": "jwt", "jwt": "eyJ..."}}`). The plural format takes precedence when both are present.

### mTLS flow — cert.lab.fikua.com

The `cert.lab` subdomain handles client certificate selection (mTLS). The browser shows the native certificate selection dialog and data is sent back to the Issuer.

**Nginx configuration:**

```nginx
ssl_verify_client optional_no_ca;   # Request certificate without validating CA
```

- `optional_no_ca` allows the browser to present any certificate (including self-signed) without nginx rejecting it. This is useful for the lab where we don't have a trusted CA configured.

**`/cert-info` endpoint:**

```nginx
location = /cert-info {
    add_header X-Client-Verify $ssl_client_verify always;
    add_header X-Client-Subject $ssl_client_s_dn always;
    add_header X-Client-Issuer $ssl_client_i_dn always;
    add_header X-Client-Serial $ssl_client_serial always;
    add_header X-Client-Fingerprint $ssl_client_fingerprint always;
    add_header X-Client-Valid-From $ssl_client_v_start always;
    add_header X-Client-Valid-To $ssl_client_v_end always;
    add_header Access-Control-Expose-Headers "..." always;
    return 204;
}
```

Certificate data is sent via HTTP headers (not JSON body) because Distinguished Names contain escaped commas (`TORRES RUIZ\, ANA BELEN`) that break nginx's inline JSON parsing.

**Issuer → cert → issuer flow:**

```text
1. User clicks "Identify with certificate" at issuer.lab.fikua.com
2. Redirect to cert.lab.fikua.com?return_url=https://issuer.lab.fikua.com
3. Browser shows native certificate selection dialog (mTLS)
4. cert/app.js does GET /cert-info → reads X-Client-* headers
5. Shows detected certificate → user clicks "Accept"
6. Redirect to issuer.lab.fikua.com?cert=<base64-json>
7. issuer/app.js reads query param, decodes, displays certificate data
```

**Distinguished Name parsing:**

```javascript
// DN format: CN=NAME\, SURNAME,OU=DEPT,O=ORG
// The comma inside CN is escaped with backslash
dn.split(/(?<!\\),/)   // Split on commas NOT preceded by backslash
```

### SSL certificate

A single multi-domain Let's Encrypt certificate covers all subdomains:

```text
certbot certonly --nginx -d lab.fikua.com -d issuer.lab.fikua.com [-d wallet.lab.fikua.com -d verifier.lab.fikua.com]
```

All nginx server blocks reference the same certificate at `/etc/letsencrypt/live/lab.fikua.com/`.

### Path prefixes per role

OIDF endpoints don't have fixed paths per spec — the suite reads URLs from `.well-known` metadata. We leverage this to organize APIs by role with identifying prefixes:

| Role | Path prefix | Example |
|------|-------------|---------|
| Issuer | `/oid4vci/v1/` | `https://issuer.lab.fikua.com/oid4vci/v1/token` |
| Wallet | `/oid4vp/v1/` | `https://wallet.lab.fikua.com/oid4vp/v1/...` (future) |
| Verifier | `/oid4vp/v1/` | `https://verifier.lab.fikua.com/oid4vp/v1/...` (future) |

`.well-known` endpoints always stay at the root path (per RFC 8615 spec).

### Error handling

The backend uses a dual error format:

| Scope | Format | Content-Type | Standard |
| ----- | ------ | ------------ | -------- |
| Protocol endpoints (`/oid4vci/v1/*`, `/.well-known/*`) | `OAuthError` (`error` + `error_description`) | `application/json` | RFC 6749 §5.2 |
| Non-protocol endpoints (`/admin/*`, 404, 405, 500) | `ProblemDetail` (`type`, `status`, `title`, `detail`, `instance`) | `application/problem+json` | RFC 9457 |

**Key behaviors:**

- **401 responses** include `WWW-Authenticate: DPoP error="..."` header (RFC 9449 §7.1)
- **404/405** at the Javalin level return `ProblemDetail` (not HTML)
- **500** unhandled exceptions return `ProblemDetail.internalError()` with stack trace logged server-side
- `OAuthErrorException` is the transport for all protocol-level errors (carries HTTP status + `OAuthError`)
- **`Cache-Control: no-store`** on `/token`, `/nonce`, and `/credential` responses (OID4VCI §7.2, §8.3, RFC 6749 §5.1)
- **`iss` parameter** in authorization response redirect (RFC 9207)
- **`authorization_response_iss_parameter_supported: true`** in AS Metadata for HAIP profile (RFC 9207 §3)

**Records:**

- `com.fikua.core.oauth2.OAuthError` — OAuth2 error codes: `invalid_request`, `invalid_grant`, `invalid_client`, `invalid_token`, `invalid_or_missing_proof`, `invalid_nonce`, `unsupported_grant_type`, `unsupported_credential_type`, `unsupported_credential_format`
- `com.fikua.core.http.ProblemDetail` — RFC 9457 with factory methods: `notFound()`, `methodNotAllowed()`, `internalError()`, `badRequest()`

### Test coverage

126 unit tests in `fikua-core` covering security validators, protocol records, and error handling:

| Test class | Tests | Coverage |
| ---------- | ----- | -------- |
| `AuthServerMetadataTest` | 6 | HAIP + pre-auth metadata, JSON contract, RFC 9207 iss parameter |
| `CredentialIssuerMetadataTest` | 12 | HAIP + plain metadata, credential configs |
| `ClientAttestationValidatorTest` | 7 | WIA~PoP parsing, assertion types |
| `DPoPValidatorTest` | 14 | All RFC 9449 validation branches |
| `ProofValidatorTest` | 12 | OID4VCI §7.2.1 proof of possession |
| `PkceUtilTest` | 9 | RFC 7636 test vector, S256 challenge |
| `OAuthErrorTest` | 10 | All error codes, JSON snake_case |
| `ProblemDetailTest` | 7 | RFC 9457 factories, serialization |
| `TokenResponseTest` | 4 | Bearer/DPoP, JSON contract |
| `TokenRequestTest` | 5 | Form parsing, grant type detection |
| `CredentialOfferTest` | 6 | Pre-auth + auth_code, tx_code |
| `CredentialRequestTest` | 9 | Singular/plural proofs, extractProofJwt, JSON contract |
| `CredentialResponseTest` | 4 | JSON contract, NON_NULL |
| `DisclosureTest` | 9 | Create/digest/parse round-trip |
| `SdJwtVerifierTest` | 5 | Signature verification, expiry, claim resolution |
| `SdJwtBuilderTest` | ~3 | SD-JWT building (pre-existing) |

### Error pages

Shared error pages for all subdomains, served from `/opt/vps/frontends/lab/shared/`.

| File | Code | Description |
|------|------|-------------|
| `404.html` | 404 | Page not found |
| `50x.html` | 500, 502, 503, 504 | Server error |

**Features:**

- Self-contained (HTML + inline CSS, no external dependencies)
- Automatic dark mode via `prefers-color-scheme`
- Inline favicon (SVG as data URI)
- "Go to Fikua Lab" button linking to `https://lab.fikua.com`
- Configured in nginx with `internal` to prevent direct access:

```nginx
error_page 404 /404.html;
error_page 500 502 503 504 /50x.html;
location = /404.html { root /opt/vps/frontends/lab/shared; internal; }
location = /50x.html { root /opt/vps/frontends/lab/shared; internal; }
```

### Favicons

Every frontend has an identical `favicon.svg`: white "F" letter on a teal (`#2A9D8F`) circle. Referenced in each `index.html`:

```html
<link rel="icon" type="image/svg+xml" href="favicon.svg">
```

Error pages (404, 50x) use the favicon inline as a data URI in the `<link>` tag to be fully self-contained.

## Normative hierarchy

```text
ARF 2.8 (EU regulatory layer: Trusted Lists, WUA/WIA, signed metadata, ETSI certs)
  └── HAIP 1.0 (technical profile: DPoP, PKCE S256, PAR, x509_hash, DCQL, response encryption)
       └── OID4VCI 1.0 Final (issuance) + OID4VP 1.0 Final (presentation)
```

- **Plain** = vanilla OID4VCI/OID4VP specs without HAIP restrictions
- **HAIP** = mandates authorization_code + PKCE S256 + PAR + DPoP + wallet attestation. Does NOT allow pre_authorization_code
- ARF does NOT require OpenID Federation — uses X.509 PKI + EU Trusted Lists
- No DIDs. Only X.509 certificates (x509_hash, x509_san_dns as client_id prefix)

## OIDF conformance tests

### How they work

| Testing... | The suite acts as... | We expose... |
|------------|---------------------|-------------|
| Our **Issuer** | Wallet (sends requests to our endpoints) | Metadata, token, credential endpoints |
| Our **Wallet** | Verifier (sends VP requests to our wallet) | HTTP client that responds |
| Our **Verifier** | Fake Wallet (waits for our requests) | Verifier pointing to the suite endpoint |

### 12 supported tests

| # | Role | Grant Type | Format | Notes |
|---|------|-----------|--------|-------|
| 1-2 | Issuer | pre_authorization_code | sd-jwt-vc | No DPoP, no client auth |
| 3-4 | Issuer | authorization_code (HAIP) | sd-jwt-vc | DPoP + PAR + PKCE S256 |
| 5-8 | Wallet | pre_auth / auth_code | sd-jwt-vc | Wallet as holder |
| 9-12 | Verifier | - | sd-jwt-vc | direct_post, x509_san_dns/x509_hash |

## Profile system

Configuration profiles stored in PostgreSQL (JSONB). Each profile is a set of parameters that defines the behavior of the Issuer, Wallet, or Verifier. Switchable at runtime via Portal.

### Configuration parameters

| Parameter | Values |
|-----------|--------|
| Sender Constraining | `dpop`, `mtls` |
| Client Authentication | `mtls`, `private_key_jwt`, `client_attestation` |
| Grant Type | `authorization_code`, `pre_authorization_code` |
| Credential Format | `sd_jwt_vc`, `mdoc`, `iso_mdl` |
| Credential Offer | `by_value`, `by_reference` |
| Issuance Mode | `immediate`, `deferred` |
| Response Mode | `direct_post`, `direct_post_jwt`, `dc_api`, `dc_api_jwt` |
| Client ID Prefix | `x509_san_dns`, `x509_hash`, `pre_registered`, `redirect_uri` |
| Query Language | `presentation_exchange`, `dcql` |
| Credential Response Enc | `plain`, `encrypted` |

### Presets

**Plain Pre-Auth Issuer** — The simplest test to start with

| Parameter | Value |
|-----------|-------|
| Grant Type | `pre_authorization_code` |
| Credential Format | `sd_jwt_vc` |
| Credential Offer | `by_reference` |
| Issuance Mode | `immediate` |
| DPoP / Client Auth | None (not required with pre-auth) |

**HAIP Authorization Code Issuer** — What EUDI/ARF requires

| Parameter | Value |
|-----------|-------|
| Grant Type | `authorization_code` |
| Sender Constraining | `dpop` (RFC 9449) |
| Client Authentication | `client_attestation` |
| PKCE | `S256` |
| PAR | Required |
| Credential Format | `sd_jwt_vc` |

**Plain Verifier**

| Parameter | Value |
|-----------|-------|
| Client ID Prefix | `x509_san_dns` |
| Response Mode | `direct_post` |
| Request Method | `request_uri_signed` |

**HAIP Verifier**

| Parameter | Value |
|-----------|-------|
| Client ID Prefix | `x509_hash` |
| Response Mode | `direct_post_jwt` (encrypted) |
| Query Language | `dcql` |
| Response Encryption | `ECDH-ES` + `A128GCM`/`A256GCM` |

### Admin API

```text
GET  /admin/profiles              List all profiles
POST /admin/profiles              Create profile
PUT  /admin/profiles/{id}         Update profile
PUT  /admin/profiles/{id}/activate  Activate profile
GET  /admin/presets               List available presets
GET  /admin/health                Health check for endpoints
```

## Happy path — Plain Pre-Auth Issuer (OID4VCI)

```text
1. Issuer generates credential_offer with pre-authorized_code
   → credential_offer_uri points to /oid4vci/v1/credential-offer/{id}

2. Suite (wallet) GET /.well-known/openid-credential-issuer
   → Credential Issuer Metadata (credential_endpoint = .../oid4vci/v1/credential)

3. Suite GET /.well-known/oauth-authorization-server
   → Authorization Server Metadata (token_endpoint = .../oid4vci/v1/token)

4. Suite POST /oid4vci/v1/token
   → grant_type: pre-authorized_code, pre-authorized_code: <code>
   → Response: { access_token, token_type: "Bearer" }

5. Suite POST /oid4vci/v1/nonce
   → Body: empty (Content-Length: 0)
   → Response: { c_nonce: "<nonce>" }

6. Suite POST /oid4vci/v1/credential
   → Authorization: Bearer <access_token>
   → Body: { credential_configuration_id, proof: { jwt: "<proof with c_nonce>" } }
   → Response: { credentials: [{ credential: "<sd-jwt-vc-string>" }] }
```

### Issuer endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/.well-known/openid-credential-issuer` | Credential Issuer Metadata |
| GET | `/.well-known/oauth-authorization-server` | Authorization Server Metadata |
| POST | `/oid4vci/v1/issuance` | Trigger issuance (creates offer + links credential_data) |
| GET | `/oid4vci/v1/credential-offer/{id}` | Credential Offer by reference |
| POST | `/oid4vci/v1/token` | Pre-auth code or auth code → access_token |
| POST | `/oid4vci/v1/credential` | SD-JWT VC issuance |
| POST | `/oid4vci/v1/nonce` | Fresh c_nonce |
| GET | `/oid4vci/v1/jwks` | JWK Set (EC P-256) |
| GET | `/oid4vci/v1/authorize` | Authorization endpoint (HAIP) |
| POST | `/oid4vci/v1/par` | Pushed Authorization Request (HAIP) |

> **Note:** `GET /oid4vci/v1/credential-offer` returns 400 — use `POST /issuance` with `credential_data` to trigger issuance.

## X.509 certificates

Self-signed X.509 certificate chain with OpenSSL, structure aligned with eIDAS:

- **Root CA** — Simulates trust anchor (NOT included in x5c headers per HAIP)
- **Issuer signing cert** — Signs SD-JWT VCs, included in x5c JOSE header
- **Verifier access cert** — For x509_hash/x509_san_dns client_id prefix
- All certificates use EC P-256 (ES256) as mandated by HAIP

## Database

PostgreSQL with the main tables:

- **profiles** — Profile configuration (JSONB), with `is_active` flag
- **credential_offers** — By-reference offers with pre-authorized codes
- **access_tokens** — Issued tokens with c_nonce and DPoP thumbprint
- **verification_sessions** — OID4VP sessions with state/nonce

Migrations managed by Flyway at `src/main/resources/db/migration/`.

## Deployment

### Prerequisites

- SSH key at `deployment/envs/dev/ssh/id_ed25519`
- Docker Desktop installed locally
- DockerHub PAT configured in `deployment/envs/dev/.env` (copy from `.env.example`)
- SSH access to VPS (port `49222`)

### Environments

| Environment | Directory | Backend | Frontends |
|-------------|-----------|---------|-----------|
| Local | `deployment/envs/local/` | Docker build from source | `python3 -m http.server` (landing:3000, portal:3001) |
| Dev (VPS) | `deployment/envs/dev/` | Docker pull from DockerHub | SCP to VPS, served by nginx |

### Deployment flow (VPS)

**First time (clean VPS):**

```bash
make full-deploy      # cleanup + nginx/SSL + backend
make deploy-frontend  # upload all frontends
```

**Redeployment (update version):**

```bash
make docker-push      # build Docker image + push to DockerHub
make deploy           # pull image on VPS + restart containers
```

**Frontend only:**

```bash
make deploy-frontend  # upload all frontend files to VPS
```

### Available commands

Run `make help` to see all available commands. Full reference:

**Development:**

| `make` target | Description |
|---------------|-------------|
| `help` | Show available commands |
| `build` | Build fat jar (Gradle) |
| `run` | Run backend locally (requires PostgreSQL) |
| `compile` | Quick compilation check |
| `test` | Run tests |
| `clean` | Clean build artifacts |
| `reset` | Reset local state (`POST /reset`) |

**Local environment:**

| `make` target | Description |
|---------------|-------------|
| `local-up` | Start backend + postgres (Docker Compose) |
| `local-down` | Stop local environment |
| `local-logs` | Tail backend logs (local) |
| `local-frontend` | Serve frontend locally (ports 3000-3005) |

**Docker:**

| `make` target | Description |
|---------------|-------------|
| `docker-push` | Build + push to DockerHub (version tag from `gradle.properties` + `latest`) |

**VPS — Deploy:**

| `make` target | Description |
|---------------|-------------|
| `deploy` | Pull image on VPS + restart containers |
| `deploy-frontend` | Upload frontend to VPS (SCP) |
| `deploy-nginx` | Deploy nginx config + SSL certificates to VPS |
| `full-deploy` | Cleanup + nginx + deploy |
| `cleanup` | Remove old Docker resources on VPS |

**VPS — Operations:**

| `make` target | Description |
|---------------|-------------|
| `ssh` | SSH into VPS |
| `logs` | Tail backend logs in real time |
| `status` | Health check |
| `backup` | Backup PostgreSQL to local |
| `vps-reset` | Reset database (dangerous!) |

**Git sync:**

| `make` target | Description |
|---------------|-------------|
| `pull` | Pull changes from remote |
| `push` | Commit and push all changes (auto-sync with timestamp) |

### Environment variables

| Variable | Defined in | Description |
|----------|-----------|-------------|
| `FIKUA_BASE_URL` | `compose.yaml` | Issuer base URL (`https://issuer.lab.fikua.com`) |
| `FIKUA_PORT` | `compose.yaml` | Backend internal port (`8080`) |
| `FIKUA_DB_URL` | `compose.yaml` | JDBC connection string |
| `FIKUA_DB_USER` | `.env` | PostgreSQL user |
| `FIKUA_DB_PASSWORD` | `.env` | PostgreSQL password |
| `FIKUA_ROLES` | `compose.yaml` | Comma-separated roles to start: `issuer`, `wallet`, `verifier` (default: all) |
| `FIKUA_CERTS_DIR` | `compose.yaml` | X.509 certificates directory inside container |
| `FIKUA_VERSION` | `.env` / shell | Docker image tag (`latest` or `vX.Y.Z`) |
| `DOCKER_REGISTRY` | `.env` | DockerHub registry (`oriolcanades`) |
| `DOCKER_PAT` | `.env` | DockerHub PAT |

## Docker image versioning

The version is read automatically from `suite/backend/gradle.properties` (`version` field). Each push generates two images:

- **`<version>`** — Tag with the project version (e.g., `0.1.0-SNAPSHOT`)
- **`latest`** — Always points to the latest build

```bash
make docker-push      # Build + push with gradle.properties tag + latest
make deploy           # Pull image on VPS + restart
```

To force a different tag:

```bash
FIKUA_VERSION=v1.0.0 make docker-push
FIKUA_VERSION=v1.0.0 make deploy
```

## Rollback and recovery

### Version rollback

```bash
# On VPS, change the version in .env
ssh -p 49222 ubuntu@51.38.179.236
cd /opt/vps/lab
# Edit .env → FIKUA_VERSION=<previous-version>
sudo docker compose --env-file .env -f compose.yaml up -d --force-recreate
```

Or from local:

```bash
FIKUA_VERSION=<previous-version> make deploy
```

### Database reset

```bash
make vps-reset    # Warning: deletes ALL data
```

### Nginx recovery

```bash
make setup-nginx    # Re-upload and reactivate config
```

### If VPS is unresponsive

1. `make ssh` — Verify SSH access
2. `sudo systemctl status docker` — Docker running?
3. `sudo docker compose -f /opt/vps/lab/compose.yaml ps` — Container status
4. `sudo docker compose -f /opt/vps/lab/compose.yaml logs --tail=50` — Recent logs
5. `sudo systemctl status nginx` — Nginx running?
6. `df -h` — Disk full?
7. `free -m` — Out of memory?

## Backups

### PostgreSQL

Low data volume — weekly backup is sufficient.

**Manual backup:**

```bash
make backup    # Download SQL dump to backups/
```

**Direct backup on VPS:**

```bash
make ssh
sudo docker exec fikua-lab-db pg_dump -U fikua fikua > /tmp/backup.sql
```

**Restore:**

```bash
# Copy dump to VPS
scp -P 49222 backups/fikua-lab-backup-XXXXXXXX.sql ubuntu@51.38.179.236:/tmp/

# Restore (overwrites existing data)
make ssh
sudo docker exec -i fikua-lab-db psql -U fikua fikua < /tmp/fikua-lab-backup-XXXXXXXX.sql
```

### What the backup includes

- `profiles` table (JSONB profile configuration)
- `credential_offers` table (active offers)
- `access_tokens` table (issued tokens)
- `verification_sessions` table (OID4VP sessions)

### What the backup does NOT include

- X.509 certificates (regenerable)
- Nginx configuration (versioned at `deployment/envs/dev/nginx-lab.conf`)
- Docker images (available on DockerHub)

## Monitoring

### Health check

```bash
make status                                          # From local (via SSH)
curl -sf https://lab.fikua.com/health | python3 -m json.tool   # From anywhere
```

### Logs

```bash
make logs    # Real-time backend logs (tail -f)
```

Log rotation configured: JSON file, 50MB x 3 files per container (configured in `deployment/envs/dev/docker/compose.yaml`).

### SSL verification

```bash
curl -vI https://lab.fikua.com 2>&1 | grep -E "expire|subject|issuer"
sudo certbot certificates    # On VPS
```

### VPS resources

```bash
make ssh
df -h                    # Disk space
free -m                  # Memory
sudo docker stats --no-stream   # CPU/memory per container
```

### Configured limits

| Container | Max memory |
|-----------|-----------|
| `fikua-lab` (backend) | 1 GB |
| `fikua-lab-db` (PostgreSQL) | 512 MB |

## Certificate renewal

### Let's Encrypt (TLS for nginx)

Certbot automatically installs a systemd timer that renews certificates before expiry.

**Verify the timer is working:**

```bash
make ssh
sudo systemctl status certbot.timer
sudo certbot certificates    # Shows expiration dates
```

**Manual renewal (if needed):**

```bash
make ssh
sudo certbot renew
sudo systemctl reload nginx
```

### X.509 self-signed (for credential signing)

Generated with OpenSSL, valid for 365 days. Stored in the Docker volume `lab-certs` on VPS. Regenerate when expired and redeploy.

## Current implementation status

### Completed

- [x] Gradle mono-repo (Java 25, fikua-core + fikua-issuer + fikua-lab)
- [x] fikua-core: crypto (EcKeyManager, X509CertUtil, JwkUtils)
- [x] fikua-core: OAuth2 (TokenGrant, DPoP, PKCE, errors)
- [x] fikua-core: OID4VCI (metadata, offers, credentials, proofs)
- [x] fikua-core: SD-JWT (build, parse, verify)
- [x] fikua-core: profiles (config, presets, enums)
- [x] fikua-lab: orchestrator (FikuaLab.java, LabConfig, FIKUA_ROLES)
- [x] fikua-lab: database (HikariCP, Flyway, ProfileRepository)
- [x] fikua-lab: admin API (AdminRoutes — profile CRUD)
- [x] fikua-issuer: issuer endpoints (IssuerController — metadata, token, credential, nonce, jwks, offers, authorize, par)
- [x] fikua-issuer: application layer (IssuanceService + ports: SessionStore, IssuanceStore, ProfileStore)
- [x] fikua-issuer: infrastructure adapters (InMemorySessionStore, JdbcIssuanceStore, JdbcProfileStore, PemKeyLoader)
- [x] Frontend: Portal (profile management, presets, health)
- [x] Frontend: Landing page (teal + berry, light/dark mode)
- [x] Frontend: Issuer UI (credential offers, certificate identification)
- [x] Frontend: Cert UI (mTLS certificate selection via browser)
- [x] Frontend: Wallet/Holder UI (credentials, verification history)
- [x] Frontend: Verifier UI (verification requests, results)
- [x] Frontend: Favicons (SVG "F" teal on all frontends)
- [x] Frontend: Shared error pages (404, 50x with dark mode)
- [x] Frontend: Light/dark mode on all frontends
- [x] Deployment: Dockerfile (multi-stage Java 25, backend only)
- [x] Deployment: local environment (compose + local frontend)
- [x] Deployment: dev/VPS environment (compose + deploy-backend.sh + deploy-frontend.sh)
- [x] Deployment: nginx config (subdomains, static/proxy routing)
- [x] Deployment: Makefile targets (local + VPS + git sync)
- [x] Deployment: backup command (pg_dump via SSH)
- [x] Deployment: deploy-frontend.sh (shared assets + 6 frontends)
- [x] CI: GitHub Actions workflow (build + test + Docker push on main)
- [x] Docs: operational sections (deployment, rollback, backups, monitoring, certificates, versioning)
- [x] BUILD SUCCESSFUL (Gradle 8.14 + Java 25)
- [x] nginx: mTLS on cert.lab.fikua.com (ssl_verify_client optional_no_ca)
- [x] nginx: /cert-info endpoint with X-Client-* headers
- [x] nginx: error pages (error_page + internal locations) on all subdomains

### Pending

- [x] **Architecture refactor: Infrastructure-Application-Domain**
  - [x] Purify fikua-core (extract I/O, add SigningKey interface, remove hardcoded paths/schemas)
  - [x] Create fikua-issuer module (IssuanceService + ports + infra adapters from fikua-server)
  - [x] Create fikua-lab orchestrator (FIKUA_ROLES-based startup)
  - [ ] Create fikua-wallet module (HTTP client for OID4VCI)
  - [ ] Create fikua-verifier module (OID4VP endpoints)
  - [x] Retire fikua-server (replaced by fikua-issuer + fikua-lab)
- [ ] Deploy to OVH VPS (Docker Compose)
- [x] Configure DNS lab.fikua.com + issuer.lab.fikua.com + wallet.lab.fikua.com + verifier.lab.fikua.com
- [ ] Generate self-signed X.509 certificates on VPS
- [ ] Pass first OIDF test: Issuer pre-auth code (sd-jwt-vc)
- [x] Implement HAIP Issuer (DPoP, PKCE, PAR, authorization_code) — v0.2.0, 2026-02-18
- [ ] Implement Verifier endpoints (OID4VP, DCQL, JAR signing)
- [ ] Implement Wallet HTTP client
- [ ] Pass all 12 OIDF tests

## Verification checklist

- [ ] `./gradlew build` compiles without errors
- [ ] `./gradlew test` unit tests pass
- [ ] `make local-up` starts backend + postgres
- [ ] `curl https://issuer.lab.fikua.com/.well-known/openid-credential-issuer` returns valid metadata
- [ ] `curl https://issuer.lab.fikua.com/.well-known/oauth-authorization-server` returns valid metadata
- [ ] OIDF "OID4VCI 1.0 Final: Test an issuer" (pre-auth + sd_jwt_vc) passes
- [ ] Portal at `https://portal.lab.fikua.com` shows active profile
- [ ] Profile switching works without redeployment

---

**Note for agents:** When you modify the project (new features, architecture changes, updated dependencies, passed tests), update the relevant sections of this document. Mark completed tasks, add new ones if needed, and keep the stack up to date.
