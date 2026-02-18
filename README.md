# Fikua Lab

A hands-on learning lab for OpenID Foundation digital identity protocols. Implements the full Issuer-Wallet-Verifier triangle, profiled by HAIP 1.0 and aligned with eIDAS 2.0 / EUDI ARF 2.8.

## What it does

Fikua Lab is a conformance testing platform built to pass the 12 OIDF conformance tests for credential issuance, presentation, and wallet flows. Every implementation detail is driven by the specs — not a framework.

| Role | Tests | Standards |
|------|-------|-----------|
| **Issuer** | 4 | OID4VCI 1.0, SD-JWT VC, DPoP, PAR, PKCE |
| **Wallet** | 4 | Holder binding, selective disclosure, HAIP 1.0 |
| **Verifier** | 4 | OID4VP 1.0, DCQL, x509_san_dns, x509_hash |

## Architecture

```text
fikua-core     Pure domain logic (OAuth2, OID4VCI, OID4VP, SD-JWT, crypto)
               Zero framework dependencies. Reusable in any context.

fikua-server   HTTP layer (Javalin) + database + configuration
               Calls core logic, exposes endpoints, manages state.
```

Profiles are stored in PostgreSQL and switchable at runtime via an admin UI — no redeployment needed to switch between OIDF test configurations.

## Stack

| Component | Technology |
|-----------|------------|
| Language | Java 25 (LTS) |
| HTTP | Javalin |
| Database | PostgreSQL 17 |
| JWT/Crypto | nimbus-jose-jwt, Bouncy Castle |
| Deployment | Docker Compose + nginx on OVH VPS (EU) |
| Certificates | X.509 self-signed (EC P-256), no DIDs |
| Frontend | HTML, CSS, JS (vanilla) |

## Quick start

```bash
# Build
make build

# Run locally (requires PostgreSQL)
make run

# Docker Compose (full stack)
make local-up

# Preview landing page
make landing
```

## Project structure

```text
suite/
  backend/
    fikua-core/       Protocol library (crypto, OAuth2, OID4VCI, SD-JWT)
    fikua-server/     HTTP endpoints (Javalin, PostgreSQL, admin API)
  frontend/
    landing/          Public landing page
    admin/            Profile management UI
    issuer/           Issuer UI
    holder/           Wallet UI
    verifier/         Verifier UI
deployment/
  Dockerfile          Multi-stage build (Java 25)
  docker-compose.yaml Full stack: backend + postgres + nginx
  nginx/              Reverse proxy + TLS termination
docs/
  architecture/       Implementation plan
  analysis/           OIDF test configurations
```

## Documentation

- [Document Tècnic](docs/fikua-lab-dt.md) — Source of truth: architecture, stack, brand, implementation status
- [OIDF Test Configurations](docs/analysis/oidf-test-configurations.md) — 12 tests with parameters

## Brand

Fikua Lab shares a visual identity system with [oriolcanades.com](https://oriolcanades.com):

| Role | Light | Dark |
|------|-------|------|
| Accent (teal) | `#2A9D8F` | `#2dd4bf` |
| Highlight (berry) | `#c2185b` | `#f06292` |
| Heading | `#1B263B` | `#e2e8f0` |
| Background | `#ffffff` | `#0f172a` |

Shared neutrals create brand cohesion. Berry adds the energy of a startup lab.

## Author

Built by [Oriol Canadés](https://oriolcanades.com) — Technical Product Manager specializing in digital identity (SSI/eIDAS2).
