# Fikua Lab

A hands-on learning lab for OpenID Foundation digital identity protocols. Implements the full Issuer-Wallet-Verifier triangle, profiled by HAIP 1.0 and aligned with eIDAS 2.0 / EUDI ARF 2.8.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## What it does

Fikua Lab is a conformance testing platform built to pass the 12 OIDF conformance tests for credential issuance, presentation, and wallet flows. Every implementation detail is driven by the specs — not a framework.

| Role        | Tests | Standards                                          |
| ----------- | ----- | -------------------------------------------------- |
| **Issuer**  | 4     | OID4VCI 1.0, SD-JWT VC, DPoP, PAR, PKCE            |
| **Wallet**  | 4     | Holder binding, selective disclosure, HAIP 1.0     |
| **Verifier**| 4     | OID4VP 1.0, DCQL, x509_san_dns, x509_hash          |

## Architecture

```text
fikua-core     Pure protocol library (OAuth2, OID4VCI, OID4VP, SD-JWT, crypto)
               Zero I/O, zero state, zero framework dependencies.

fikua-issuer   Issuer service (application layer + infrastructure adapters)
               IssuanceService, ports (SessionStore, IssuanceStore, ProfileStore),
               HTTP controller, JDBC adapters, PEM key loading.

fikua-lab      Orchestrator — reads FIKUA_ROLES and starts services.
               Database, config, admin API, Javalin server.
```

Profiles are stored in PostgreSQL and switchable at runtime via an admin UI — no redeployment needed to switch between OIDF test configurations.

## Stack

| Component    | Technology                                |
| ------------ | ----------------------------------------- |
| Language     | Java 25 (LTS)                             |
| HTTP         | Javalin                                   |
| Database     | PostgreSQL 17                             |
| JWT/Crypto   | nimbus-jose-jwt, Bouncy Castle            |
| Certificates | X.509 self-signed (EC P-256), no DIDs     |
| Frontend     | HTML, CSS, JS (vanilla). Holder: Vite     |
| Tests        | JUnit 5 (unit), k6 (integration + load)   |

## Quick start

```bash
# Build
make build

# Run locally (requires PostgreSQL)
make run

# Docker Compose (full stack)
make local-up

# Serve frontends locally
make local-frontend
```

## Project structure

```text
suite/
  backend/
    Dockerfile            Multi-stage build (Java 25 → JRE)
    compose.local.yaml    Backend + Postgres for dev & CI integration tests
    fikua-core/           Protocol library (crypto, OAuth2, OID4VCI, SD-JWT)
    fikua-issuer/         Issuer service (use cases, ports, adapters, controller)
    fikua-lab/            Orchestrator (config, DB, admin API, role-based startup)
  frontend/
    landing/              Public landing page
    portal/               Profile management UI
    issuer/               Issuer UI
    holder/               Wallet UI (TypeScript + Vite)
    verifier/             Verifier UI
    cert/                 Certificate management UI
    identify/             Identification UI
    shared/               Shared CSS/JS (consent banner, favicon)
  k6/                     Integration + load tests
docs/
  fikua-lab-dt.md         Technical document (source of truth)
  specs/                  Protocol specs and flow docs
  analysis/               OIDF test configurations
```

## Deployment

This repo builds and publishes artefacts; it does **not** deploy to production.

- **Backend:** push to `main` builds + tests + publishes `oriolcanades/fikua-lab:<version>` to Docker Hub. Production infrastructure consumes the image from [`fikua-platform-iac`](https://github.com/fikua/fikua-platform-iac).
- **Frontends:** each subdirectory under `suite/frontend/` is published to Cloudflare Pages independently.

See [`fikua-platform-iac`](https://github.com/fikua/fikua-platform-iac) for the production setup.

## Documentation

- [Document Tècnic](docs/fikua-lab-dt.md) — Source of truth: architecture, stack, brand, implementation status
- [OIDF Test Configurations](docs/analysis/oidf-test-configurations.md) — 12 tests with parameters

## Brand

Fikua Lab shares a visual identity system with [oriolcanades.com](https://oriolcanades.com):

| Role              | Light       | Dark        |
| ----------------- | ----------- | ----------- |
| Accent (teal)     | `#2A9D8F`   | `#2dd4bf`   |
| Highlight (berry) | `#c2185b`   | `#f06292`   |
| Heading           | `#1B263B`   | `#e2e8f0`   |
| Background        | `#ffffff`   | `#0f172a`   |

Shared neutrals create brand cohesion. Berry adds the energy of a startup lab.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Author

Built by [Oriol Canadés](https://oriolcanades.com) — Technical Product Manager specializing in digital identity (SSI/eIDAS2).
