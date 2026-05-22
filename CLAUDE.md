# Fikua Lab — Instruccions per a Claude Code

## Projecte

Fikua Lab és una plataforma d'aprenentatge i testing de conformitat per protocols d'Identitat Digital. Implementa el triangle Issuer-Holder-Verifier seguint les especificacions de l'OpenID Foundation, perfilades per HAIP 1.0 i alineades amb l'EUDI Architecture Reference Framework (ARF) 2.8.

## Source of truth

| Document | Path | Propòsit |
|----------|------|----------|
| Technical Document | `docs/fikua-lab-dt.md` | Arquitectura, decisions, endpoints |
| Credential Issuance Flow | `docs/specs/credential-issuance-flow.md` | Spec tècnica del flux d'emissió (15 passos, gaps, prioritats) |
| OIDF Test Configurations | `docs/analysis/oidf-test-configurations.md` | 12 tests OIDF amb paràmetres configurables |
| References | `docs/specs/references.md` | Index de specs, RFCs i recursos externs |

**Llegeix sempre `docs/fikua-lab-dt.md` abans de qualsevol canvi.** Actualitza'l quan facis canvis significatius a l'arquitectura o endpoints.

## Estructura del repo

```text
fikua-lab/
├── suite/
│   ├── backend/             Java multi-module (fikua-core, fikua-issuer, fikua-lab)
│   │   ├── Dockerfile       Imatge de producció publicada a Docker Hub
│   │   └── compose.local.yaml  Backend + Postgres per dev/test local
│   ├── frontend/            7 frontends + shared/ (HTML/CSS/JS, holder amb Vite)
│   └── k6/                  Tests de càrrega i integració
├── dev-tools/               Eines locals (cert builders, etc.)
├── docs/                    Documentació tècnica i specs
└── .github/workflows/ci.yml CI: build + test + Docker push + GitHub release
```

## Deployment

**Aquest repo NO desplega a producció.** Construeix i publica artefactes; la infraestructura els consumeix.

- **Backend:** push a `main` → CI publica `oriolcanades/fikua-lab:<version>` a Docker Hub. La VPS la consumeix via [`fikua-platform-iac`](https://github.com/fikua/fikua-platform-iac) (`projects/fikua-lab/backend/compose.yaml`).
- **Frontends:** cada subdirectori de `suite/frontend/` és un projecte Cloudflare Pages independent. `shared/` es copia al pre-build de cada projecte.
- **`compose.local.yaml`** és només per a desenvolupament i CI integration tests; no per a producció.

## Idioma

- Codi: anglès (noms de variables, classes, mètodes, comentaris)
- Documentació tècnica (`docs/`): català o anglès segons el document existent
- Commits: anglès
- Comunicació amb l'usuari: català

## Stack tècnic

| Decisió       | Elecció                                                                       |
| ------------- | ----------------------------------------------------------------------------- |
| Backend       | Java 25, Javalin 6.6.0, nimbus-jose-jwt 10.2                                  |
| Frontend      | Vanilla HTML/CSS/JS (no build step, no frameworks). Holder: TypeScript + Vite |
| Base de dades | PostgreSQL 17, Flyway migrations                                              |
| Tests         | JUnit 5, k6 (integració + càrrega)                                            |
| Build         | Gradle (multi-module: fikua-core, fikua-issuer, fikua-lab)                    |

## Constitució — regles immutables

Aquestes regles NO es poden violar. Si un gap o spec entra en conflicte amb una regla, PARA i informa l'usuari.

### Arquitectura

- **`fikua-core` té zero dependències de framework, zero I/O, zero estat.** Només nimbus-jose-jwt, Jackson i slf4j-api.
- **`fikua-issuer` depèn de `fikua-core`. `fikua-lab` depèn de `fikua-issuer`.** Mai dependències inverses.
- **Tota la lògica de validació de protocols va a `fikua-core`.** Els serveis (issuer, wallet, verifier) tenen capa Application (use cases + ports) i Infrastructure (HTTP, DB, crypto).
- **No ORM.** Queries SQL directes amb JDBC + Flyway migrations.
- **No caching implícit.** State management explícit via `InMemoryStore` (dev) o PostgreSQL (prod).
- **Un fitxer, una responsabilitat.** No helper classes genèriques. No `Utils.java`.

### Codi

- **Java records per tot value object.** Mai classes mutables per DTOs, metadata, requests o responses.
- **`@JsonProperty` explícit a tots els camps de records** que es serialitzen a JSON. Mai confiar en naming automàtic.
- **`@JsonInclude(NON_NULL)` a tots els records de resposta.** Els camps opcionals es representen com `null`, no amb Optional.
- **No Lombok.** Records natius de Java.
- **Null check a les fronteres del sistema** (input HTTP, JSON parsing). Dins de `fikua-core`, els paràmetres són non-null per contracte.
- **Tots els valors literals de protocol** (`dc+sd-jwt`, `openid4vci-proof+jwt`, etc.) **són constants `static final`** definides un sol cop.

### Testing

- **Tot gap implementat requereix un test.** P0: test unitari del record/builder + validació JSON output. P1-P2: test d'integració del flow. P3: test manual documentat.
- **Tests a `src/test/java/` seguint package mirror.** `com.fikua.core.oid4vci.CredentialIssuerMetadataTest` per `CredentialIssuerMetadata`.
- **Cada test verifica conformitat amb la spec**, no implementació interna. Assertar sobre el JSON output, no sobre camps interns.
- **El build (`./gradlew build`) inclou els tests.** Si un test falla, el build falla. No hi ha excuses per saltar-los.

## Convencions de codi

- Packages: `com.fikua.core.*` (domini pur), `com.fikua.issuer.*` (servei issuer: app + infra), `com.fikua.lab.*` (orchestrador)
- Endpoints: prefix `/oid4vci/v1/` per issuer, `.well-known/` per metadata
- Frontend: IIFE pattern `(() => { ... })()`, no modules

## Metodologia

**Spec Driven Development:** Els specs defineixen el "què" i el "com tècnicament".

1. L'usuari defineix/valida l'spec (`docs/specs/`)
2. S'implementa seguint l'spec
3. Es revisa que la implementació compleix l'spec
4. L'usuari valida amb tests OIDF

## Regles generals

- Mai canviar `docs/specs/credential-issuance-flow.md` durant la implementació sense confirmar amb l'usuari
- Mai fer push sense confirmació de l'usuari
- Compilar després de cada canvi: `cd suite/backend && ./gradlew build`
- No sobre-enginyeritzar: codi mínim per complir l'spec
