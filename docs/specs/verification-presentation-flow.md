# Verification & Presentation Flow — Especificació tècnica

**Created:** 2026-02-25
**Updated:** 2026-02-25
**Status:** Draft
**Normativa:** OID4VP 1.0 Final, HAIP 1.0, SD-JWT VC draft-14, ARF 2.8

---

## Resum

Aquest document defineix el flux complet de verificació/presentació de credencials a Fikua Lab, des que el verifier inicia una sol·licitud de presentació fins que rep i valida el VP Token. Cobreix els dos perfils suportats (Plain i HAIP) i identifica els gaps entre la implementació actual i les especificacions.

El document complementa `credential-issuance-flow.md` (emissió OID4VCI) amb el segon flux principal del triangle: la presentació OID4VP entre Verifier i Wallet.

## Normativa de referència

```text
ARF 2.8 (EU regulatory layer: Trusted Lists, WUA/WIA, signed metadata, ETSI certs)
  └── HAIP 1.0 (technical profile: x509_hash, DCQL, direct_post.jwt, ECDH-ES, JAR, KB-JWT)
       └── OID4VP 1.0 Final (presentation) + SD-JWT VC draft-14 (credential format)
```

| Spec | URL |
|------|-----|
| OID4VP 1.0 Final | [openid.net/specs/openid-4-verifiable-presentations-1_0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) |
| HAIP 1.0 | [openid.github.io/OpenID4VC-HAIP](https://openid.github.io/OpenID4VC-HAIP/openid4vc-high-assurance-interoperability-profile-wg-draft.html) |
| SD-JWT VC draft-14 | [datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) |
| RFC 9101 (JAR) | [rfc-editor.org/rfc/rfc9101](https://www.rfc-editor.org/rfc/rfc9101) |
| RFC 7516 (JWE) | [rfc-editor.org/rfc/rfc7516](https://www.rfc-editor.org/rfc/rfc7516) |

---

## Perfils suportats

| Paràmetre | Plain Verifier | HAIP Verifier |
|-----------|---------------|---------------|
| Client ID Prefix | `x509_san_dns` | `x509_hash` |
| Response Mode | `direct_post` | `direct_post.jwt` (encriptat) |
| Query Language | Scope (DCQL opcional) | `dcql` (obligatori) |
| Authorization Request | JAR signat (`request_uri`) | JAR signat (`request_uri`) |
| Response Encryption | Cap | `ECDH-ES` + `A128GCM`/`A256GCM` |
| Credential Format | `dc+sd-jwt` | `dc+sd-jwt` |
| KB-JWT (Key Binding) | Recomanat | Obligatori |
| Test OIDF | Test #6 | Test #5 |

### Client ID Prefix

| Prefix | Format `client_id` | Clau de signatura |
|--------|--------------------|-------------------|
| `x509_san_dns` | `x509_san_dns:verifier.lab.fikua.com` | Clau privada del certificat X.509, SAN conté el DNS |
| `x509_hash` | `x509_hash:<base64url-sha256-der-cert>` | Clau privada del certificat X.509, hash del cert DER |

**Spec OID4VP §5.9.3:** El wallet detecta el prefix per la presència de `:` al `client_id`. Valida la signatura del Request Object contra el certificat a `x5c` del JOSE header.

### Response Mode

| Mode | Transmissió | Encriptació |
|------|-------------|-------------|
| `direct_post` | HTTP POST form-urlencoded a `response_uri` | Cap |
| `direct_post.jwt` | HTTP POST amb JWE a `response_uri` | ECDH-ES + A128GCM/A256GCM |

---

## Flux complet (10 passos)

### Diagrama general

```text
VERIFIER                               WALLET                          ISSUER
   │                                      │                               │
   │  1. Crea Authorization Request       │                               │
   │     (DCQL query, nonce, state)       │                               │
   │                                      │                               │
   │  2. Presenta request_uri             │                               │
   │     (QR code / deep link)            │                               │
   │  ──────────────────────────────────→ │                               │
   │                                      │                               │
   │  3. Wallet GET/POST request_uri      │                               │
   │ ←────────────────────────────────── │                               │
   │     Retorna signed Request Object    │                               │
   │  ──────────────────────────────────→ │                               │
   │                                      │                               │
   │                                      │  4. Wallet valida Request     │
   │                                      │     Object (signatura, x5c,   │
   │                                      │     client_id, nonce)         │
   │                                      │                               │
   │                                      │  5. Wallet selecciona         │
   │                                      │     credencial i disclosures  │
   │                                      │     (matching DCQL query)     │
   │                                      │                               │
   │                                      │  6. Wallet construeix VP      │
   │                                      │     Token (SD-JWT + KB-JWT)   │
   │                                      │                               │
   │                                      │  7. (HAIP) Wallet encripta    │
   │                                      │     resposta amb JWE          │
   │                                      │                               │
   │  8. Wallet POST VP Token             │                               │
   │     a response_uri                   │                               │
   │ ←────────────────────────────────── │                               │
   │                                      │                               │
   │  9. Verifier valida VP Token         │                               │
   │     (signatura issuer, KB-JWT,       │                               │
   │      nonce, disclosures, status)     │                               │
   │                                      │                               │
   │ 10. Verifier retorna resultat        │                               │
   │  ──────────────────────────────────→ │                               │
   │     { redirect_uri } (same-device)   │                               │
```

---

### Pas 1 — Verifier crea Authorization Request

El verifier genera un Authorization Request amb els paràmetres necessaris per sol·licitar una presentació.

**Spec OID4VP §5.1-5.2:**

| Paràmetre | Spec | Descripció |
|-----------|------|------------|
| `response_type` | REQUIRED | `"vp_token"` |
| `client_id` | REQUIRED | Amb prefix: `x509_san_dns:verifier.lab.fikua.com` o `x509_hash:<hash>` |
| `response_mode` | REQUIRED | `"direct_post"` o `"direct_post.jwt"` |
| `response_uri` | REQUIRED (direct_post) | URL on el wallet envia la resposta |
| `nonce` | REQUIRED | Valor criptogràfic aleatori, mínim 128 bits, ASCII URL-safe |
| `state` | REQUIRED (sense holder binding) | Valor criptogràfic per lligar request i response |
| `dcql_query` | REQUIRED (si no `scope`) | Query DCQL (veure Pas 1.1) |
| `scope` | REQUIRED (si no `dcql_query`) | Scope predefinit que mapeja a una DCQL query |
| `client_metadata` | OPTIONAL | Metadata del verifier (jwks per encriptació, formats suportats) |

**Authorization Request Object (JAR — JWT signat):**

```text
Header:
{
  "typ": "oauth-authz-req+jwt",
  "alg": "ES256",
  "x5c": ["<verifier-cert-base64>"]
}

Payload:
{
  "response_type": "vp_token",
  "client_id": "x509_san_dns:verifier.lab.fikua.com",
  "response_mode": "direct_post",
  "response_uri": "https://verifier.lab.fikua.com/oid4vp/v1/response",
  "nonce": "n-0S6_WzA2Mj",
  "state": "af0ifjsldkj",
  "dcql_query": {
    "credentials": [
      {
        "id": "identity_credential",
        "format": "dc+sd-jwt",
        "meta": {
          "vct_values": ["urn:eu.europa.ec.eudi:pid:1"]
        },
        "claims": [
          { "path": ["given_name"] },
          { "path": ["family_name"] },
          { "path": ["birth_date"] }
        ]
      }
    ]
  },
  "client_metadata": {
    "vp_formats_supported": {
      "dc+sd-jwt": {
        "sd-jwt_alg_values": ["ES256"]
      }
    },
    "jwks": {
      "keys": [{ "kty": "EC", "crv": "P-256", "x": "...", "y": "...", "use": "enc" }]
    },
    "encrypted_response_enc_values_supported": ["A128GCM", "A256GCM"]
  },
  "aud": "https://self-issued.me/v2",
  "iss": "x509_san_dns:verifier.lab.fikua.com",
  "iat": 1709000000,
  "exp": 1709000300
}
```

**Spec OID4VP §5.2 — Normativa JAR:**
- El verifier MUST incloure `typ: oauth-authz-req+jwt` al header del Request Object.
- El wallet MUST NOT processar Request Objects sense `typ: oauth-authz-req+jwt`.
- Per `x509_san_dns` i `x509_hash`, la signatura es fa amb la clau privada del certificat X.509. El certificat va a `x5c` del JOSE header.

#### Pas 1.1 — DCQL Query (Digital Credentials Query Language)

**Spec OID4VP §6:**

```json
{
  "credentials": [
    {
      "id": "identity_credential",
      "format": "dc+sd-jwt",
      "meta": {
        "vct_values": ["urn:eu.europa.ec.eudi:pid:1"]
      },
      "claims": [
        { "path": ["given_name"], "essential": true },
        { "path": ["family_name"], "essential": true },
        { "path": ["birth_date"] }
      ]
    }
  ]
}
```

| Camp | Spec | Descripció |
|------|------|------------|
| `credentials` | REQUIRED | Array de credential queries |
| `credentials[].id` | REQUIRED | Identificador únic dins la query |
| `credentials[].format` | REQUIRED | Format de la credencial (`dc+sd-jwt`) |
| `credentials[].meta` | OPTIONAL | Metadades específiques del format |
| `credentials[].meta.vct_values` | Per dc+sd-jwt | Array de VCT URIs per filtrar |
| `credentials[].claims` | OPTIONAL | Array de claims sol·licitats |
| `credentials[].claims[].path` | REQUIRED | Path del claim (array de strings) |
| `credentials[].claims[].values` | OPTIONAL | Valors acceptats (OR logic) |
| `credentials[].claims[].essential` | OPTIONAL | `true` = el wallet MUST satisfer aquest claim |

**HAIP §5:** DCQL query i response MUST ser usats. `aki`-based Trusted Authority Query MUST ser suportat.

**Implementació actual:** El package `com.fikua.core.oid4vp` existeix però és buit. No hi ha cap tipus de domini per DCQL.

**Gaps:**

- [ ] Core: crear record `DcqlQuery` amb `credentials` array
- [ ] Core: crear record `CredentialQuery` amb `id`, `format`, `meta`, `claims`
- [ ] Core: crear record `ClaimQuery` amb `path`, `values`, `essential`
- [ ] Core: crear builder per construir DCQL queries per EUDI PID i LEAR

---

### Pas 2 — Verifier presenta l'Authorization Request

El verifier genera una URL amb `request_uri` que apunta al Request Object signat, i la presenta al wallet de dues maneres:

**Same-device (deep link):**

```text
openid4vp://?client_id=x509_san_dns%3Averifier.lab.fikua.com&request_uri=https%3A%2F%2Fverifier.lab.fikua.com%2Foid4vp%2Fv1%2Frequest%2F{session_id}
```

Per same-device amb wallet web (Fikua Lab), s'utilitza HTTPS:

```text
https://wallet.lab.fikua.com/?vp_request_uri=https%3A%2F%2Fverifier.lab.fikua.com%2Foid4vp%2Fv1%2Frequest%2F{session_id}&client_id=x509_san_dns%3Averifier.lab.fikua.com
```

**Cross-device (QR code):**

El QR conté la URL amb custom scheme `openid4vp://`. El wallet mòbil escaneja el QR.

**Per als tests OIDF:**

L'OIDF conformance suite actua com a wallet (Tests #5, #6). Necessita la URL de l'Authorization Request per iniciar el flux. Cal que la URL sigui visible i copiable al frontend de verifier.lab.

**Spec OID4VP §5.4 — Authorization Request by reference:**

```
GET /authorize?
  client_id=x509_san_dns%3Averifier.lab.fikua.com
  &request_uri=https%3A%2F%2Fverifier.lab.fikua.com%2Foid4vp%2Fv1%2Frequest%2F{session_id}
```

**Implementació actual:**

- El frontend de verifier té una UI demo que genera URLs demo amb dades hardcoded.
- No hi ha cap backend endpoint que generi sessions ni Request Objects.

**Gaps:**

- [ ] Backend: crear endpoint `POST /oid4vp/v1/session` que genera una sessió amb Authorization Request
- [ ] Backend: crear endpoint `GET /oid4vp/v1/request/{session_id}` que retorna el signed Request Object
- [ ] Frontend: connectar botó "Verify" al backend per crear sessió real
- [ ] Frontend: generar QR code amb la URL `openid4vp://`
- [ ] Frontend: mostrar URL copiable per tests OIDF

---

### Pas 3 — Wallet obté el Request Object

El wallet, amb la `request_uri`, fa una petició HTTP per obtenir el signed Request Object.

**Spec OID4VP §5.4, §5.10:**

- Si `request_uri_method` és absent o `"get"`: el wallet fa GET a la `request_uri`
- Si `request_uri_method` és `"post"`: el wallet fa POST amb `wallet_metadata` i `wallet_nonce`

**GET (per defecte):**

```http
GET /oid4vp/v1/request/{session_id} HTTP/1.1
Host: verifier.lab.fikua.com
Accept: application/oauth-authz-req+jwt
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/oauth-authz-req+jwt

eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QiLCJ4NWMiOlsiLi4uIl19...
```

El body és el JWT signat (Request Object) amb tots els paràmetres de l'Authorization Request.

**POST (advanced — HAIP opcional):**

```http
POST /oid4vp/v1/request/{session_id} HTTP/1.1
Host: verifier.lab.fikua.com
Content-Type: application/x-www-form-urlencoded
Accept: application/oauth-authz-req+jwt

wallet_metadata=%7B%22vp_formats_supported%22%3A...%7D&wallet_nonce=qPmxiNFCR3QTm19POc8u
```

Permet al wallet comunicar les seves capacitats al verifier abans que aquest generi la query final.

**Implementació actual:** No existeix cap endpoint `request_uri`.

**Gaps:**

- [ ] Backend: implementar `GET /oid4vp/v1/request/{session_id}` retornant JWT signat
- [ ] Backend: opcionalment suportar POST amb `wallet_metadata` (P2)
- [ ] Backend: signar el Request Object amb la clau del verifier (ES256 + x5c)
- [ ] Wallet: fer GET a la `request_uri` per obtenir el Request Object

---

### Pas 4 — Wallet valida el Request Object

El wallet parseja el JWT del Request Object i el valida.

**Spec OID4VP §5.2, §5.9.3:**

Validacions obligatòries:

1. **typ header:** MUST ser `oauth-authz-req+jwt`
2. **Signatura:** Verificar amb la clau pública del certificat a `x5c`
3. **Client ID prefix:**
   - `x509_san_dns`: verificar que el SAN del certificat leaf conté el DNS del `client_id`
   - `x509_hash`: verificar que el hash SHA-256 del cert DER coincideix amb el valor al `client_id`
4. **nonce:** Present i ben format
5. **response_type:** MUST ser `vp_token`
6. **response_mode:** Suportat pel wallet
7. **response_uri:** URL HTTPS vàlida
8. **dcql_query o scope:** Present

**Implementació actual:** No existeix cap lògica de validació de Request Objects al wallet.

**Gaps:**

- [ ] Wallet: parsejar JWT (split `.`, base64url decode header + payload)
- [ ] Wallet: verificar signatura ES256 amb Web Crypto API contra `x5c`
- [ ] Wallet: validar `typ`, `client_id`, `response_type`, `nonce`
- [ ] Wallet: parsejar DCQL query o scope
- [ ] Wallet: mostrar UI de consentiment amb el que el verifier demana

---

### Pas 5 — Wallet selecciona credencial i disclosures

El wallet busca a la seva store una credencial que coincideixi amb la DCQL query.

**Spec OID4VP §6.4 — Selection Processing:**

1. Buscar credencials amb `format` = `dc+sd-jwt`
2. Filtrar per `meta.vct_values` (el VCT de la credencial ha de coincidir)
3. Per cada `claims[].path`, verificar que la credencial conté el claim (via disclosures)
4. Si `essential: true`, el claim MUST existir
5. Seleccionar les disclosures que coincideixen amb els claims demanats (selective disclosure)

**Exemple:**

```text
DCQL demana: given_name, family_name, birth_date
Credencial SD-JWT té disclosures: given_name, family_name, birth_date, issuing_authority, issuing_country
Wallet selecciona: given_name, family_name, birth_date (3 de 5 disclosures)
```

**Implementació actual:**

- El wallet frontend (TypeScript) té `storage.ts` amb IndexedDB per credencials i `sdjwt.ts` per parsejar SD-JWT.
- No hi ha lògica de matching DCQL → credencials.

**Gaps:**

- [ ] Wallet: implementar matching DCQL query → credencials guardades (per VCT)
- [ ] Wallet: implementar selecció de disclosures segons els claims demanats
- [ ] Wallet: mostrar UI de consentiment amb claims seleccionats i opció de desmarcar opcionals

---

### Pas 6 — Wallet construeix VP Token (SD-JWT + KB-JWT)

El wallet construeix el VP Token: una SD-JWT presentació amb les disclosures seleccionades i una Key Binding JWT.

**Spec SD-JWT VC draft-14, OID4VP Appendix B.3:**

```text
SD-JWT Presentation = <Issuer-JWT>~<Disclosure1>~<Disclosure2>~<KB-JWT>
```

On:

- **Issuer-JWT**: El JWT original signat per l'issuer (sense canvis)
- **Disclosures**: Només les disclosures seleccionades (subset de les originals)
- **KB-JWT**: Key Binding JWT signat pel wallet amb la clau privada vinculada a la credencial

**Key Binding JWT (KB-JWT):**

```text
Header:
{
  "typ": "kb+jwt",
  "alg": "ES256"
}

Payload:
{
  "iat": <timestamp>,
  "aud": "<client_id del verifier>",
  "nonce": "<nonce del Authorization Request>",
  "sd_hash": "<base64url(SHA-256(SD-JWT sense KB-JWT))>"
}
```

| Camp | Spec | Descripció |
|------|------|------------|
| `typ` | REQUIRED | `"kb+jwt"` |
| `aud` | REQUIRED | El `client_id` del verifier (inclou prefix) |
| `nonce` | REQUIRED | El nonce de l'Authorization Request |
| `sd_hash` | REQUIRED | Hash SHA-256 de l'SD-JWT serialitzat sense KB-JWT |
| `iat` | REQUIRED | Timestamp |

**HAIP §6.1.1.1:** La KB-JWT MUST sempre estar present quan es presenta una credencial amb holder binding.

**Implementació actual:** No existeix cap lògica de construcció de VP Token ni KB-JWT.

**Gaps:**

- [ ] Core: crear `KbJwtBuilder` per construir i signar KB-JWT
- [ ] Core: crear `VpTokenBuilder` per muntar SD-JWT presentation amb disclosures seleccionades + KB-JWT
- [ ] Wallet: implementar `buildVpToken()` usant Web Crypto API per signar KB-JWT

---

### Pas 7 — (HAIP) Wallet encripta resposta amb JWE

Per HAIP (`direct_post.jwt`), el wallet encripta tota la resposta en un JWE.

**Spec OID4VP §8.3.1, HAIP §5:**

L'encriptació usa la clau pública efímera del verifier, proporcionada a `client_metadata.jwks`.

**JWE Structure:**

```text
Header:
{
  "alg": "ECDH-ES",
  "enc": "A128GCM",
  "kid": "<key-id-from-verifier-jwks>"
}

Payload (plaintext JWT):
{
  "vp_token": "<sd-jwt-presentation-with-kb-jwt>",
  "presentation_submission": { ... },
  "state": "<state-from-request>",
  "aud": "<client_id>",
  "iss": "https://self-issued.me/v2",
  "iat": <timestamp>,
  "exp": <timestamp>
}
```

**HAIP §5 — Requeriments criptogràfics:**

| Paràmetre | Requeriment |
|-----------|-------------|
| JWE `alg` | `ECDH-ES` amb corba P-256 (MUST suportar) |
| JWE `enc` | `A128GCM` i `A256GCM` (verifiers MUST suportar ambdós, wallets MUST suportar mínim un, SHOULD preferir A256GCM) |
| Clau encriptació | Efímera, específica per cada Authorization Request |

**Per Plain (`direct_post`):** No s'encripta. El VP Token s'envia directament com a form parameter.

**Implementació actual:** No existeix cap lògica de JWE al wallet ni al verifier.

**Gaps:**

- [ ] Core: suport per JWE encryption/decryption (ECDH-ES + A128GCM/A256GCM) usant nimbus-jose-jwt
- [ ] Verifier: generar clau efímera EC P-256 per cada sessió i incloure-la a `client_metadata.jwks`
- [ ] Wallet: encriptar resposta amb la clau pública del verifier (Web Crypto JWE o via backend)

---

### Pas 8 — Wallet POST VP Token a response_uri

El wallet envia la resposta al verifier via HTTP POST.

**Spec OID4VP §8.2:**

#### Plain (direct_post)

```http
POST /oid4vp/v1/response HTTP/1.1
Host: verifier.lab.fikua.com
Content-Type: application/x-www-form-urlencoded

vp_token=<sd-jwt-presentation>&presentation_submission=%7B...%7D&state=af0ifjsldkj
```

#### HAIP (direct_post.jwt)

```http
POST /oid4vp/v1/response HTTP/1.1
Host: verifier.lab.fikua.com
Content-Type: application/x-www-form-urlencoded

response=<jwe-token>&state=af0ifjsldkj
```

**Presentation Submission:**

```json
{
  "id": "<unique-id>",
  "definition_id": "<matches-dcql-query-id>",
  "descriptor_map": [
    {
      "id": "identity_credential",
      "format": "dc+sd-jwt",
      "path": "$"
    }
  ]
}
```

**Nota:** Amb DCQL, la presentation_submission pot ser simplificada o implícita. El mapping entre `credentials[].id` i el `vp_token` és directe.

**Implementació actual:** No existeix cap endpoint `response_uri`.

**Gaps:**

- [ ] Backend: crear endpoint `POST /oid4vp/v1/response` que rep VP Token
- [ ] Backend: parsejar form params (plain) o desencriptar JWE (HAIP)
- [ ] Backend: validar `state` contra la sessió guardada
- [ ] Wallet: construir i enviar HTTP POST amb VP Token

---

### Pas 9 — Verifier valida VP Token

El verifier rep el VP Token i el valida completament.

**Spec OID4VP §8, SD-JWT VC draft-14, HAIP §7:**

Validacions obligatòries:

1. **state:** Coincideix amb el guardat a la sessió
2. **Desencriptar JWE** (si `direct_post.jwt`)
3. **Parsejar SD-JWT presentation:** Separar Issuer-JWT, disclosures, KB-JWT per `~`
4. **Validar signatura Issuer-JWT:**
   - Verificar signatura ES256
   - Verificar `x5c` chain against trusted issuers
   - Verificar `vct` coincideix amb el demanat
   - Verificar `exp` (no expirat)
   - Verificar `iss` (issuer esperat)
5. **Validar disclosures:**
   - Cada disclosure hasheja correctament al `_sd` array del payload
   - Les disclosures cobreixen els claims sol·licitats
6. **Validar KB-JWT:**
   - `typ` = `kb+jwt`
   - Signatura vàlida amb la clau de `cnf.jwk` del payload de l'Issuer-JWT
   - `aud` = `client_id` del verifier
   - `nonce` = nonce de l'Authorization Request original
   - `sd_hash` = SHA-256 de l'SD-JWT serialitzat sense KB-JWT
   - `iat` dins de rang acceptable
7. **Verificar status** (opcional):
   - Si la credencial té `status.status_list`, fer GET al status list token
   - Verificar que el bit a `idx` és `0x00` (VALID)
8. **Extreure claims** de les disclosures verificades

**Implementació actual:** `SdJwtVerifier` a `fikua-core` ja verifica signatura, expiració i resol claims. Falta KB-JWT i status.

**Gaps:**

- [ ] Core: crear `KbJwtValidator` per validar KB-JWT (aud, nonce, sd_hash, signatura)
- [ ] Core: crear `VpTokenValidator` que orquestra la validació completa (issuer sig + disclosures + KB-JWT)
- [ ] Core: ampliar `SdJwtVerifier` per verificar disclosures individualment contra `_sd`
- [ ] Backend: integrar validació al endpoint `POST /oid4vp/v1/response`
- [ ] Backend: verificar `x5c` chain del issuer contra trusted issuers configurats

---

### Pas 10 — Verifier retorna resultat

Després de validar el VP Token, el verifier retorna el resultat.

**Spec OID4VP §8.2:**

**Same-device:** El verifier respon amb un `redirect_uri` al body JSON:

```json
{
  "redirect_uri": "https://verifier.lab.fikua.com/oid4vp/v1/result/{session_id}"
}
```

El wallet ha de seguir el redirect per tornar a la pàgina del verifier.

**Cross-device:** El verifier processa la resposta i actualitza la seva UI (polling o WebSocket).

**Error response:**

```json
{
  "error": "invalid_request",
  "error_description": "VP Token validation failed: KB-JWT nonce mismatch"
}
```

**Implementació actual:** No existeix cap lògica de resultat.

**Gaps:**

- [ ] Backend: retornar `redirect_uri` al wallet després de validar VP Token
- [ ] Backend: crear endpoint `GET /oid4vp/v1/result/{session_id}` amb el resultat
- [ ] Frontend: polling o SSE per actualitzar la UI quan arriba la resposta (cross-device)
- [ ] Frontend: mostrar claims verificats o error

---

## Verification Session — Model

Model persistent (PostgreSQL) que registra cada sessió de verificació.

```sql
CREATE TABLE verification_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    state           VARCHAR(255) NOT NULL UNIQUE,
    nonce           VARCHAR(255) NOT NULL,
    dcql_query      JSONB NOT NULL,
    response_mode   VARCHAR(50) NOT NULL,
    client_id       VARCHAR(512) NOT NULL,
    response_uri    VARCHAR(512) NOT NULL,
    encryption_key  JSONB,                          -- Clau efímera JWK per HAIP
    request_jwt     TEXT,                            -- Signed Request Object (JWT)
    status          VARCHAR(50) NOT NULL DEFAULT 'pending',
    vp_token        TEXT,                            -- VP Token rebut
    verified_claims JSONB,                           -- Claims extrets després de validació
    error           TEXT,                            -- Error si la validació falla
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT now(),
    completed_at    TIMESTAMP WITH TIME ZONE DEFAULT now()
);
```

**Estats del lifecycle:**

```text
pending → request_sent → response_received → verified / failed
```

---

## Verifier Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/oid4vp/v1/session` | Crear sessió de verificació (genera Authorization Request) |
| GET | `/oid4vp/v1/request/{session_id}` | Retorna signed Request Object (JWT) |
| POST | `/oid4vp/v1/response` | Rep VP Token del wallet (direct_post) |
| GET | `/oid4vp/v1/result/{session_id}` | Consulta resultat de la verificació |

**Nota:** No hi ha `.well-known` per al verifier. La metadata es transmet inline via `client_metadata` al Request Object.

---

## Wallet Endpoints (OID4VP)

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/oid4vp/v1/present` | (Futur) Backend wallet rep request i retorna VP Token |

Per Fikua Lab, la lògica de presentació viu principalment al frontend TypeScript del wallet. El backend wallet opcionalment pot exposar endpoints per a fluxos que requereixen signatura server-side.

---

## Arbre de fitxers rellevants

```text
suite/backend/
├── fikua-core/src/main/java/com/fikua/core/
│   ├── oid4vp/
│   │   ├── AuthorizationRequest.java           ← P0: Request Object params
│   │   ├── DcqlQuery.java                      ← P0: DCQL query model
│   │   ├── CredentialQuery.java                ← P0: Individual credential query
│   │   ├── ClaimQuery.java                     ← P0: Claim path + essential
│   │   ├── KbJwt.java                          ← P1: KB-JWT builder/validator
│   │   ├── VpToken.java                        ← P1: VP Token builder/validator
│   │   └── JweUtil.java                        ← P2: JWE encrypt/decrypt
│   └── sdjwt/
│       └── SdJwtVerifier.java                  ← Ampliar per VP validation
│
├── fikua-verifier/
│   ├── build.gradle.kts                        ← P0: crear mòdul
│   └── src/main/java/com/fikua/verifier/
│       ├── app/
│       │   ├── VerificationService.java        ← P1: Orchestration
│       │   └── port/
│       │       ├── SessionStore.java           ← P0: Ephemeral sessions
│       │       └── VerificationStore.java      ← P1: Persistent records
│       ├── infra/
│       │   ├── InMemorySessionStore.java       ← P0: Sessions en memòria
│       │   ├── JdbcVerificationStore.java      ← P1: JDBC adapter
│       │   └── http/VerifierController.java    ← P0: HTTP controllers
│       └── VerifierService.java                ← P0: Wiring entry point
│
├── fikua-lab/
│   └── src/main/java/com/fikua/lab/
│       └── FikuaLab.java                       ← Activar role "verifier"
│
suite/frontend/
├── verifier/
│   ├── index.html                              ← Connectar amb backend real
│   └── app.js                                  ← Reemplaçar demo amb crides API
├── holder/src/
│   ├── types.ts                                ← Afegir OID4VP types
│   ├── protocol.ts                             ← Afegir VP flow handlers
│   └── main.ts                                 ← Afegir UI de presentació
```

---

## Gaps consolidats per prioritat

### P0 — Estructura base verifier + domain types (prerequisit per tot)

#### P0.1 — Crear mòdul `fikua-verifier` (Gradle)

**Fitxers:**
- `suite/backend/fikua-verifier/build.gradle.kts`
- `suite/backend/settings.gradle.kts` (afegir `include("fikua-verifier")`)
- `suite/backend/fikua-lab/build.gradle.kts` (afegir dependency)

Seguir el patró de `fikua-issuer`:

```kotlin
// fikua-verifier/build.gradle.kts
dependencies {
    implementation(project(":fikua-core"))
    implementation("io.javalin:javalin:${javalinVersion}")
    // PostgreSQL + HikariCP per persistence
}
```

#### P0.2 — Domain types OID4VP a `fikua-core`

**Fitxer:** `suite/backend/fikua-core/src/main/java/com/fikua/core/oid4vp/`

Records a crear:

```java
// DCQL Query
public record DcqlQuery(
    @JsonProperty("credentials") List<CredentialQuery> credentials
) {}

public record CredentialQuery(
    @JsonProperty("id") String id,
    @JsonProperty("format") String format,
    @JsonProperty("meta") CredentialMeta meta,
    @JsonProperty("claims") List<ClaimQuery> claims
) {}

public record CredentialMeta(
    @JsonProperty("vct_values") List<String> vctValues
) {}

public record ClaimQuery(
    @JsonProperty("path") List<String> path,
    @JsonProperty("values") List<String> values,
    @JsonProperty("essential") Boolean essential
) {}

// Authorization Request (payload del signed Request Object)
public record AuthorizationRequest(
    @JsonProperty("response_type") String responseType,
    @JsonProperty("client_id") String clientId,
    @JsonProperty("response_mode") String responseMode,
    @JsonProperty("response_uri") String responseUri,
    @JsonProperty("nonce") String nonce,
    @JsonProperty("state") String state,
    @JsonProperty("dcql_query") DcqlQuery dcqlQuery,
    @JsonProperty("client_metadata") Map<String, Object> clientMetadata
) {}
```

#### P0.3 — VerifierService skeleton + controller

**Fitxers:**
- `com/fikua/verifier/VerifierService.java` — Wiring
- `com/fikua/verifier/app/VerificationService.java` — Use cases
- `com/fikua/verifier/app/port/SessionStore.java` — Port
- `com/fikua/verifier/infra/InMemorySessionStore.java` — Adapter
- `com/fikua/verifier/infra/http/VerifierController.java` — HTTP

Endpoints inicials (stubs):
- `POST /oid4vp/v1/session` → crea sessió, retorna `request_uri`
- `GET /oid4vp/v1/request/{id}` → retorna signed Request Object
- `POST /oid4vp/v1/response` → rep VP Token

#### P0.4 — Activar role "verifier" a `FikuaLab`

**Fitxer:** `suite/backend/fikua-lab/src/main/java/com/fikua/lab/FikuaLab.java`

Descomentantar/afegir:

```java
if (roles.contains("verifier")) {
    verifierService = new VerifierService(app, config, signingKey);
}
```

#### P0 — Checklist

- [x] P0.1: Crear `fikua-verifier/build.gradle.kts`, afegir a `settings.gradle.kts` i `fikua-lab/build.gradle.kts` (2026-02-25)
- [x] P0.2: Records DCQL (`DcqlQuery`, `CredentialQuery`, `CredentialMeta`, `ClaimQuery`) (2026-02-25)
- [x] P0.2: Record `AuthorizationRequest` (2026-02-25)
- [x] P0.3: `VerifierService`, `VerificationService`, `SessionStore`, `InMemorySessionStore`, `VerifierController` (2026-02-25)
- [x] P0.4: Activar role "verifier" a `FikuaLab` (2026-02-25)
- [x] Compilar: `cd suite/backend && ./gradlew build` (2026-02-25)
- [x] Tests: `DcqlQueryTest`, `AuthorizationRequestTest` (JSON contract) (2026-02-25)

#### P0 — Acceptance criteria

P0 es considera COMPLETAT quan:

1. **Build:** `./gradlew build` compila amb el mòdul `fikua-verifier` inclòs
2. **Tests:** Existeixen tests per `DcqlQuery` i `AuthorizationRequest` que validen el JSON output
3. **Endpoint stub:** `POST /oid4vp/v1/session` retorna un `request_uri` (pot ser amb dades hardcoded)
4. **Role:** El backend amb `FIKUA_ROLES=verifier` arranca sense errors

---

### P1 — Authorization Request + Request Object signat (necessari per Tests #5, #6)

#### P1.1 — Signar Request Object (JAR)

**Fitxer:** `com/fikua/core/oid4vp/RequestObjectSigner.java` (nou)

Construir i signar JWT amb:
- Header: `typ: oauth-authz-req+jwt`, `alg: ES256`, `x5c: [<cert>]`
- Payload: tots els paràmetres de l'Authorization Request
- Signatura: clau privada del verifier

Usar nimbus-jose-jwt `SignedJWT`.

#### P1.2 — VerificationService: crear sessió completa

**Fitxer:** `com/fikua/verifier/app/VerificationService.java`

```java
public VerificationSession createSession(VerificationRequest request) {
    String state = generateSecureRandom(32);
    String nonce = generateSecureRandom(32);
    DcqlQuery query = buildDcqlQuery(request.credentialType(), request.requestedClaims());
    // Per HAIP: generar clau efímera EC P-256 per encriptació
    ECKey encryptionKey = responseMode == DIRECT_POST_JWT ? generateEphemeralKey() : null;
    // Construir i signar Request Object
    String requestJwt = signRequestObject(state, nonce, query, encryptionKey);
    // Guardar sessió
    sessionStore.store(new VerificationSession(state, nonce, query, requestJwt, encryptionKey));
    return session;
}
```

#### P1.3 — VP Token reception (direct_post)

**Fitxer:** `com/fikua/verifier/infra/http/VerifierController.java`

Endpoint `POST /oid4vp/v1/response`:
1. Parsejar form params: `vp_token`, `presentation_submission`, `state`
2. Buscar sessió per `state`
3. Delegar a `VerificationService.verifyPresentation()`

#### P1.4 — SD-JWT VP validation

**Fitxer:** `com/fikua/core/oid4vp/VpTokenValidator.java` (nou)

1. Parsejar SD-JWT presentation: split per `~`
2. Validar signatura Issuer-JWT (reutilitzar `SdJwtVerifier`)
3. Validar disclosures contra `_sd` hashes
4. Validar KB-JWT (signatura, aud, nonce, sd_hash)
5. Extreure claims verificats

#### P1 — Checklist

- [ ] P1.1: `RequestObjectSigner` — signar JAR amb ES256 + x5c
- [ ] P1.2: `VerificationService.createSession()` — sessió completa amb signed Request Object
- [ ] P1.3: `POST /oid4vp/v1/response` — recepció VP Token (direct_post)
- [ ] P1.4: `VpTokenValidator` — validació completa SD-JWT VP + KB-JWT
- [ ] Tests: `RequestObjectSignerTest`, `VpTokenValidatorTest`
- [ ] Compilar: `./gradlew build`

#### P1 — Acceptance criteria

P1 es considera COMPLETAT quan:

1. **Flux E2E amb curl:**
   - `POST /oid4vp/v1/session` → retorna `request_uri`
   - `GET /oid4vp/v1/request/{id}` → retorna JWT signat amb `typ: oauth-authz-req+jwt`
   - `POST /oid4vp/v1/response` amb VP Token vàlid → retorna 200 amb claims
   - `POST /oid4vp/v1/response` amb KB-JWT nonce incorrecte → retorna error
2. **Tests:** `VpTokenValidator` valida correctament signatura issuer + KB-JWT + disclosures
3. **Conformitat:** El signed Request Object conté tots els paràmetres requerits per OID4VP §5

---

### P2 — HAIP: Response encryption + DCQL (necessari per Test #5)

#### P2.1 — JWE support (ECDH-ES + A128GCM/A256GCM)

**Fitxer:** `com/fikua/core/oid4vp/JweUtil.java` (nou)

```java
public class JweUtil {
    public static String encrypt(String payload, ECKey recipientKey, String enc) {
        // ECDH-ES key agreement + AES-GCM content encryption
    }
    public static String decrypt(String jwe, ECKey privateKey) {
        // Decrypt JWE with verifier's private key
    }
}
```

Usar nimbus-jose-jwt `JWEObject` amb `ECDHEncrypter` / `ECDHDecrypter`.

#### P2.2 — Clau efímera per sessió

**Fitxer:** `com/fikua/verifier/app/VerificationService.java`

Generar `ECKey` efímera P-256 per cada sessió. La clau pública va a `client_metadata.jwks`. La clau privada es guarda a la sessió per desencriptar la resposta.

#### P2.3 — Desencriptar resposta al verifier

**Fitxer:** `com/fikua/verifier/infra/http/VerifierController.java`

Si `response_mode = direct_post.jwt`:
1. Rebre param `response` (JWE)
2. Obtenir clau privada efímera de la sessió
3. Desencriptar amb `JweUtil.decrypt()`
4. Parsejar JWT intern per obtenir `vp_token`, `presentation_submission`, `state`

#### P2.4 — DCQL query builder per credentials

**Fitxer:** `com/fikua/core/oid4vp/DcqlQueryBuilder.java` (nou)

```java
public class DcqlQueryBuilder {
    public static DcqlQuery forEudiPid(List<String> claims) {
        return new DcqlQuery(List.of(
            new CredentialQuery(
                "identity_credential",
                "dc+sd-jwt",
                new CredentialMeta(List.of("urn:eu.europa.ec.eudi:pid:1")),
                claims.stream().map(c -> new ClaimQuery(List.of(c), null, null)).toList()
            )
        ));
    }
}
```

#### P2 — Checklist

- [ ] P2.1: `JweUtil` — encrypt/decrypt amb ECDH-ES + A128GCM/A256GCM
- [ ] P2.2: Generar clau efímera EC P-256 per sessió, incloure a `client_metadata.jwks`
- [ ] P2.3: Desencriptar JWE response al verifier controller
- [ ] P2.4: `DcqlQueryBuilder` amb presets per EUDI PID i LEAR
- [ ] Tests: `JweUtilTest` (round-trip encrypt/decrypt), `DcqlQueryBuilderTest`
- [ ] Compilar: `./gradlew build`

#### P2 — Acceptance criteria

P2 es considera COMPLETAT quan:

1. **HAIP flux amb curl:**
   - `POST /oid4vp/v1/session` (perfil HAIP) → retorna `request_uri` amb DCQL i `encrypted_response_enc_values_supported`
   - `POST /oid4vp/v1/response` amb JWE response → verifier desencripta i valida → retorna claims
2. **Tests:** `JweUtil` round-trip funciona amb P-256 + A128GCM i A256GCM
3. **Conformitat HAIP:** El Request Object conté DCQL (no scope), `response_mode: direct_post.jwt`, i `client_metadata` amb `jwks`

---

### P3 — Wallet presentation logic (necessari per Tests #7, #8)

#### P3.1 — Wallet detecta VP request

**Fitxer:** `suite/frontend/holder/src/main.ts`

Detectar query params `vp_request_uri` i `client_id` a la URL del wallet. Iniciar flux de presentació.

#### P3.2 — Wallet fetch Request Object

**Fitxer:** `suite/frontend/holder/src/protocol.ts`

```typescript
async function fetchRequestObject(requestUri: string): Promise<AuthorizationRequest> {
    const response = await fetch(requestUri, {
        headers: { 'Accept': 'application/oauth-authz-req+jwt' }
    });
    const jwt = await response.text();
    // Parse JWT, validate signature against x5c
    return parseAuthorizationRequest(jwt);
}
```

#### P3.3 — Wallet matching i consent UI

**Fitxer:** `suite/frontend/holder/src/main.ts`

1. Buscar credencials a IndexedDB que matchegen DCQL query (per VCT)
2. Seleccionar disclosures
3. Mostrar UI de consentiment: "Verifier X demana: given_name, family_name, birth_date"
4. L'usuari aprova o rebutja

#### P3.4 — Wallet construeix VP Token

**Fitxer:** `suite/frontend/holder/src/protocol.ts`

```typescript
async function buildVpToken(
    credential: StoredCredential,
    selectedClaims: string[],
    nonce: string,
    audience: string
): Promise<string> {
    // 1. Filtrar disclosures
    // 2. Construir KB-JWT amb Web Crypto (ES256)
    // 3. Serialitzar: <issuer-jwt>~<disc1>~<disc2>~<kb-jwt>
}
```

#### P3.5 — Wallet POST a response_uri

**Fitxer:** `suite/frontend/holder/src/protocol.ts`

```typescript
async function submitPresentation(
    responseUri: string,
    vpToken: string,
    state: string,
    responseMode: string,
    encryptionKey?: JsonWebKey
): Promise<void> {
    if (responseMode === 'direct_post.jwt') {
        // Encrypt with JWE
        const jwe = await encryptResponse(vpToken, state, encryptionKey);
        await fetch(responseUri, { method: 'POST', body: `response=${jwe}&state=${state}` });
    } else {
        await fetch(responseUri, { method: 'POST', body: `vp_token=${vpToken}&state=${state}` });
    }
}
```

#### P3 — Checklist

- [ ] P3.1: Wallet: detectar VP request params a la URL
- [ ] P3.2: Wallet: fetch i parsejar Request Object (JWT)
- [ ] P3.3: Wallet: matching DCQL → credencials guardades + consent UI
- [ ] P3.4: Wallet: construir VP Token (SD-JWT + KB-JWT)
- [ ] P3.5: Wallet: POST a response_uri (plain i encriptat)
- [ ] Tests: `protocol.test.ts` — VP Token building, KB-JWT structure

#### P3 — Acceptance criteria

P3 es considera COMPLETAT quan:

1. **Flux E2E:** Verifier crea sessió → Wallet rep request → Wallet mostra consent → Wallet envia VP Token → Verifier valida → Resultat visible
2. **SD-JWT selectiva:** El wallet només envia les disclosures demanades (no totes)
3. **KB-JWT:** Present i vàlid amb `aud`, `nonce`, `sd_hash` correctes
4. **Tests OIDF #7, #8:** Configurar i executar

---

### P4 — Frontend UX complet

#### P4.1 — Frontend verifier connectat al backend

**Fitxers:**
- `suite/frontend/verifier/app.js`
- `suite/frontend/verifier/index.html`

Substituir demo per crides reals:
- "Verify" → `POST /oid4vp/v1/session` → mostra QR/link amb `request_uri`
- Polling `GET /oid4vp/v1/result/{id}` → mostra claims o error

#### P4.2 — Wallet presentation screen

**Fitxer:** `suite/frontend/holder/src/main.ts`

Nova pantalla al wallet:
- Header: "Verification Request"
- Detalls: Qui demana (verifier client_id), què demana (claims)
- Claims amb checkboxes (essentials locked, opcionals toggleable)
- Botons: "Share" / "Decline"

#### P4 — Checklist

- [ ] P4.1: Frontend verifier: reemplaçar demo amb crides API
- [ ] P4.1: Frontend verifier: QR code real, URL copiable, polling resultat
- [ ] P4.2: Wallet: pantalla de presentació amb consent
- [ ] P4.2: Wallet: historial de presentacions a activity log

---

## Client ID i certificats per al verifier

El verifier necessita un certificat X.509 propi per signar Request Objects.

### x509_san_dns

- `client_id`: `x509_san_dns:verifier.lab.fikua.com`
- El certificat del verifier ha de tenir `verifier.lab.fikua.com` al SAN (Subject Alternative Name)
- El certificat va al JOSE header `x5c` del Request Object

### x509_hash

- `client_id`: `x509_hash:<base64url(SHA-256(DER-cert))>`
- El hash es calcula sobre la representació DER del certificat
- No cal SAN, el hash identifica unívocament el certificat

### Generació

```bash
# Verifier certificate (CA-signed, EC P-256)
openssl ecparam -name prime256v1 -genkey -noout -out verifier-key.pem
openssl req -new -key verifier-key.pem -out verifier.csr \
  -subj "/CN=Fikua Lab Verifier/O=Fikua"
openssl x509 -req -in verifier.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out verifier-cert.pem -days 365 \
  -extfile <(echo "subjectAltName=DNS:verifier.lab.fikua.com")
```

**Nota:** Reutilitzar el patró `PemKeyLoader` de `fikua-issuer` per carregar la clau i el certificat del verifier.
