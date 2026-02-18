# Credential Issuance Flow — Especificació tècnica

**Created:** 2026-02-18
**Updated:** 2026-02-19
**Status:** Draft
**Normativa:** OID4VCI 1.0 Final, HAIP 1.0, ARF 2.8, SD-JWT VC draft-14, Token Status List draft-12

---

## Resum

Aquest document defineix el flux complet d'emissió de credencials a Fikua Lab, des de la interacció inicial de l'usuari fins a la notificació final. Cobreix els dos perfils suportats (Plain pre-auth i HAIP auth code) i identifica els gaps entre la implementació actual i les especificacions.

## Normativa de referència

```text
ARF 2.8 (EU regulatory layer: Trusted Lists, WUA/WIA, signed metadata, ETSI certs)
  └── HAIP 1.0 (technical profile: DPoP, PKCE S256, PAR, x509_hash, DCQL, response encryption)
       └── OID4VCI 1.0 Final (issuance) + SD-JWT VC draft-14 (credential format)
            └── Token Status List draft-12 (revocació)
```

| Spec | URL |
|------|-----|
| OID4VCI 1.0 Final | [openid.net/specs/openid-4-verifiable-credential-issuance-1_0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) |
| OID4VCI 1.0 Examples | [github.com/openid/OpenID4VCI/1.0/examples](https://github.com/openid/OpenID4VCI/tree/main/1.0/examples) |
| SD-JWT VC draft-14 | [datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) |
| Token Status List draft-12 | [datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-12](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-12) |
| HAIP 1.0 | [openid.github.io/OpenID4VC-HAIP](https://openid.github.io/OpenID4VC-HAIP/openid4vc-high-assurance-interoperability-profile-wg-draft.html) |
| RFC 9449 (DPoP) | [rfc-editor.org/rfc/rfc9449](https://www.rfc-editor.org/rfc/rfc9449) |
| RFC 7636 (PKCE) | [rfc-editor.org/rfc/rfc7636](https://www.rfc-editor.org/rfc/rfc7636) |
| RFC 8414 (AS Metadata) | [rfc-editor.org/rfc/rfc8414](https://www.rfc-editor.org/rfc/rfc8414) |

---

## Canvi de format identifier: `vc+sd-jwt` → `dc+sd-jwt`

SD-JWT VC draft-13+ ha canviat el `typ` header de `vc+sd-jwt` a `dc+sd-jwt` per evitar conflicte amb el media type `vc` registrat pel W3C. El terme "dc" significa "digital credential".

- **OID4VCI 1.0 Final (exemples oficials):** ja utilitza `dc+sd-jwt` com a format identifier
- **Període de transició:** es RECOMANA acceptar ambdós (`vc+sd-jwt` i `dc+sd-jwt`) durant un temps raonable
- **Fikua Lab:** Utilitzarem `dc+sd-jwt` als metadades i al `typ` header del JWT. Acceptarem ambdós al parser del wallet.

---

## Perfils suportats

| Paràmetre | Plain Pre-Auth | HAIP Auth Code |
|-----------|---------------|----------------|
| Grant Type | `pre_authorization_code` | `authorization_code` |
| Sender Constraining | Cap | `dpop` (RFC 9449) |
| Client Authentication | Cap | `attest_jwt_client_auth` |
| PKCE | Cap | `S256` (obligatori) |
| PAR | Cap | Obligatori |
| Credential Offer | `by_value` o `by_reference` | `by_value` o `by_reference` |
| Issuance Mode | `immediate` | `immediate` |
| Credential Format | `dc+sd-jwt` | `dc+sd-jwt` |
| Test OIDF | Test #2 | Test #1 |

---

## Flux complet (15 passos)

### Pas 1 — Wallet redirigeix a Issuer Portal

L'usuari, des del wallet (wallet.lab), inicia una sol·licitud de credencial. El wallet el redirigeix al portal frontal de l'issuer (issuer.lab).

**Spec:** Fora d'spec. OID4VCI defineix `issuer_initiated` i `wallet_initiated`, però la UX de redirecció és decisió de l'implementació.

**Implementació actual:**

- El frontend d'issuer.lab existeix amb la fase d'identificació.
- El wallet (holder/app.js) té login amb passkey i un escàner QR de demo, però cap lògica real de protocol.

**Gaps:**

- [ ] Implementar al wallet.lab el mecanisme d'iniciar una sol·licitud de credencial que redirigeixi a l'issuer.

---

### Pas 2 — Issuer redirigeix a cert.lab per certificat

El portal d'issuer.lab demana que l'usuari seleccioni el certificat instal·lat al navegador. Ho fa redirigint a cert.lab.

**Spec:** Fora d'spec. La identificació del titular és una decisió de l'issuer. L'spec no defineix com es fa l'autenticació/identificació de l'usuari.

**Implementació actual:** Completat.

- issuer/app.js redirigeix a `cert.lab.fikua.com` amb `return_url`.
- cert.lab fa mTLS (`ssl_verify_client optional_no_ca`), llegeix els headers `X-Client-*`.
- L'usuari veu el certificat i l'accepta.

**Gaps:** Cap.

---

### Pas 3 — cert.lab retorna amb callback

cert.lab valida el certificat i retorna l'usuari a issuer.lab amb les dades del certificat com a callback.

**Spec:** Fora d'spec.

**Implementació actual:** Completat.

- cert.lab fa GET `/cert-info` → llegeix headers → redirigeix a issuer.lab amb `?cert=<base64-json>`.
- issuer/app.js descodifica i mostra les dades.

**Flux:**

```text
1. User clicks "Identify with certificate" at issuer.lab
2. Redirect to cert.lab?return_url=https://issuer.lab
3. Browser shows native certificate selection dialog (mTLS)
4. cert/app.js does GET /cert-info → reads X-Client-* headers
5. User clicks "Accept"
6. Redirect to issuer.lab?cert=<base64-json>
7. issuer/app.js reads query param, decodes certificate data
```

**Gaps:** Cap.

---

### Pas 4 — Issuer crea IssuanceRecord i genera Credential Offer

issuer.lab captura les dades del callback del certificat i les envia al servidor. El servidor:

1. Registra la sol·licitud d'emissió en un `IssuanceRecord`
2. Genera la `CredentialOffer` (by_value o by_reference segons configuració)
3. Retorna l'offer al frontend
4. El frontend presenta l'offer a l'usuari de tres maneres

**Spec OID4VCI §4.1 — Credential Offer:**

```json
{
  "credential_issuer": "https://issuer.lab.fikua.com",
  "credential_configuration_ids": ["eu.europa.ec.eudi.pid_dc+sd-jwt"],
  "grants": {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "<code>",
      "tx_code": { ... }
    }
  }
}
```

O per authorization_code:

```json
{
  "credential_issuer": "https://issuer.lab.fikua.com",
  "credential_configuration_ids": ["eu.europa.ec.eudi.pid_dc+sd-jwt"],
  "grants": {
    "authorization_code": {
      "issuer_state": "<state>"
    }
  }
}
```

**Variants d'entrega:**

- `by_value`: l'objecte JSON sencer es codifica a la URL del wallet via deep link
- `by_reference`: es retorna una `credential_offer_uri` que el wallet fa GET per obtenir l'offer

**Presentació de l'offer al frontend d'issuer.lab:**

Un cop el backend retorna l'offer, el frontend d'issuer.lab la presenta de tres maneres:

1. **QR code (cross-device):** Codifica la URL `openid-credential-offer://` en un QR. Permet que un wallet extern (mòbil) escanegi el QR.
2. **Botó "Open in Wallet" (same-device):** Redirecció directa a `https://wallet.lab.fikua.com/?credential_offer=...` o `?credential_offer_uri=...` per flux same-device amb el wallet de Fikua Lab.
3. **URL copiable (testing):** La URL completa visible en un camp de text amb botó de copiar. Necessari per als tests OIDF, on cal enganxar la URL a la configuració del test suite.

**Flux same-device:**

```text
openid-credential-offer://?credential_offer_uri=https://issuer.lab.fikua.com/oid4vci/v1/credential-offer/{id}
```

Per same-device amb wallet.lab, el botó utilitza una URL HTTPS en comptes del custom scheme:

```text
https://wallet.lab.fikua.com/?credential_offer_uri=https://issuer.lab.fikua.com/oid4vci/v1/credential-offer/{id}
```

**Flux cross-device (QR):**

El QR conté la URL amb custom scheme `openid-credential-offer://`. Si és `by_reference`, el QR és petit perquè només conté la URI. Si és `by_value`, el QR pot ser gran perquè conté tot el JSON codificat.

**Per als tests OIDF:**

L'OIDF conformance suite actua com a wallet (Tests #2, #1) o com a issuer (Tests #4, #3). Quan testa el nostre issuer, necessita la `credential_offer_uri` o la `credential_offer` per iniciar el flux. Per això cal que la URL sigui visible i copiable al frontend d'issuer.lab.

**Implementació actual:**

- `CredentialOffer.java` suporta `preAuthorized()` i `authorizationCode()`. OK.
- `IssuerRoutes.credentialOffer()` suporta `by_reference` via `?mode=by_reference` i `by_value` per defecte. OK.
- No existeix `IssuanceRecord`. L'`InMemoryStore` guarda sessions però no hi ha registre persistent del procés d'emissió.
- No hi ha connexió frontend-backend: l'issuer frontend captura les dades del certificat però no les envia al servidor.
- No hi ha presentació d'offer (QR, botó, URL copiable).

**Gaps:**

- [ ] Crear model `IssuanceRecord` (sol·licitant, certificat, offer, token, credential, status, timestamps). Guardar a base de dades.
- [ ] Connectar frontend issuer amb el backend: enviar dades del certificat → rebre credential offer.
- [ ] Frontend issuer: generar QR code amb la URL `openid-credential-offer://` (cross-device).
- [ ] Frontend issuer: botó "Open in Wallet" amb redirecció a `wallet.lab.fikua.com` (same-device).
- [ ] Frontend issuer: camp de text amb la URL completa i botó de copiar (testing OIDF).

---

### Pas 5 — Wallet obté la Credential Offer

El wallet rep la credential offer de dues maneres possibles:

- **Same-device:** redirecció HTTP des d'issuer.lab amb query params `?credential_offer=...` o `?credential_offer_uri=...`
- **Cross-device:** l'usuari escaneja un QR amb el wallet mòbil que conté la URL `openid-credential-offer://`

**Spec OID4VCI §4.2 — Credential Offer URIs:**

```text
openid-credential-offer://?credential_offer=<url-encoded-json>
openid-credential-offer://?credential_offer_uri=<url>
```

Per same-device amb wallet web (Fikua Lab), s'utilitza HTTPS en comptes del custom scheme:

```text
https://wallet.lab.fikua.com/?credential_offer=<url-encoded-json>
https://wallet.lab.fikua.com/?credential_offer_uri=<url>
```

**Flux del wallet al rebre l'offer:**

```text
1. Wallet detecta query params (credential_offer o credential_offer_uri)
2. Si credential_offer: parseja el JSON directament
3. Si credential_offer_uri: fa GET a la URI per obtenir el JSON
4. Guarda la credential offer en memòria
5. Neteja la URL (replaceState) per no exposar codis
6. Continua al pas 6 (fetch .well-known)
```

**Implementació actual:**

- El backend serveix offers per referència via `GET /oid4vci/v1/credential-offer/{id}`. OK.
- El wallet frontend no implementa cap lògica per processar credential offers.

**Gaps:**

- [ ] Wallet: detectar query params `credential_offer` i `credential_offer_uri` a la URL.
- [ ] Wallet: si és `credential_offer_uri`, fer GET per obtenir l'offer JSON.
- [ ] Wallet: parsejar i guardar la credential offer en memòria.
- [ ] Wallet: netejar la URL (replaceState) després de capturar l'offer.

---

### Pas 6 — Wallet demana els .well-known

El wallet, amb la credential offer, necessita obtenir els metadades de l'issuer:

1. `GET /.well-known/openid-credential-issuer` → `CredentialIssuerMetadata`
2. `GET /.well-known/oauth-authorization-server` → `AuthServerMetadata`

Amb aquests dos documents el wallet sap:

- On fer credential request (`credential_endpoint`)
- On fer token request (`token_endpoint` — de l'AS Metadata)
- Quins formats/algoritmes suporta l'issuer
- Si necessita DPoP, PAR, PKCE
- On demanar nonce (`nonce_endpoint`)
- Quins proof types espera l'issuer (`proof_types_supported`)
- Si suporta notificacions (`notification_endpoint`)

#### Credential Issuer Metadata — Referència OID4VCI 1.0

Font: exemple oficial [credential_issuer_metadata_sd_jwt_long.json](https://github.com/openid/OpenID4VCI/blob/main/1.0/examples/credential_issuer_metadata_sd_jwt_long.json)

**Camps top-level:**

| Camp | Spec | Descripció |
|------|------|------------|
| `credential_issuer` | REQUIRED | URL identificadora de l'issuer |
| `credential_endpoint` | REQUIRED | URL del credential endpoint |
| `credential_configurations_supported` | REQUIRED | Map de configs per credential_configuration_id |
| `authorization_servers` | OPTIONAL | Array d'URLs d'Authorization Servers (si AS != issuer) |
| `nonce_endpoint` | OPTIONAL (HAIP: REQUIRED) | URL per obtenir nonce fresc |
| `notification_endpoint` | OPTIONAL | URL per rebre notificacions del wallet |
| `deferred_credential_endpoint` | OPTIONAL | URL per deferred credential |
| `credential_request_encryption` | OPTIONAL | Claus i algoritmes per encriptar requests |
| `credential_response_encryption` | OPTIONAL | Algoritmes per encriptar responses |
| `batch_credential_issuance` | OPTIONAL | `{ "batch_size": N }` |
| `display` | OPTIONAL | Array d'objectes de visualització de l'issuer |

**Nota important:** `token_endpoint` NO és un camp del Credential Issuer Metadata. El wallet obté el `token_endpoint` de l'Authorization Server Metadata (`/.well-known/oauth-authorization-server`).

**Estructura `credential_response_encryption` (top-level):**

```json
{
  "alg_values_supported": ["ECDH-ES"],
  "enc_values_supported": ["A128GCM"],
  "zip_values_supported": ["DEF"],
  "encryption_required": true
}
```

**Camps dins `credential_configurations_supported` per `dc+sd-jwt`:**

| Camp | Spec | Descripció |
|------|------|------------|
| `format` | REQUIRED | `"dc+sd-jwt"` |
| `vct` | REQUIRED | Identificador del tipus de credencial (e.g., `eu.europa.ec.eudi.pid.1`) |
| `scope` | OPTIONAL | OAuth scope per demanar aquesta credencial |
| `cryptographic_binding_methods_supported` | OPTIONAL | Mètodes de key binding (e.g., `["jwk"]`) |
| `credential_signing_alg_values_supported` | OPTIONAL | Algoritmes de signatura de la credencial (e.g., `["ES256"]`) |
| `proof_types_supported` | OPTIONAL | Proof types i els seus algoritmes (veure estructura sota) |
| `credential_metadata` | OPTIONAL | Conté `display` i `claims` (veure estructura sota) |

**Estructura `proof_types_supported` (CONFIRMAT via exemple oficial):**

```json
{
  "jwt": {
    "proof_signing_alg_values_supported": ["ES256"],
    "key_attestations_required": {
      "key_storage": ["iso_18045_moderate"],
      "user_authentication": ["iso_18045_moderate"]
    }
  }
}
```

El camp intern és `proof_signing_alg_values_supported` (no `alg`). Confirmat per l'exemple oficial del repo OID4VCI.

El camp `key_attestations_required` és per HAIP/ARF — indica els requisits de key attestation.

**Estructura `credential_metadata` (dins credential config):**

```json
{
  "display": [
    {
      "name": "EUDI PID",
      "locale": "en",
      "description": "EU Digital Identity Personal Identification Data",
      "background_color": "#12107c",
      "text_color": "#FFFFFF",
      "logo": {
        "uri": "https://...",
        "alt_text": "..."
      }
    }
  ],
  "claims": [
    { "path": ["given_name"], "display": [{ "name": "Given Name", "locale": "en" }] },
    { "path": ["family_name"], "display": [{ "name": "Surname", "locale": "en" }] },
    { "path": ["birth_date"], "display": [{ "name": "Date of Birth", "locale": "en" }] },
    { "path": ["issuing_authority"] },
    { "path": ["issuing_country"] }
  ]
}
```

**Nota:** `claims` ara és un array d'objectes amb `path` (array de strings, per suportar nested claims) i `display`, no un map planer amb `mandatory`/`value_type` com en drafts anteriors.

#### Exemple complet de Credential Issuer Metadata per Fikua Lab

```json
{
  "credential_issuer": "https://issuer.lab.fikua.com",
  "credential_endpoint": "https://issuer.lab.fikua.com/oid4vci/v1/credential",
  "nonce_endpoint": "https://issuer.lab.fikua.com/oid4vci/v1/nonce",
  "notification_endpoint": "https://issuer.lab.fikua.com/oid4vci/v1/notification",
  "display": [
    {
      "name": "Fikua Lab Issuer",
      "locale": "en"
    }
  ],
  "credential_configurations_supported": {
    "eu.europa.ec.eudi.pid_dc+sd-jwt": {
      "format": "dc+sd-jwt",
      "vct": "eu.europa.ec.eudi.pid.1",
      "scope": "eu.europa.ec.eudi.pid_dc+sd-jwt",
      "cryptographic_binding_methods_supported": ["jwk"],
      "credential_signing_alg_values_supported": ["ES256"],
      "proof_types_supported": {
        "jwt": {
          "proof_signing_alg_values_supported": ["ES256"]
        }
      },
      "credential_metadata": {
        "display": [
          {
            "name": "EUDI PID",
            "locale": "en",
            "description": "EU Digital Identity Personal Identification Data"
          }
        ],
        "claims": [
          { "path": ["given_name"], "display": [{ "name": "Given Name", "locale": "en" }] },
          { "path": ["family_name"], "display": [{ "name": "Surname", "locale": "en" }] },
          { "path": ["birth_date"], "display": [{ "name": "Date of Birth", "locale": "en" }] },
          { "path": ["issuing_authority"], "display": [{ "name": "Issuing Authority", "locale": "en" }] },
          { "path": ["issuing_country"], "display": [{ "name": "Issuing Country", "locale": "en" }] }
        ]
      }
    }
  }
}
```

#### Authorization Server Metadata — Referència RFC 8414

| Camp | Spec | Descripció |
|------|------|------------|
| `issuer` | REQUIRED | Issuer identifier |
| `token_endpoint` | REQUIRED | URL del token endpoint |
| `authorization_endpoint` | OPTIONAL | URL de l'authorization endpoint (auth code flow) |
| `pushed_authorization_request_endpoint` | OPTIONAL | URL del PAR endpoint (HAIP) |
| `jwks_uri` | OPTIONAL | URL del JWK Set |
| `response_types_supported` | REQUIRED | `["code"]` o `["none"]` |
| `grant_types_supported` | REQUIRED | Grant types suportats |
| `code_challenge_methods_supported` | OPTIONAL | `["S256"]` (HAIP) |
| `token_endpoint_auth_methods_supported` | OPTIONAL | Mètodes d'autenticació del client |
| `dpop_signing_alg_values_supported` | OPTIONAL | Algoritmes DPoP (HAIP: `["ES256"]`) |
| `pre-authorized_grant_anonymous_access_supported` | OPTIONAL | `true` per pre-auth sense client auth |

**Nota:** `nonce_endpoint` i `notification_endpoint` NO pertanyen a l'AS Metadata. Pertanyen al Credential Issuer Metadata.

#### Implementació actual vs. spec

**CredentialIssuerMetadata.java — errors i gaps:**

| Problema | Detall |
|----------|--------|
| Falta `nonce_endpoint` | HAIP ho requereix. Cal afegir al top-level. |
| Falta `notification_endpoint` | Necessari pel pas 15. Cal afegir. |
| `format` és `"vc+sd-jwt"` | Cal canviar a `"dc+sd-jwt"` (OID4VCI 1.0 Final) |
| `proof_types_supported` OK | El camp intern `proof_signing_alg_values_supported` és correcte |
| `claims` amb format antic | Cal migrar a array amb `path` + `display` dins `credential_metadata` |
| Falta `credential_metadata` wrapper | `display` i `claims` ara van dins `credential_metadata` |
| `credential_response_encryption` absent | Cal afegir al top-level per perfils amb encriptació |
| `credential_configuration_id` | Cal actualitzar a `eu.europa.ec.eudi.pid_dc+sd-jwt` |

**AuthServerMetadata.java — errors i gaps:**

| Problema | Detall |
|----------|--------|
| Conté `credential_nonce_endpoint` | **Error.** No pertany aquí. Cal treure. |

**Gaps:**

- [ ] `CredentialIssuerMetadata`: afegir `nonce_endpoint` (top-level)
- [ ] `CredentialIssuerMetadata`: afegir `notification_endpoint` (top-level)
- [ ] `CredentialIssuerMetadata`: canviar format de `"vc+sd-jwt"` a `"dc+sd-jwt"`
- [ ] `CredentialIssuerMetadata`: actualitzar credential_configuration_id a `eu.europa.ec.eudi.pid_dc+sd-jwt`
- [ ] `CredentialIssuerMetadata`: migrar `claims` a array amb `path` dins `credential_metadata`
- [ ] `CredentialIssuerMetadata`: afegir `credential_response_encryption` al top-level (per perfils encriptats)
- [ ] `AuthServerMetadata`: treure `credential_nonce_endpoint`
- [ ] Wallet: fer fetch als dos .well-known i parsejar-los

---

### Pas 7 — Wallet analitza el grant type

El wallet rellegeix la Credential Offer i identifica quin grant type aplica:

- `"urn:ietf:params:oauth:grant-type:pre-authorized_code"` dins `grants` → pre-auth flow (pas 9)
- `"authorization_code"` dins `grants` → auth code flow (pas 8)

**Spec OID4VCI §4.1:** L'offer pot contenir un o ambdós grant types. El wallet tria.

**Implementació actual:** Cap lògica al wallet.

**Gaps:**

- [ ] Wallet: implementar branching basat en el grant type de l'offer.

---

### Pas 8 — Authorization Code flow (auth request)

Si el grant type és `authorization_code`, el wallet ha de fer una sol·licitud d'autorització. Això varia segons el perfil:

#### Plain (authorization_code sense HAIP)

Opció simple: el wallet pot fer directament GET a l'authorization endpoint amb els paràmetres.

#### HAIP (obligatori)

HAIP imposa:

1. **PAR obligatori:** POST a `/par` amb tots els paràmetres
2. **PKCE S256 obligatori:** generar `code_verifier` → calcular `code_challenge = SHA256(code_verifier)`
3. **DPoP obligatori:** incloure header DPoP a la petició
4. **Client Authentication:** `attest_jwt_client_auth` (Wallet Instance Attestation — WIA)

**Flux HAIP:**

```text
1. Wallet genera code_verifier + code_challenge (PKCE S256)
2. Wallet genera DPoP proof JWT
3. Wallet genera client attestation JWT (WIA)
4. POST /par
   - client_id, redirect_uri, response_type=code, scope
   - code_challenge, code_challenge_method=S256
   - issuer_state (de la credential offer)
   - Headers: DPoP, client attestation
   → Response: { "request_uri": "urn:ietf:params:oauth:request_uri:...", "expires_in": 60 }
5. Redirect a GET /authorize?request_uri=...&client_id=...
6. Issuer autentica l'usuari (ja fet als passos 2-3 amb certificat)
7. Redirect de tornada amb ?code=<auth_code>&state=<state>
```

**Implementació actual — Issuer backend:**

- `POST /par`: molt bàsic — retorna un `request_uri` random sense guardar paràmetres ni validar.
- `GET /authorize`: genera auth code i redirigeix, però no resol `request_uri` ni el vincula als paràmetres del PAR.
- No hi ha implementació de `client_attestation` / `attest_jwt_client_auth` (WIA/WUA).
- PKCE: `handleAuthCodeToken` comprova `code_verifier` però **no verifica contra el `code_challenge` guardat**.

**Gaps — Backend (Issuer):**

- [ ] PAR: persistir els paràmetres rebuts a l'`InMemoryStore` associats al `request_uri`.
- [ ] Authorize: recuperar els paràmetres del PAR quan arriba el `request_uri`.
- [ ] PKCE: guardar `code_challenge` al crear l'auth code. Verificar amb `PkceUtil.verifyS256()` al token endpoint.
- [ ] Client attestation: implementar validació de `attest_jwt_client_auth` (WIA JWT).

**Gaps — Frontend (Wallet):**

- [ ] Wallet: generar `code_verifier` + `code_challenge` (PKCE S256).
- [ ] Wallet: generar DPoP proof JWT.
- [ ] Wallet: construir i enviar PAR request.
- [ ] Wallet: gestionar la redirecció a authorize i capturar l'auth code de tornada.

---

### Pas 9 — Token Request

El wallet demana un access token:

#### Pre-authorized code

```http
POST /oid4vci/v1/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code
&pre-authorized_code=<code>
```

Si la credential offer inclou `tx_code`, el wallet l'ha d'incloure:

```
&tx_code=<user-provided-code>
```

#### Authorization code

```http
POST /oid4vci/v1/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=<auth_code>
&redirect_uri=<redirect_uri>
&code_verifier=<pkce_verifier>
```

Amb HAIP, a més:

- Header `DPoP: <dpop-proof-jwt>` (RFC 9449)
- Header de client attestation

**Token Response:**

```json
{
  "access_token": "<token>",
  "token_type": "Bearer",
  "expires_in": 86400,
  "c_nonce": "<nonce>",
  "c_nonce_expires_in": 86400
}
```

Si DPoP, `token_type` és `"DPoP"`.

**Implementació actual — Backend:**

- `handlePreAuthToken`: funciona — consumeix pre-auth code, genera access token + c_nonce, retorna `TokenResponse.bearer()`. OK.
- `handleAuthCodeToken`: funciona parcialment — valida DPoP si cal, intenta validar PKCE (sense verificar realment), retorna token.

**Gaps — Backend:**

- [ ] PKCE: verificar `code_verifier` contra `code_challenge` guardat (ja mencionat al pas 8).
- [ ] DPoP binding: vincular el thumbprint de la clau DPoP a l'access token. Al credential endpoint, verificar que el DPoP proof usa la mateixa clau.
- [ ] `tx_code` support al pre-auth flow.

**Gaps — Wallet:**

- [ ] Wallet: construir i enviar token request (pre-auth o auth code).
- [ ] Wallet: generar DPoP proof per al token request (HAIP).
- [ ] Wallet: guardar la token response (access_token, c_nonce).

---

### Pas 10 — Wallet processa la Token Response

El wallet guarda:

- `access_token` (per autenticar-se al credential endpoint)
- `token_type` (`"Bearer"` o `"DPoP"`)
- `c_nonce` (per al proof of possession)
- `c_nonce_expires_in`

**Gaps:**

- [ ] Wallet: parsejar i guardar la token response.

---

### Pas 11 — Wallet demana nonce si cal

El wallet analitza si necessita un nonce fresc:

- Si la token response ja conté `c_nonce`, normalment és suficient.
- Si el c_nonce ha expirat o no n'hi ha, el wallet fa `POST /nonce` per obtenir-ne un de nou.

**Spec OID4VCI §7:** El nonce endpoint (`nonce_endpoint` al CredentialIssuerMetadata) no és un recurs protegit — no cal access token.

```http
POST /oid4vci/v1/nonce
```

```json
{
  "c_nonce": "<fresh-nonce>",
  "c_nonce_expires_in": 86400
}
```

**Implementació actual — Backend:** L'endpoint `POST /nonce` existeix i funciona. OK.

**Gaps:**

- [ ] Wallet: si el c_nonce ha expirat, demanar-ne un de nou via `POST /nonce`.

---

### Pas 12 — Wallet genera key pair i proof

El wallet analitza els metadades per determinar si la credencial requereix cryptographic holder binding:

1. Consulta `cryptographic_binding_methods_supported` al credential config → si conté `"jwk"`, cal binding.
2. Consulta `credential_signing_alg_values_supported` per saber com l'issuer signa la credencial.
3. Consulta `proof_types_supported` per saber com construir el proof.

Si cal holder binding (PID, empleat, colegiado — sí; altres — potser no):

1. **Generar par de claus EC P-256** amb Web Crypto API al navegador.
2. **Construir proof JWT:**

```text
Header:
{
  "typ": "openid4vci-proof+jwt",
  "alg": "ES256",
  "jwk": { <wallet-public-key> }
}

Payload:
{
  "iss": "<client_id>",
  "aud": "<credential_issuer>",
  "iat": <timestamp>,
  "nonce": "<c_nonce>"
}
```

3. **Signar** el JWT amb la clau privada del wallet.

**Credential Request:**

```http
POST /oid4vci/v1/credential
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "credential_configuration_id": "eu.europa.ec.eudi.pid_dc+sd-jwt",
  "proof": {
    "proof_type": "jwt",
    "jwt": "<signed-proof-jwt>"
  }
}
```

Si DPoP, el header és `Authorization: DPoP <access_token>` i s'afegeix el header `DPoP: <dpop-proof-jwt>`.

**Implementació actual — Backend:**

- `ProofValidator.java` valida correctament: typ, alg ES256, jwk al header, signatura, aud, nonce, iat. OK.
- `IssuerRoutes.credential()` valida access token, DPoP si cal, proof, construeix SD-JWT VC. OK.

**Gaps — Wallet:**

- [ ] Wallet: generar par de claus EC P-256 amb Web Crypto API.
- [ ] Wallet: construir el proof JWT amb la clau pública al header `jwk`.
- [ ] Wallet: signar el proof JWT amb la clau privada.
- [ ] Wallet: enviar el credential request amb el proof.
- [ ] Wallet: si DPoP, generar un nou DPoP proof per al credential endpoint.

---

### Pas 13 — Issuer processa i retorna la credencial

L'issuer rep el credential request i:

1. Valida l'access token.
2. Valida DPoP (si HAIP): verifica que el thumbprint de la clau DPoP coincideix amb el vinculat al token.
3. Valida el proof of possession (ProofValidator).
4. Extreu la clau pública del wallet del proof.
5. Construeix la SD-JWT VC:
   - Assigna un índex al Token Status List.
   - Posa el claim `status` amb `idx` i `uri`.
   - Posa el claim `cnf` amb la clau pública del wallet (holder binding).
   - Posa els claims selectively disclosable: `given_name`, `family_name`, `birth_date`.
   - Posa els claims plain: `issuing_authority`, `issuing_country`.
   - Posa `vct`, `iss`, `sub`, `iat`, `exp`.
   - Signa amb la clau de l'issuer (ES256).
   - Inclou la cadena de certificats `x5c` al header JWT.
6. Actualitza l'`IssuanceRecord` amb la credencial emesa.
7. Retorna la `CredentialResponse`.

**SD-JWT VC estructura completa (SD-JWT VC draft-14):**

```text
Header:
{
  "typ": "dc+sd-jwt",
  "alg": "ES256",
  "kid": "<issuer-key-id>",
  "x5c": ["<issuer-cert-base64>"]
}

Payload:
{
  "iss": "https://issuer.lab.fikua.com",
  "sub": "urn:fikua:pid:<id>",
  "iat": <timestamp>,
  "exp": <timestamp>,
  "vct": "eu.europa.ec.eudi.pid.1",
  "_sd_alg": "sha-256",
  "_sd": ["<digest1>", "<digest2>", ...],
  "issuing_authority": "Fikua Lab",
  "issuing_country": "EU",
  "cnf": {
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "..."
    }
  },
  "status": {
    "status_list": {
      "idx": 42,
      "uri": "https://issuer.lab.fikua.com/oid4vci/v1/statuslist/1"
    }
  }
}

Disclosures:
  base64url(["<salt>", "given_name", "<value>"])
  base64url(["<salt>", "family_name", "<value>"])
  base64url(["<salt>", "birth_date", "<value>"])

Serialized: <jwt>~<disclosure1>~<disclosure2>~<disclosure3>~
```

**Nota `typ` header:** `dc+sd-jwt` (draft-13+). Acceptar `vc+sd-jwt` durant període de transició.

**Credential Response:**

```json
{
  "credential": "<sd-jwt-vc-serialized>",
  "c_nonce": "<fresh-nonce>",
  "c_nonce_expires_in": 86400
}
```

**Implementació actual — Backend:**

- `SdJwtBuilder` construeix la SD-JWT VC amb disclosures, holder key binding. OK.
- `SdJwtBuilder` té suport per `x5c` però `IssuerRoutes` no el passa.
- Les dades de la credencial són hardcoded ("Jan", "Kowalski", "1990-01-15").
- No hi ha claim `status` (Token Status List).
- No hi ha `IssuanceRecord` update.

**Gaps — Backend:**

- [ ] Passar `x5c` (cadena de certificats de l'issuer) al `SdJwtBuilder`.
- [ ] Afegir claim `status` amb `status_list` (idx + uri) a la credencial.
- [ ] Implementar Token Status List (veure secció dedicada).
- [ ] Substituir dades hardcoded per les dades reals del certificat de l'usuari.
- [ ] Actualitzar `IssuanceRecord` amb la credencial emesa.
- [ ] Afegir `exp` (expiration) a la credencial.

---

### Pas 14 — Wallet presenta la credencial a l'usuari

El wallet rep la `CredentialResponse` i:

1. Parseja la SD-JWT VC serialitzada.
2. Extreu les disclosures i les descodifica.
3. Mostra les dades de la credencial a l'usuari.
4. Demana consentiment: acceptar o rebutjar.

Si l'usuari accepta, el wallet guarda la credencial a localStorage (o equivalent).

**Implementació actual:** El wallet frontend no té cap lògica per parsejar SD-JWT VC ni mostrar credencials reals.

**Gaps:**

- [ ] Wallet: parsejar SD-JWT VC (separar JWT base de les disclosures pel separador `~`).
- [ ] Wallet: descodificar cada disclosure (base64url → JSON array).
- [ ] Wallet: mostrar les dades en una UI de consentiment.
- [ ] Wallet: guardar la credencial si l'usuari accepta.

---

### Pas 15 — Notification

El wallet envia una notificació a l'issuer sobre el resultat:

**Spec OID4VCI §11 — Notification Endpoint:**

```http
POST /oid4vci/v1/notification
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "notification_id": "<id-from-credential-response>",
  "event": "credential_accepted",
  "event_description": "Credential stored successfully"
}
```

**Paràmetres del request:**

| Camp | Spec | Descripció |
|------|------|------------|
| `notification_id` | REQUIRED | Identificador de la credencial (ve de la CredentialResponse) |
| `event` | REQUIRED | Tipus d'event (veure taula) |
| `event_description` | OPTIONAL | Descripció llegible per humans |

**Events possibles:**

- `credential_accepted` — l'usuari ha acceptat la credencial
- `credential_deleted` — l'usuari ha eliminat la credencial
- `credential_failure` — error en processar la credencial

L'issuer actualitza l'`IssuanceRecord` amb l'estat final.

**Nota:** Per poder usar notificacions, la `CredentialResponse` ha d'incloure un camp `notification_id`.

**Credential Response actualitzada:**

```json
{
  "credential": "<sd-jwt-vc-serialized>",
  "notification_id": "<unique-id>",
  "c_nonce": "<fresh-nonce>",
  "c_nonce_expires_in": 86400
}
```

**Implementació actual:** No existeix cap endpoint de notificació ni lògica associada.

**Gaps — Backend:**

- [ ] Crear endpoint `POST /oid4vci/v1/notification`.
- [ ] Declarar `notification_endpoint` al `CredentialIssuerMetadata`.
- [ ] Afegir `notification_id` a la `CredentialResponse`.
- [ ] Actualitzar `IssuanceRecord` amb l'estat final.

**Gaps — Wallet:**

- [ ] Wallet: enviar notificació a l'issuer després del consentiment de l'usuari.

---

## Token Status List — Implementació

### Arquitectura

El Token Status List (TSL) és un mecanisme de revocació per SD-JWT VCs definit a [draft-ietf-oauth-status-list-12](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-12).

```text
SD-JWT VC (credencial)
  └── status.status_list.idx = 42
  └── status.status_list.uri = https://issuer.lab.fikua.com/oid4vci/v1/statuslist/1

Status List Token (JWT, typ: statuslist+jwt)
  └── status_list.bits = 1 (o 2 per suportar SUSPENDED)
  └── status_list.lst = <base64url(DEFLATE(byte-array))>
```

### Valors d'estat

| Valor | Significat | Bits necessaris |
|-------|-----------|-----------------|
| `0x00` | VALID | 1 bit |
| `0x01` | INVALID (revocat) | 1 bit |
| `0x02` | SUSPENDED | 2 bits |

Per suportar SUSPENDED, cal `bits=2` (4 valors possibles per token).

### Status List Token (JWT)

```text
Header:
{
  "typ": "statuslist+jwt",
  "alg": "ES256",
  "kid": "<issuer-key-id>"
}

Payload:
{
  "sub": "https://issuer.lab.fikua.com/oid4vci/v1/statuslist/1",
  "iat": <timestamp>,
  "exp": <timestamp>,
  "ttl": 3600,
  "status_list": {
    "bits": 2,
    "lst": "<base64url-encoded-compressed-bytes>"
  }
}
```

### Endpoint

```http
GET /oid4vci/v1/statuslist/{id}
Accept: application/statuslist+jwt

HTTP/1.1 200 OK
Content-Type: application/statuslist+jwt

<status-list-token-jwt>
```

### Components a implementar

| Component | Fitxer | Descripció |
|-----------|--------|------------|
| `StatusList` | `fikua-core/sdjwt/StatusList.java` | Bit array comprimit (DEFLATE+ZLIB), assignació d'índexs |
| `StatusListToken` | `fikua-core/sdjwt/StatusListToken.java` | Generació del JWT `statuslist+jwt` |
| `StatusListRepository` | `fikua-server/db/StatusListRepository.java` | Persistència del bit array a PostgreSQL |
| Endpoint | `IssuerRoutes` | `GET /oid4vci/v1/statuslist/{id}` |
| `SdJwtBuilder` | Modificar | Afegir claim `status` amb `idx` i `uri` |

### Flux de revocació

```text
1. Admin fa POST /admin/revoke/{issuance-id}
2. Server busca l'IssuanceRecord → obté l'idx
3. Server modifica el bit a la posició idx del StatusList (0x00 → 0x01)
4. Server regenera el StatusListToken (nou JWT signat)
5. Verifiers que fan GET /statuslist/{id} obtindran el nou token
```

---

## IssuanceRecord — Model

Model persistent (PostgreSQL) que registra cada procés d'emissió.

```sql
CREATE TABLE issuance_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id UUID REFERENCES profiles(id),
    session_id VARCHAR(255),

    -- Identificació del sol·licitant (dades del certificat)
    subject_dn TEXT,
    issuer_dn TEXT,
    serial_number VARCHAR(255),
    certificate_fingerprint VARCHAR(255),

    -- Credential Offer
    credential_offer JSONB,
    offer_variant VARCHAR(20),
    grant_type VARCHAR(50),

    -- Token
    access_token_hash VARCHAR(255),
    dpop_thumbprint VARCHAR(255),

    -- Credential
    credential_config_id VARCHAR(255),
    status_list_idx INTEGER,
    credential_issued_at TIMESTAMP,

    -- Notification
    notification_id VARCHAR(255),
    notification_event VARCHAR(50),
    notification_received_at TIMESTAMP,

    -- Lifecycle
    status VARCHAR(50) DEFAULT 'OFFER_CREATED',
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
);
```

**Estats del lifecycle:**

```text
OFFER_CREATED → TOKEN_ISSUED → CREDENTIAL_ISSUED → ACCEPTED / REJECTED / FAILED
                                                   → REVOKED (via admin)
```

---

### Arbre de fitxers rellevants

```text
suite/backend/
├── fikua-core/src/main/java/com/fikua/core/
│   ├── oid4vci/
│   │   ├── CredentialIssuerMetadata.java    ← P0: metadata issuer
│   │   ├── AuthServerMetadata.java          ← P0: metadata AS
│   │   ├── CredentialOffer.java             ← OK
│   │   ├── CredentialRequest.java           ← P1: afegir credential_configuration_id
│   │   ├── CredentialResponse.java          ← P5: afegir notification_id
│   │   └── ProofValidator.java              ← OK
│   ├── oauth2/
│   │   ├── TokenResponse.java               ← OK
│   │   ├── TokenRequest.java                ← P1: tx_code
│   │   └── DPoPValidator.java               ← P2: binding
│   ├── sdjwt/
│   │   ├── SdJwtBuilder.java                ← P0: typ dc+sd-jwt; P1: exp
│   │   ├── SdJwt.java
│   │   └── Disclosure.java
│   ├── crypto/
│   │   └── EcKeyManager.java
│   └── profile/
│       └── ProfileConfig.java               ← OK
├── fikua-server/src/main/java/com/fikua/server/
│   ├── issuer/
│   │   └── IssuerRoutes.java                ← P0: constant; P1-P2: endpoints
│   ├── state/
│   │   └── InMemoryStore.java               ← P2: PAR storage
│   └── db/
│       └── ProfileRepository.java
suite/frontend/
├── issuer/
│   ├── index.html                           ← P4: presentació offer
│   └── app.js                               ← P4: connexió backend
├── holder/
│   ├── index.html                           ← P3-P4: wallet UI
│   └── app.js                               ← P3: protocol logic
```

---

## Gaps consolidats per prioritat

### P0 — Metadata correcte (necessari per tots els tests OIDF)

#### P0.1 — CredentialIssuerMetadata: format `dc+sd-jwt` i nous camps top-level

**Fitxer:** `suite/backend/fikua-core/src/main/java/com/fikua/core/oid4vci/CredentialIssuerMetadata.java`
**Spec:** OID4VCI 1.0 §10, HAIP 1.0

**Actual** — El record només té 4 camps (credential_issuer, credential_endpoint, credential_configurations_supported, display):

```java
public record CredentialIssuerMetadata(
        @JsonProperty("credential_issuer") String credentialIssuer,
        @JsonProperty("credential_endpoint") String credentialEndpoint,
        @JsonProperty("credential_configurations_supported") Map<String, Object> credentialConfigurationsSupported,
        @JsonProperty("display") List<Map<String, Object>> display
) { ... }
```

**Esperat** — Afegir `nonce_endpoint` i `notification_endpoint` al record:

```java
public record CredentialIssuerMetadata(
        @JsonProperty("credential_issuer") String credentialIssuer,
        @JsonProperty("credential_endpoint") String credentialEndpoint,
        @JsonProperty("nonce_endpoint") String nonceEndpoint,
        @JsonProperty("notification_endpoint") String notificationEndpoint,
        @JsonProperty("credential_configurations_supported") Map<String, Object> credentialConfigurationsSupported,
        @JsonProperty("display") List<Map<String, Object>> display
) { ... }
```

I dins del `build()`, retornar-los:

```java
return new CredentialIssuerMetadata(
        baseUrl,
        baseUrl + apiPrefix + "/credential",
        baseUrl + apiPrefix + "/nonce",            // NOU
        baseUrl + apiPrefix + "/notification",     // NOU
        Map.of(configId, credConfig),
        display
);
```

#### P0.2 — CredentialIssuerMetadata: credential_configuration_id i format

**Fitxer:** `suite/backend/fikua-core/src/main/java/com/fikua/core/oid4vci/CredentialIssuerMetadata.java`
**Spec:** OID4VCI 1.0 §10, SD-JWT VC draft-13+

**Actual** (dins `build()`):

```java
String configId = "eu.europa.ec.eudi.pid_vc+sd-jwt";
// ...
credConfig.put("format", "vc+sd-jwt");
credConfig.put("scope", "eu.europa.ec.eudi.pid_vc+sd-jwt");
```

**Esperat:**

```java
String configId = "eu.europa.ec.eudi.pid_dc+sd-jwt";
// ...
credConfig.put("format", "dc+sd-jwt");
credConfig.put("scope", "eu.europa.ec.eudi.pid_dc+sd-jwt");
```

#### P0.3 — CredentialIssuerMetadata: migrar claims a `credential_metadata`

**Fitxer:** `suite/backend/fikua-core/src/main/java/com/fikua/core/oid4vci/CredentialIssuerMetadata.java`
**Spec:** OID4VCI 1.0 §10, exemple oficial `credential_issuer_metadata_sd_jwt_long.json`

**Actual** — claims és un flat map i display està al nivell de la credential config:

```java
// Claims for EUDI PID
var claims = new LinkedHashMap<String, Object>();
claims.put("given_name", Map.of());
claims.put("family_name", Map.of());
claims.put("birth_date", Map.of());
claims.put("issuing_authority", Map.of());
claims.put("issuing_country", Map.of());
credConfig.put("claims", claims);

// Display
credConfig.put("display", List.of(Map.of(
        "name", "EUDI PID",
        "locale", "en",
        "description", "EU Digital Identity Personal Identification Data"
)));
```

**Esperat** — claims és un array amb `path` i tot va dins `credential_metadata`:

```java
// Claims array amb path (OID4VCI 1.0 Final)
var claims = List.of(
        Map.of("path", List.of("given_name"), "display", List.of(Map.of("name", "Given Name", "locale", "en"))),
        Map.of("path", List.of("family_name"), "display", List.of(Map.of("name", "Surname", "locale", "en"))),
        Map.of("path", List.of("birth_date"), "display", List.of(Map.of("name", "Date of Birth", "locale", "en"))),
        Map.of("path", List.of("issuing_authority"), "display", List.of(Map.of("name", "Issuing Authority", "locale", "en"))),
        Map.of("path", List.of("issuing_country"), "display", List.of(Map.of("name", "Issuing Country", "locale", "en")))
);

// Credential metadata wrapper (OID4VCI 1.0 Final)
var credentialMetadata = new LinkedHashMap<String, Object>();
credentialMetadata.put("display", List.of(Map.of(
        "name", "EUDI PID",
        "locale", "en",
        "description", "EU Digital Identity Personal Identification Data"
)));
credentialMetadata.put("claims", claims);

credConfig.put("credential_metadata", credentialMetadata);
```

**Important:** Treure els `credConfig.put("claims", ...)` i `credConfig.put("display", ...)` antics.

#### P0.4 — AuthServerMetadata: treure `credential_nonce_endpoint`

**Fitxer:** `suite/backend/fikua-core/src/main/java/com/fikua/core/oid4vci/AuthServerMetadata.java`
**Spec:** RFC 8414, OID4VCI 1.0 §10 — `nonce_endpoint` pertany al Credential Issuer Metadata, no a l'AS Metadata.

**Actual** — El record té un camp `credentialNonceEndpoint` i les factories el passen:

```java
public record AuthServerMetadata(
        // ...
        @JsonProperty("credential_nonce_endpoint") String credentialNonceEndpoint
) {
    public static AuthServerMetadata forPreAuthProfile(String baseUrl) {
        return new AuthServerMetadata(
                // ... 11 params ...,
                baseUrl + API_PREFIX + "/nonce"  // últim param
        );
    }
}
```

**Esperat** — Treure el camp `credentialNonceEndpoint` del record i eliminar l'últim argument de les factories:

```java
public record AuthServerMetadata(
        @JsonProperty("issuer") String issuer,
        @JsonProperty("token_endpoint") String tokenEndpoint,
        @JsonProperty("authorization_endpoint") String authorizationEndpoint,
        @JsonProperty("pushed_authorization_request_endpoint") String parEndpoint,
        @JsonProperty("jwks_uri") String jwksUri,
        @JsonProperty("response_types_supported") List<String> responseTypesSupported,
        @JsonProperty("grant_types_supported") List<String> grantTypesSupported,
        @JsonProperty("code_challenge_methods_supported") List<String> codeChallengeMethodsSupported,
        @JsonProperty("token_endpoint_auth_methods_supported") List<String> tokenEndpointAuthMethodsSupported,
        @JsonProperty("dpop_signing_alg_values_supported") List<String> dpopSigningAlgValues,
        @JsonProperty("pre-authorized_grant_anonymous_access_supported") Boolean preAuthAnonymousAccess
) { ... }
```

Les factories `forPreAuthProfile()` i `forHaipProfile()` han de passar 11 arguments (sense el nonce).

#### P0.5 — SdJwtBuilder: `typ` header `dc+sd-jwt`

**Fitxer:** `suite/backend/fikua-core/src/main/java/com/fikua/core/sdjwt/SdJwtBuilder.java`
**Spec:** SD-JWT VC draft-13+

**Actual** (dins `build()`):

```java
var headerBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256)
        .type(new JOSEObjectType("vc+sd-jwt"))
        .keyID(issuerKey.kid());
```

**Esperat:**

```java
var headerBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256)
        .type(new JOSEObjectType("dc+sd-jwt"))
        .keyID(issuerKey.kid());
```

#### P0.6 — IssuerRoutes: x5c i constant

**Fitxer:** `suite/backend/fikua-server/src/main/java/com/fikua/server/issuer/IssuerRoutes.java`
**Spec:** OID4VCI 1.0, SD-JWT VC draft-14 §3.5

**Actual:**

```java
private static final String CREDENTIAL_CONFIG_ID = "eu.europa.ec.eudi.pid_vc+sd-jwt";
```

i dins `credential()`:

```java
String sdJwt = new SdJwtBuilder(issuerKey)
        .vct("eu.europa.ec.eudi.pid.1")
        // ... NO passa x5c
        .build()
        .serialize();
```

**Esperat:**

```java
private static final String CREDENTIAL_CONFIG_ID = "eu.europa.ec.eudi.pid_dc+sd-jwt";
```

i dins `credential()`:

```java
String sdJwt = new SdJwtBuilder(issuerKey)
        .vct("eu.europa.ec.eudi.pid.1")
        .x5cChain(issuerKey.x5cChain())    // NOU: passar cadena de certificats
        // ...
        .build()
        .serialize();
```

**Nota:** Cal que `EcKeyManager` exposi un mètode `x5cChain()` que retorni `List<Base64>`. Si no existeix, cal crear-lo o passar `null` en labs sense certificat real.

#### P0 — Checklist

- [ ] P0.1: Afegir `nonce_endpoint` i `notification_endpoint` al record `CredentialIssuerMetadata`
- [ ] P0.2: Canviar `vc+sd-jwt` → `dc+sd-jwt` a `CredentialIssuerMetadata.build()`
- [ ] P0.3: Migrar claims a array amb `path` dins `credential_metadata`
- [ ] P0.4: Treure `credential_nonce_endpoint` de `AuthServerMetadata`
- [ ] P0.5: Canviar `typ` header a `dc+sd-jwt` a `SdJwtBuilder`
- [ ] P0.6: Actualitzar constant `CREDENTIAL_CONFIG_ID` i passar `x5c` a `IssuerRoutes`
- [ ] Compilar: `cd suite/backend && ./gradlew build`
- [ ] Tests unitaris passen: `./gradlew test`
- [ ] Validar metadata amb curl

#### P0 — Acceptance criteria

P0 es considera COMPLETAT quan es compleixen TOTS els criteris següents:

1. **Build:** `./gradlew build` passa sense errors ni warnings rellevants
2. **Tests:** Existeix `CredentialIssuerMetadataTest` i `AuthServerMetadataTest` amb assertions sobre el JSON output. Tots passen.
3. **Issuer Metadata:** `GET /.well-known/openid-credential-issuer` retorna JSON que coincideix camp per camp amb l'exemple de la secció "Exemple complet de Credential Issuer Metadata per Fikua Lab" d'aquest document. Verificació:
   - `nonce_endpoint` i `notification_endpoint` presents
   - `format` = `dc+sd-jwt` (no `vc+sd-jwt`)
   - `credential_configurations_supported` key = `eu.europa.ec.eudi.pid_dc+sd-jwt`
   - `claims` dins `credential_metadata` amb format array `[{path: [...]}]`
4. **AS Metadata:** `GET /.well-known/oauth-authorization-server` NO conté `credential_nonce_endpoint`
5. **SD-JWT:** `SdJwtBuilder.build()` genera un JWT amb header `typ: dc+sd-jwt`
6. **Commits:** Un commit per sub-gap (6 commits), format `feat(oid4vci): P0.X — ...`, cada un compila independentment

---

### P1 — Necessari per Test #2 OIDF (Pre-auth Issuer)

#### P1.1 — Afegir `exp` a la credencial SD-JWT VC

**Fitxer:** `suite/backend/fikua-core/src/main/java/com/fikua/core/sdjwt/SdJwtBuilder.java`
**Spec:** SD-JWT VC draft-14 §3.4

**Actual** — El builder ja afegeix `expirationTime` dins `build()`:

```java
var claimsBuilder = new JWTClaimsSet.Builder()
        .issuer(issuer)
        .issueTime(Date.from(now))
        .expirationTime(Date.from(now.plusSeconds(validitySeconds)));
```

**Estat:** Revisar que `validitySeconds` és coherent (default 1 any). Si l'OIDF test espera un `exp` explícit i el builder ja el genera, hauria de funcionar. Si el test falla perquè espera un format concret, ajustar.

#### P1.2 — `credential_configuration_id` al CredentialRequest

**Fitxer:** `suite/backend/fikua-core/src/main/java/com/fikua/core/oid4vci/CredentialRequest.java`
**Spec:** OID4VCI 1.0 §7.2

**Actual:**

```java
public record CredentialRequest(
        @JsonProperty("format") String format,
        @JsonProperty("credential_identifier") String credentialIdentifier,
        @JsonProperty("proof") Proof proof,
        @JsonProperty("credential_response_encryption") Map<String, Object> credentialResponseEncryption
) { ... }
```

**Esperat** — OID4VCI 1.0 Final usa `credential_configuration_id` (no `format`):

```java
public record CredentialRequest(
        @JsonProperty("credential_configuration_id") String credentialConfigurationId,
        @JsonProperty("format") String format,
        @JsonProperty("credential_identifier") String credentialIdentifier,
        @JsonProperty("proof") Proof proof,
        @JsonProperty("credential_response_encryption") Map<String, Object> credentialResponseEncryption
) { ... }
```

**Nota:** El camp `format` es manté per backward compat, però OID4VCI 1.0 Final usa `credential_configuration_id` com a camp principal per identificar quina credencial es demana. Cal que `IssuerRoutes.credential()` validi `credentialConfigurationId` contra el `CREDENTIAL_CONFIG_ID`.

#### P1.3 — `tx_code` al pre-auth flow

**Fitxer:** `suite/backend/fikua-server/src/main/java/com/fikua/server/issuer/IssuerRoutes.java`
**Spec:** OID4VCI 1.0 §6.1

**Actual** — `handlePreAuthToken` no comprova `tx_code`:

```java
private void handlePreAuthToken(Context ctx, TokenRequest request, ProfileConfig config) {
    if (request.preAuthorizedCode() == null) {
        ctx.status(400).json(OAuthError.invalidGrant("Missing pre-authorized_code"));
        return;
    }
    SessionData session = store.consumePreAuthCode(request.preAuthorizedCode());
    // ... genera token directament
}
```

**Esperat** — Si l'offer conté `tx_code`, cal validar-lo:

```java
private void handlePreAuthToken(Context ctx, TokenRequest request, ProfileConfig config) {
    if (request.preAuthorizedCode() == null) {
        ctx.status(400).json(OAuthError.invalidGrant("Missing pre-authorized_code"));
        return;
    }

    SessionData session = store.consumePreAuthCode(request.preAuthorizedCode());
    if (session == null) {
        ctx.status(400).json(OAuthError.invalidGrant("Invalid or expired pre-authorized_code"));
        return;
    }

    // Validar tx_code si la sessió el requereix
    String expectedTxCode = session.metadata().get("tx_code");
    if (expectedTxCode != null) {
        if (request.txCode() == null || !expectedTxCode.equals(request.txCode())) {
            ctx.status(400).json(OAuthError.invalidGrant("Invalid tx_code"));
            return;
        }
    }

    // ... genera token
}
```

**Nota:** Cal que `TokenRequest` parsegi el camp `tx_code` dels form params. Cal que `CredentialOffer.preAuthorized()` inclogui l'objecte `tx_code` a l'offer si es vol usar. Cal que `SessionData` guardi el `tx_code` esperat al metadata.

#### P1 — Checklist

- [ ] P1.1: Verificar que `exp` es genera correctament a `SdJwtBuilder`
- [ ] P1.2: Afegir `credential_configuration_id` a `CredentialRequest`; validar a `IssuerRoutes.credential()`
- [ ] P1.3: Afegir validació de `tx_code` a `handlePreAuthToken`; afegir `tx_code` a `TokenRequest`
- [ ] Compilar i tests: `./gradlew build`
- [ ] Executar Test #2 OIDF

#### P1 — Acceptance criteria

P1 es considera COMPLETAT quan:

1. **Build + tests:** `./gradlew build` passa. Existeixen tests per `CredentialRequest` (valida `credential_configuration_id`) i per `handlePreAuthToken` (valida `tx_code`).
2. **Pre-auth flow complet amb curl:**
   - `POST /oid4vci/v1/token` amb `pre-authorized_code` + `tx_code` → retorna `access_token` + `c_nonce`
   - `POST /oid4vci/v1/token` amb `tx_code` incorrecte → retorna `400 invalid_grant`
   - `POST /oid4vci/v1/credential` amb `credential_configuration_id` correcte → retorna SD-JWT VC amb `exp`
   - `POST /oid4vci/v1/credential` amb `credential_configuration_id` incorrecte → retorna `400`
3. **Test OIDF #2:** Configurar i executar. Pot fallar per motius aliens a P1 (connectivitat, configuració OIDF), però els endpoints han de respondre correctament.
4. **Commits:** Un commit per sub-gap, format correcte

---

### P2 — Necessari per Test #1 OIDF (HAIP Issuer)

#### P2.1 — PAR: persistir paràmetres

**Fitxer:** `suite/backend/fikua-server/src/main/java/com/fikua/server/issuer/IssuerRoutes.java`
**Fitxer auxiliar:** `suite/backend/fikua-server/src/main/java/com/fikua/server/state/InMemoryStore.java`
**Spec:** RFC 9126, HAIP 1.0

**Actual** — `par()` genera un `request_uri` random sense guardar res:

```java
private void par(Context ctx) {
    // ...
    Map<String, String> params = parseFormParams(ctx);
    String requestUri = "urn:ietf:params:oauth:request_uri:" + InMemoryStore.randomToken(16);
    ctx.status(201).json(Map.of("request_uri", requestUri, "expires_in", 60));
}
```

**Esperat** — Guardar els paràmetres a l'`InMemoryStore`:

```java
private void par(Context ctx) {
    // ...
    Map<String, String> params = parseFormParams(ctx);
    String requestUri = "urn:ietf:params:oauth:request_uri:" + InMemoryStore.randomToken(16);
    store.storeParRequest(requestUri, params);  // NOU
    ctx.status(201).json(Map.of("request_uri", requestUri, "expires_in", 60));
}
```

**Nota:** Cal afegir `storeParRequest(String uri, Map<String, String> params)` i `getParRequest(String uri)` a `InMemoryStore`.

#### P2.2 — Authorize: recuperar paràmetres del PAR

**Fitxer:** `suite/backend/fikua-server/src/main/java/com/fikua/server/issuer/IssuerRoutes.java`
**Spec:** RFC 9126 §4

**Actual** — `authorize()` llegeix els paràmetres directament dels query params, ignorant `request_uri`:

```java
String clientId = ctx.queryParam("client_id");
String redirectUri = ctx.queryParam("redirect_uri");
String state = ctx.queryParam("state");
String codeChallenge = ctx.queryParam("code_challenge");
String requestUri = ctx.queryParam("request_uri");
```

**Esperat** — Si hi ha `request_uri`, recuperar els paràmetres guardats pel PAR:

```java
String requestUri = ctx.queryParam("request_uri");
Map<String, String> params;
if (requestUri != null) {
    params = store.consumeParRequest(requestUri);  // NOU
    if (params == null) {
        ctx.status(400).json(OAuthError.invalidRequest("Invalid or expired request_uri"));
        return;
    }
} else {
    params = Map.of(
        "client_id", ctx.queryParam("client_id") != null ? ctx.queryParam("client_id") : "",
        "redirect_uri", ctx.queryParam("redirect_uri") != null ? ctx.queryParam("redirect_uri") : "",
        "state", ctx.queryParam("state") != null ? ctx.queryParam("state") : "",
        "code_challenge", ctx.queryParam("code_challenge") != null ? ctx.queryParam("code_challenge") : ""
    );
}
String clientId = params.get("client_id");
String redirectUri = params.get("redirect_uri");
String codeChallenge = params.get("code_challenge");
// ...
```

#### P2.3 — PKCE: guardar i verificar code_challenge

**Fitxers:**
- `suite/backend/fikua-server/src/main/java/com/fikua/server/issuer/IssuerRoutes.java` (authorize + token)
- `suite/backend/fikua-server/src/main/java/com/fikua/server/state/InMemoryStore.java` (session data)
**Spec:** RFC 7636, HAIP 1.0

**Actual** — `handleAuthCodeToken` comprova que `code_verifier` existeix però no el verifica contra `code_challenge`:

```java
if (config.requiresPkce()) {
    if (request.codeVerifier() == null) {
        ctx.status(400).json(OAuthError.invalidRequest("Missing code_verifier"));
        return;
    }
    // In a full implementation, verify against stored code_challenge
}
```

**Esperat** — Guardar `code_challenge` al crear l'auth code (a `authorize`) i verificar-lo al token endpoint:

```java
// A authorize(): guardar code_challenge al SessionData.metadata
Map.of("client_id", clientId, "redirect_uri", redirectUri, "code_challenge", codeChallenge)

// A handleAuthCodeToken():
if (config.requiresPkce()) {
    if (request.codeVerifier() == null) {
        ctx.status(400).json(OAuthError.invalidRequest("Missing code_verifier"));
        return;
    }
    String storedChallenge = session.metadata().get("code_challenge");
    if (!PkceUtil.verifyS256(request.codeVerifier(), storedChallenge)) {
        ctx.status(400).json(OAuthError.invalidGrant("PKCE verification failed"));
        return;
    }
}
```

**Nota:** `PkceUtil.verifyS256()` ja existeix a `fikua-core`. Verificar que `SessionData.metadata()` conté `code_challenge` des del pas authorize.

#### P2.4 — DPoP binding: vincular thumbprint al token

**Fitxers:**
- `suite/backend/fikua-server/src/main/java/com/fikua/server/issuer/IssuerRoutes.java` (token + credential)
- `suite/backend/fikua-server/src/main/java/com/fikua/server/state/InMemoryStore.java`
**Spec:** RFC 9449 §6

**Actual** — `handleAuthCodeToken` guarda `dpopKey` al `SessionData` però `credential()` no verifica que el DPoP proof al credential endpoint usi la mateixa clau:

```java
// token endpoint:
SessionData tokenSession = new SessionData(session.sessionId(), cNonce, dpopKey, Instant.now(), Map.of());

// credential endpoint:
if (config.requiresDPoP()) {
    String dpopHeader = ctx.header("DPoP");
    dpopValidator.validate(dpopHeader, "POST", baseUrl + API_PREFIX + "/credential", null);
}
```

**Esperat** — Al credential endpoint, verificar que el DPoP proof usa la mateixa clau vinculada al token:

```java
if (config.requiresDPoP()) {
    String dpopHeader = ctx.header("DPoP");
    ECKey dpopKey = dpopValidator.validate(dpopHeader, "POST", baseUrl + API_PREFIX + "/credential", null);
    // Verificar que el thumbprint coincideix amb el vinculat al token
    if (session.dpopKey() != null) {
        String expectedThumbprint = session.dpopKey().computeThumbprint().toString();
        String actualThumbprint = dpopKey.computeThumbprint().toString();
        if (!expectedThumbprint.equals(actualThumbprint)) {
            ctx.status(401).json(new OAuthError(OAuthError.INVALID_TOKEN, "DPoP key mismatch"));
            return;
        }
    }
}
```

#### P2.5 — Client attestation

**Fitxer:** Nou fitxer `suite/backend/fikua-core/src/main/java/com/fikua/core/oauth2/ClientAttestationValidator.java`
**Spec:** HAIP 1.0, OAuth Attestation-Based Client Authentication draft

**Implementació:** Validar el JWT `client_assertion` amb `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation`. Això és una WIA (Wallet Instance Attestation) signada per l'Attestation Service.

**Nota:** Per als tests OIDF, pot ser que l'OIDF conformance suite proporcioni la WIA directament. Cal investigar com la suite gestiona el client assertion.

#### P2.6 — CredentialIssuerMetadata: credential_response_encryption

**Fitxer:** `suite/backend/fikua-core/src/main/java/com/fikua/core/oid4vci/CredentialIssuerMetadata.java`
**Spec:** OID4VCI 1.0 §10, HAIP 1.0

**Actual:** El record no suporta `credential_response_encryption`.

**Esperat** — Afegir al record i al `build()` condicionalment per HAIP:

```java
// Afegir camp al record:
@JsonProperty("credential_response_encryption") Map<String, Object> credentialResponseEncryption

// Dins build(), si config.isHaip():
var responseEnc = Map.of(
    "alg_values_supported", List.of("ECDH-ES"),
    "enc_values_supported", List.of("A128GCM"),
    "encryption_required", false
);
```

#### P2 — Checklist

- [ ] P2.1: PAR persistence a `InMemoryStore`
- [ ] P2.2: Authorize resol `request_uri` del PAR
- [ ] P2.3: PKCE: guardar challenge, verificar amb `PkceUtil.verifyS256()`
- [ ] P2.4: DPoP binding: verificar thumbprint al credential endpoint
- [ ] P2.5: Client attestation validator (pot ser stub inicial)
- [ ] P2.6: `credential_response_encryption` al metadata
- [ ] Compilar i tests: `./gradlew build`
- [ ] Executar Test #1 OIDF

#### P2 — Acceptance criteria

P2 es considera COMPLETAT quan:

1. **Build + tests:** `./gradlew build` passa. Tests d'integració per PAR→authorize→token→credential flow.
2. **HAIP flow complet amb curl:**
   - `POST /oid4vci/v1/par` amb `code_challenge` + `client_assertion` → retorna `request_uri` (201)
   - `GET /oid4vci/v1/authorize?request_uri=...` → recupera paràmetres del PAR, redirigeix amb `code`
   - `POST /oid4vci/v1/token` amb `code` + `code_verifier` + DPoP proof → retorna `access_token` (DPoP-bound) + `c_nonce`
   - `POST /oid4vci/v1/token` amb `code_verifier` incorrecte → retorna `400 invalid_grant` (PKCE fail)
   - `POST /oid4vci/v1/credential` amb DPoP proof d'una clau diferent → retorna `401` (DPoP key mismatch)
3. **Metadata:** `credential_response_encryption` present a issuer metadata amb `alg_values_supported` i `enc_values_supported`
4. **Test OIDF #1:** Configurar i executar
5. **Commits:** Un commit per sub-gap, format correcte

---

### P3 — Necessari per Tests #3, #4 OIDF (Wallet)

**Fitxer principal:** `suite/frontend/holder/app.js`
**Spec:** OID4VCI 1.0 (wallet side), HAIP 1.0

Tota la lògica de protocol del wallet s'implementa en JavaScript vanilla dins `app.js`. Les funcions a crear:

| Funció | Responsabilitat |
|--------|----------------|
| `handleCredentialOffer()` | Detectar i parsejar query params, fetch by_reference |
| `fetchWellKnown(issuerUrl)` | GET `.well-known/openid-credential-issuer` + `oauth-authorization-server` |
| `generateKeyPair()` | `crypto.subtle.generateKey('ECDSA', P-256)` |
| `buildProofJwt(key, nonce, issuerUrl)` | Construir i signar `openid4vci-proof+jwt` |
| `requestToken(offer, metadata)` | POST al token endpoint (pre-auth o auth code) |
| `requestCredential(token, nonce, metadata)` | POST al credential endpoint amb proof |
| `buildDPoPProof(key, method, url)` | Construir DPoP proof JWT (HAIP) |
| `parseSdJwt(serialized)` | Separar per `~`, descodificar disclosures |
| `showConsentScreen(credential)` | UI per acceptar/rebutjar |
| `sendNotification(token, notificationId, event)` | POST al notification endpoint |

#### P3 — Checklist

- [ ] Wallet: `handleCredentialOffer()` — detectar params, fetch by_reference, replaceState
- [ ] Wallet: `fetchWellKnown()` — GET ambdós metadata
- [ ] Wallet: `generateKeyPair()` — Web Crypto API EC P-256
- [ ] Wallet: `buildProofJwt()` — header typ/alg/jwk, payload iss/aud/iat/nonce
- [ ] Wallet: `requestToken()` — pre-auth i auth code grant types
- [ ] Wallet: `requestCredential()` — credential request amb proof
- [ ] Wallet: `buildDPoPProof()` — DPoP proof per HAIP
- [ ] Wallet: `parseSdJwt()` — parser SD-JWT VC
- [ ] Wallet: `showConsentScreen()` — UI consentiment
- [ ] Wallet: `sendNotification()` — notification endpoint

#### P3 — Acceptance criteria

P3 es considera COMPLETAT quan:

1. **Pre-auth flow E2E:** El wallet pot rebre un credential offer (query param), obtenir token, obtenir credencial, i mostrar-la a la UI. Verificat manualment al navegador.
2. **HAIP flow E2E:** Mateix flux amb DPoP, PAR i PKCE. Verificat manualment.
3. **SD-JWT parsing:** Les disclosures es mostren correctament a la credential card
4. **Console zero errors:** No hi ha errors a la console del navegador durant tot el flux
5. **Test OIDF #3 i #4:** Configurar i executar

---

### P4 — Flux complet UX

#### P4.1 — IssuanceRecord

**Fitxer nou:** `suite/backend/fikua-server/src/main/java/com/fikua/server/db/IssuanceRecordRepository.java`
**Fitxer nou:** `suite/backend/fikua-server/src/main/resources/db/migration/V*.sql`
**Model:** Veure secció "IssuanceRecord — Model" d'aquest document.

#### P4.2 — Connectar issuer frontend amb backend

**Fitxers:**
- `suite/frontend/issuer/app.js` — enviar dades cert al backend via POST
- `suite/backend/fikua-server/src/main/java/com/fikua/server/issuer/IssuerRoutes.java` — nou endpoint POST per rebre dades cert i retornar credential offer

#### P4.3 — Presentació de l'offer

**Fitxer:** `suite/frontend/issuer/index.html` + `app.js`

Elements a afegir al HTML:
1. Canvas/div per QR code (llibreria `qrcode.js` o similar via CDN)
2. Botó "Open in Wallet" amb href dinàmic
3. Input readonly + botó copiar amb la URL completa

#### P4 — Checklist

- [ ] P4.1: `IssuanceRecord` model + repository + migration SQL
- [ ] P4.2: Endpoint POST issuer per rebre dades cert → retornar offer
- [ ] P4.2: Frontend issuer: enviar dades cert al backend
- [ ] P4.3: Frontend issuer: QR code (cross-device)
- [ ] P4.3: Frontend issuer: botó "Open in Wallet" (same-device)
- [ ] P4.3: Frontend issuer: URL copiable (testing OIDF)
- [ ] P4.4: Wallet: detectar query params `credential_offer` / `credential_offer_uri`
- [ ] P4.5: Substituir dades hardcoded per dades reals del certificat

#### P4 — Acceptance criteria

P4 es considera COMPLETAT quan:

1. **Persistència:** `IssuanceRecord` es guarda a PostgreSQL. Flyway migration funciona.
2. **Issuer UI → Backend → Wallet:** L'usuari omple el formulari a l'issuer frontend → el backend crea l'offer → es mostra QR/link → el wallet el processa i obté la credencial.
3. **Tres modes de delivery:** QR code (escanejable amb mòbil), botó "Open in Wallet" (same-device), URL copiable (testing).
4. **Dades reals:** La credencial conté les dades del certificat, no dades hardcoded.

---

### P5 — Revocació (Token Status List)

**Fitxers nous:**
- `suite/backend/fikua-core/src/main/java/com/fikua/core/sdjwt/StatusList.java`
- `suite/backend/fikua-core/src/main/java/com/fikua/core/sdjwt/StatusListToken.java`
- `suite/backend/fikua-server/src/main/java/com/fikua/server/db/StatusListRepository.java`

**Fitxers a modificar:**
- `suite/backend/fikua-core/src/main/java/com/fikua/core/sdjwt/SdJwtBuilder.java` — afegir claim `status`
- `suite/backend/fikua-core/src/main/java/com/fikua/core/oid4vci/CredentialResponse.java` — afegir `notification_id`
- `suite/backend/fikua-server/src/main/java/com/fikua/server/issuer/IssuerRoutes.java` — endpoint statuslist + notification

**Spec:** Token Status List draft-12, OID4VCI 1.0 §11
**Detall:** Veure seccions "Token Status List — Implementació" i "IssuanceRecord — Model" d'aquest document.

#### P5 — Checklist

- [ ] `StatusList`: bit array comprimit (DEFLATE+ZLIB), assignació d'índexs
- [ ] `StatusListToken`: generació del JWT `statuslist+jwt`
- [ ] `StatusListRepository`: persistència a PostgreSQL
- [ ] Endpoint `GET /oid4vci/v1/statuslist/{id}` (`application/statuslist+jwt`)
- [ ] `SdJwtBuilder`: afegir claim `status` amb `status_list` (idx + uri)
- [ ] `CredentialResponse`: afegir `notification_id`
- [ ] Endpoint `POST /oid4vci/v1/notification`
- [ ] Admin API per revocar credencials (canviar bit al StatusList)

#### P5 — Acceptance criteria

P5 es considera COMPLETAT quan:

1. **Status list:** `GET /oid4vci/v1/statuslist/{id}` retorna `application/statuslist+jwt` amb bit array DEFLATE+ZLIB vàlid
2. **Credencial amb status:** Cada SD-JWT VC emesa conté `status.status_list` amb `idx` i `uri` vàlids
3. **Revocació:** Canviar el bit via admin API → el status list reflecteix el canvi → un verifier pot detectar-ho
4. **Notification:** `POST /oid4vci/v1/notification` accepta `notification_id` + `event` i actualitza l'`IssuanceRecord`
5. **Tests:** Tests unitaris per `StatusList` (compress/decompress, set/get bit) i `StatusListToken` (JWT vàlid). Test d'integració per revocació E2E.
