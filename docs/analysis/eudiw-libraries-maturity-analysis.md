# EUDIW Reference Implementation — Maturity Analysis & Product Impact

**Proyecto:** EUDIStack — Digital Identity Platform
**Fecha:** 2026-02-17
**Autor:** Oriol Canadés (con asistencia IA)
**Estado:** Borrador
**Clasificación:** Interno

---

## Control de versiones

| Versión | Fecha      | Autor          | Cambios                                                                                              |
|---------|------------|----------------|------------------------------------------------------------------------------------------------------|
| 0.1     | 2026-02-17 | Oriol Canadés  | Análisis inicial: 79 repositorios EUDIW, clasificación, madurez, impacto en producto                 |
| 0.2     | 2026-02-19 | Oriol Canadés  | Análisis en profundidad de wallet-ui (Android + iOS): features, specs, arquitectura, release history |

---

## Objetivo

Evaluar los 79 repositorios del EUDIW Reference Implementation para:

1. **Madurez** — comparar las capacidades de las librerías con el ARF v2.8.0
2. **Valor de la App Nativa** — beneficios de implementar un Wallet nativo vs. el enfoque web actual
3. **Personalización** — grado de customización (look & feel, white-labeling, features) que permiten las librerías

---

## Índice

- [1. Inventario completo — 79 repositorios](#1-inventario-completo--79-repositorios)
- [2. Repositorios relevantes para EUDIStack](#2-repositorios-relevantes-para-eudistack)
- [3. Análisis de madurez por plataforma](#3-análisis-de-madurez-por-plataforma)
- [4. Mapeo contra ARF v2.8.0](#4-mapeo-contra-arf-v280)
- [5. Valor de la App Nativa](#5-valor-de-la-app-nativa)
- [6. Análisis de personalización](#6-análisis-de-personalización)
- [7. Repositorios no relevantes](#7-repositorios-no-relevantes)
- [8. Análisis en profundidad de las Wallet-UI de referencia](#8-análisis-en-profundidad-de-las-wallet-ui-de-referencia)
- [9. Conclusiones y recomendaciones](#9-conclusiones-y-recomendaciones)

---

## 1. Inventario completo — 79 repositorios

Los 79 repositorios de `eu-digital-identity-wallet` se organizan en las siguientes categorías:

| Categoría | Cantidad | Descripción |
|-----------|----------|-------------|
| **Android/Kotlin libs** | 12 | Wallet app, core SDK, document manager, data transfer, OID4VCI/VP, SD-JWT, RQES, verifier |
| **iOS/Swift libs** | 14 | Wallet app, wallet kit, storage, OID4VCI/VP, ISO 18013-5 (3 libs), SD-JWT, presentation exchange, RQES (3 libs), status list |
| **Backend services (Kotlin)** | 4 | PID Issuer, Verifier endpoint, Wallet Provider, Trust Validator |
| **Backend services (Python)** | 7 | Issuer (backend + frontend + auth), Status List, Trusted List Manager, RP Registration, Booking demo |
| **Documentation** | 5 | ARF, Standards tracker, Testing, Roadmap, Attestation Rulebooks |
| **Web frontends** | 3 | Web Verifier (Angular), Recruitment demo, Wallet tester |
| **RQES services** | 6 | Wallet-driven/RP-centric signers, SCA, tester |
| **Age Verification (AV)** | 7 | Separate track for age verification (ZKP, verifier, issuer) |
| **Infrastructure/Other** | 8 | CI, DevHub site, .github, PoDoFo, SwiftCopyableMacro, OpenID4V, multiplatform verifier, ETSI lib |
| **Deprecated/Other** | ~13 | Repos sin actividad o especializados |

---

## 2. Repositorios relevantes para EUDIStack

De los 79 repositorios, **36 son directamente relevantes** para nuestro producto. Los clasificamos por prioridad:

### Prioridad ALTA (impacto directo en producto)

| # | Repositorio | Plataforma | Propósito | Versión | Última release |
|---|-------------|-----------|-----------|---------|----------------|
| 1 | `eudi-doc-architecture-and-reference-framework` | Docs | **THE spec** — ARF v2.8.0 | v2.8.0 | Feb 2026 |
| 2 | `eudi-lib-android-wallet-core` | Android | SDK orquestador central del wallet | v0.24.0 | Ene 2025 |
| 3 | `eudi-lib-ios-wallet-kit` | iOS | SDK orquestador central del wallet | v0.20.3 | Feb 2025 |
| 4 | `eudi-app-android-wallet-ui` | Android | App de referencia (Jetpack Compose) | 2026.02.35-Demo | Feb 2026 |
| 5 | `eudi-app-ios-wallet-ui` | iOS | App de referencia (SwiftUI) | 2026.02.35-Demo | Feb 2026 |
| 6 | `eudi-lib-jvm-openid4vci-kt` | JVM | Protocolo OID4VCI (wallet role) | v0.9.1 | Oct 2024 |
| 7 | `eudi-lib-ios-openid4vci-swift` | iOS | Protocolo OID4VCI (wallet role) | v0.20.0 | Feb 2025 |
| 8 | `eudi-lib-jvm-openid4vp-kt` | JVM | Protocolo OID4VP + DCQL | v0.12.2 | Ene 2025 |
| 9 | `eudi-lib-ios-openid4vp-swift` | iOS | Protocolo OID4VP + DCQL | v0.20.0 | Ene 2025 |
| 10 | `eudi-lib-jvm-sdjwt-kt` | JVM | SD-JWT issuer/holder/verifier | v0.18.0 | Ene 2025 |
| 11 | `eudi-lib-sdjwt-swift` | iOS | SD-JWT issuer/holder/verifier | v0.13.0 | Feb 2025 |
| 12 | `eudi-srv-pid-issuer` | Kotlin | Issuer de referencia (OID4VCI) | - | Activo |
| 13 | `eudi-srv-verifier-endpoint` | Kotlin | Verifier de referencia (OID4VP) | - | Activo |
| 14 | `eudi-srv-trust-validator` | Kotlin | Validación cadena X.509 vs ETSI TL | - | Muy temprano |
| 15 | `eudi-srv-statuslist-py` | Python | Revocación (ASL + ARL) | - | Muy temprano |

### Prioridad MEDIA (relevantes para funcionalidades avanzadas)

| # | Repositorio | Plataforma | Propósito | Versión | Última release |
|---|-------------|-----------|-----------|---------|----------------|
| 16 | `eudi-lib-android-wallet-document-manager` | Android | Gestión de documentos + políticas | v0.14.0 | Ene 2025 |
| 17 | `eudi-lib-android-iso18013-data-transfer` | Android | Transferencia BLE/NFC (proximity) | v0.11.0 | Ene 2025 |
| 18 | `eudi-lib-ios-iso18013-data-transfer` | iOS | Transferencia BLE (proximity) | v0.3.3 | Oct 2024 |
| 19 | `eudi-lib-ios-iso18013-data-model` | iOS | Modelo de datos mDoc (CBOR) | v0.3.3 | Oct 2024 |
| 20 | `eudi-lib-ios-iso18013-security` | iOS | Seguridad mDoc (ECDH, auth) | v0.2.6 | Oct 2024 |
| 21 | `eudi-lib-ios-wallet-storage` | iOS | Almacenamiento Keychain iOS | v0.8.3 | Feb 2025 |
| 22 | `eudi-lib-kmp-statium` | KMP | Token Status List (revocación) | v0.4.0 | Sep 2025 |
| 23 | `eudi-lib-ios-statium-swift` | iOS | Token Status List (revocación) | v0.3.1 | Ene 2025 |
| 24 | `eudi-lib-kmp-etsi-1196x2` | KMP | Validación ETSI Trust Lists | v0.2.2 | Temprano |
| 25 | `eudi-lib-jvm-trust-manager-kt` | JVM | Validación mDoc (ISO 18013-5) | - | Temprano |
| 26 | `eudi-srv-wallet-provider` | Kotlin | Wallet Instance Attestations | - | Temprano |
| 27 | `eudi-srv-web-trustedlist-manager-py` | Python | Gestión de Trusted Lists | - | Temprano |
| 28 | `eudi-web-verifier` | Angular | UI del Verifier (referencia) | v0.10.0 | Dic 2025 |
| 29 | `eudi-doc-standards-and-technical-specifications` | Docs | Tracker de estándares y gaps | - | Activo |
| 30 | `eudi-wallet-reference-implementation-roadmap` | Docs | Roadmap público de features | - | Activo |

### Prioridad BAJA (RQES, demos, testing)

| # | Repositorio | Plataforma | Propósito |
|---|-------------|-----------|-----------|
| 31 | `eudi-lib-android-rqes-core` | Android | RQES core (CSC API v2) |
| 32 | `eudi-lib-android-rqes-ui` | Android | RQES UI (Jetpack Compose) |
| 33 | `eudi-lib-ios-rqes-kit` | iOS | RQES core |
| 34 | `eudi-lib-ios-rqes-ui` | iOS | RQES UI (SwiftUI) |
| 35 | `eudi-lib-ios-rqes-csc-swift` | iOS | CSC API v2 Swift client |
| 36 | `eudi-doc-testing-application` | Java | Test E2E (Appium/Gherkin) |

---

## 3. Análisis de madurez por plataforma

### Declaración global de madurez

> **Ninguna librería del EUDIW Reference Implementation es production-ready.** Todas llevan el disclaimer explícito: *"We strongly recommend to not put this version of the software into production use."* Todas usan versionado 0.x.

Sin embargo, hay niveles significativos de diferencia:

### 3.1. Android/Kotlin — Resumen

| Librería | Versión | Releases | Cadencia | Madurez |
|----------|---------|----------|----------|---------|
| wallet-core | v0.24.0 | 24 | Mensual | **Alpha activa** |
| sdjwt-kt | v0.18.0 | 18 | Mensual | **Alpha madura** |
| document-manager | v0.14.0 | 14 | Mensual | **Alpha activa** |
| openid4vp-kt | v0.12.2 | 12 | Mensual | **Alpha activa** |
| iso18013-data-transfer | v0.11.0 | 11 | Bimensual | **Alpha** |
| openid4vci-kt | v0.9.1 | 9 | ~Trimestral | **Alpha estabilizando** |
| rqes-ui | v0.3.5 | 10 | Mensual | **Alpha activa** |
| rqes-core | v0.4.0 | 5 | ~Trimestral | **Alpha temprana** |
| statium (KMP) | v0.4.0 | 5 | ~Trimestral | **Alpha nueva** |
| presentation-exchange-kt | v0.4.0 | 5 | Lenta | **Alpha mínima** |
| verifier-core | v0.1.0 | 1 | N/A | **Embrionaria** |

**Hallazgos clave Android:**
- `wallet-core` es el SDK más extensible (9+ interfaces inyectables)
- `sdjwt-kt` es la librería más madura por feature completeness (RFC 9901 + SD-JWT-VC draft 13)
- `verifier-core` tiene una sola release — API inestable
- NFC data transfer no soportado (solo NFC para device engagement); BLE es el único canal de datos
- `presentation-exchange-kt` tiene 5 de 6 features opcionales sin implementar — posiblemente reemplazada por DCQL

### 3.2. iOS/Swift — Resumen

| Librería | Versión | Releases | Cadencia | Madurez |
|----------|---------|----------|----------|---------|
| wallet-kit | v0.20.3 | 20+ | Semanal | **Alpha muy activa** |
| openid4vci-swift | v0.20.0 | 20 | Mensual | **Alpha activa** |
| openid4vp-swift | v0.20.0 | 20 | Mensual | **Alpha activa** |
| sdjwt-swift | v0.13.0 | 13 | Mensual | **Alpha activa** |
| wallet-storage | v0.8.3 | 8+ | Trimestral | **Alpha** |
| rqes-kit | v0.7.0 | 7 | Trimestral | **Alpha** |
| rqes-csc-swift | v0.7.1 | 7+ | Trimestral | **Alpha** |
| rqes-ui | v0.4.0 | 5+ | Trimestral | **Alpha** |
| presentation-exchange | v0.4.0 | 6 | **Estancada** | **Alpha estancada** |
| iso18013-data-transfer | v0.3.3 | 4 | Lenta | **Alpha temprana** |
| iso18013-data-model | v0.3.3 | 8 | Lenta | **Alpha temprana** |
| iso18013-security | v0.2.6 | 8 | Lenta | **Alpha temprana** |
| statium-swift | v0.3.1 | 5 | Trimestral | **Alpha** |

**Hallazgos clave iOS:**
- `wallet-kit` es el más activo (4 releases solo en febrero 2025)
- Las librerías ISO 18013-5 (data-model, security, data-transfer) están estabilizando — última release Oct 2024
- `presentation-exchange` lleva 9 meses sin releases — posiblemente reemplazada por DCQL
- Device engagement solo via QR (no NFC)
- Swift 6 compatibility completada en todo el stack
- iOS 16 es el mínimo general; la app de referencia requiere iOS 17

### 3.3. Backend services — Resumen

| Servicio | Tech | Commits | Madurez | Relevancia |
|----------|------|---------|---------|------------|
| pid-issuer | Kotlin/Spring | 383 | Alpha activa | **ALTA** |
| verifier-endpoint | Kotlin/Spring | 398 | Alpha activa | **ALTA** |
| wallet-provider | Kotlin/Spring | ~50 | Alpha temprana | Media |
| trust-validator | Kotlin/Spring | 14 | **Embrionario** | ALTA (conceptual) |
| statuslist-py | Python | 35 | **Embrionario** | ALTA (crítico) |
| trustedlist-manager-py | Python/Flask | 155 | Alpha temprana | Media-Alta |
| issuing-eudiw-py | Python/Flask | ~100 | Alpha | Alta |

**Hallazgos clave Backend:**
- `pid-issuer` y `verifier-endpoint` son los más maduros (~400 commits cada uno)
- **Trust infrastructure es crítica pero inmadura**: `trust-validator` tiene solo 14 commits
- **Revocación es un single point of concern**: `statuslist-py` es el único componente de revocación (35 commits)
- Dual tech stack: Kotlin/Spring Boot + Python/Flask
- Protocolo convergente: OID4VCI 1.0 + OID4VP 1.0 en todos los servicios
- Dual formato obligatorio: `mso_mdoc` + `SD-JWT-VC` (`dc+sd-jwt`)

---

## 4. Mapeo contra ARF v2.8.0

### 4.1. Cobertura de Topics ARF por las librerías EUDIW

| Topic ARF | Descripción | Cobertura Android | Cobertura iOS | Cobertura Backend |
|-----------|-------------|-------------------|---------------|-------------------|
| **R — Key Management** | WSCD, Keystore, key binding | Android Keystore + custom SecureArea | Secure Enclave via wallet-kit | Wallet Provider (attestations) |
| **R — User Auth** | WIAM_14/15 (OS-level + WSCD) | Biometría nativa, PIN | FaceID/TouchID, PIN | N/A (client-side) |
| **T — Security Posture** | WPSM_01-03 | Play Integrity API (en wallet-core) | App Attest (iOS) | Wallet Provider validates |
| **T — Device Integrity** | Root/jailbreak, emulator | Native detection disponible | Native detection disponible | N/A |
| **E — Pseudonyms** | Use Cases A-D | WebAuthn (parcial) | No documentado | No implementado |
| **Formats** | dc+sd-jwt (Mandatory) | SD-JWT-VC draft 13 via sdjwt-kt | SD-JWT-VC via sdjwt-swift | Dual format en pid-issuer |
| **Formats** | mso_mdoc (Mandatory) | ISO 18013-5 via data-transfer | ISO 18013-5 via data-transfer | Dual format en pid-issuer |
| **Issuance** | OID4VCI 1.0 | openid4vci-kt (v0.9.1) | openid4vci-swift (v0.20.0) | pid-issuer + issuing-eudiw-py |
| **Presentation** | OID4VP 1.0 + DCQL | openid4vp-kt + DCQL (parcial) | openid4vp-swift + DCQL | verifier-endpoint + DCQL |
| **Proximity** | ISO 18013-5 (BLE/NFC) | BLE completo, NFC solo engagement | BLE completo, NFC no disponible | N/A |
| **Trust** | ETSI TS 119 602/612, LOTL | N/A (server-side) | N/A (server-side) | trust-validator + etsi-1196x2 |
| **Revocation** | Token Status List | statium (KMP) | statium-swift | statuslist-py |
| **RQES** | CSC API v2 | rqes-core + rqes-ui | rqes-kit + rqes-ui + rqes-csc | rqes-qtsp services |
| **HAIP** | High Assurance Profile | Parcial (en wallet-core) | Parcial (en wallet-kit) | verifier-endpoint soporta |

### 4.2. Gaps significativos vs ARF v2.8.0

| Gap | Descripción | Impacto |
|-----|-------------|---------|
| **NFC data transfer** | Solo NFC para device engagement; datos solo via BLE | No compliant con ISO 18013-5 full spec |
| **WiFi-Aware** | No soportado en ninguna plataforma | Limitación para transferencias de gran volumen |
| **OpenID Federation** | No implementado | No puede federar trust dinámicamente |
| **Digital Credential API** | No implementado (DC API W3C) | Limitación para flujos browser-based |
| **SIOPv2** | Eliminado de OID4VP v0.12+ | Breaking change si se dependía de SIOPv2 |
| **Presentation Exchange v2** | 5 de 6 features opcionales sin implementar | Puede ser reemplazada por DCQL |
| **DCQL parcial** | `claim_sets` y múltiples credentials no soportados (Android) | Queries complejas no posibles aún |
| **Trust infrastructure** | trust-validator con 14 commits; statuslist-py con 35 | **Riesgo**: no hay componente de trust/revocación maduro |
| **Wallet Attestations** | wallet-provider es mock por defecto | Attestaciones de wallet no verificables en producción |

### 4.3. Alineamiento con el estado actual de EUDIStack

| Área | EUDIStack v1.1 (actual) | EUDIW Ref Implementation | Gap |
|------|------------------------|--------------------------|-----|
| **Plataforma wallet** | Web-based (TypeScript/Angular) | Native Android (Kotlin) + Native iOS (Swift) | **Fundamental**: Web vs Native |
| **Formato** | `jwt_vc_json` (transitorio) | `dc+sd-jwt` + `mso_mdoc` (ambos Mandatory) | Formato no alineado |
| **Issuance** | OID4VCI pre-authorized_code | OID4VCI auth_code + pre-authorized | Falta authorization_code flow |
| **Presentation** | OID4VP scope-based | OID4VP DCQL + presentation_exchange | Falta DCQL |
| **Key management** | Web Crypto (software) / QTSP | Android Keystore / Secure Enclave | Web Crypto no califica como Keystore ARF |
| **Proximity** | No soportado | ISO 18013-5 BLE + QR engagement | Gap completo |
| **Trust** | ETSI TS 119 602 (diseñado, no implementado) | trust-validator + etsi-1196x2 (embrionario) | Ambos tempranos |
| **Revocation** | Token Status List (diseñado) | statium + statuslist-py | Ambos tempranos |
| **Device integrity** | Imposible (browser) | Play Integrity / App Attest | Gap fundamental web vs native |
| **RQES** | QTSP planned (gap §16.1) | rqes-core/kit + rqes-ui + CSC API | Gap: EUDIW tiene implementación funcional |

---

## 5. Valor de la App Nativa

### 5.1. Beneficios exclusivos de una App Nativa vs Web

| Capacidad | Web (actual) | App Nativa (EUDIW libs) | Impacto en ARF compliance |
|-----------|-------------|------------------------|---------------------------|
| **Hardware-backed keys** | Imposible (Web Crypto = software) | Android Keystore / Secure Enclave directo | **Requerido** para Keystore ARF |
| **WSCD access** | Imposible | Secure Element / StrongBox certificado | **Requerido** para LoA High (PID) |
| **BLE proximity** | Web Bluetooth (muy limitado) | CoreBluetooth / BLE nativo | **Requerido** para ISO 18013-5 |
| **NFC engagement** | Imposible | NFC nativo | **Requerido** para ISO 18013-5 |
| **Device integrity** | Imposible detectar root/jailbreak | Play Integrity / App Attest | **Requerido** por ARF Topic T |
| **Biometría nativa** | WebAuthn (indirecto) | FaceID/TouchID/Fingerprint directo | Mejor UX, compliance WIAM_15 |
| **Background processing** | Service Worker (limitado) | Background services nativos | Necesario para sync/push |
| **Push notifications** | Web Push (parcial) | FCM/APNs nativos | Notificaciones de credenciales |
| **Deep linking** | Universal Links (con limitaciones) | Deep links nativos | Flujos OID4VCI/VP cross-app |
| **Crash reporting** | `window.onerror` (~20%) | Native crash reporting (100%) | ARF Topic T WPSM_01 |
| **OS version detection** | UserAgent (poco fiable) | API nativa completa | ARF Topic T WPSM_03 |

### 5.2. Tabla de compliance ARF por plataforma

| Requisito ARF | WebApp | PWA | App Nativa |
|---------------|--------|-----|------------|
| Keystore ARF-compliant | **No** | **No** | **Sí** |
| WSCD posible | **No** | **No** | **Sí** (si SE certificado) |
| Puede manejar PIDs | **No** | **No** | **Sí** (con Remote WSCD) |
| Security Posture L4 | **No viable** | **No viable** | **Completo** |
| WPSM_01 (datos) | ~20% | ~30% | **100%** |
| WPSM_03 (security posture) | ~10% | ~15% | **100%** |
| Proximity (ISO 18013-5) | **No** | **No** | **Sí** |
| Certificación posible | **No** | **No** | **Sí** |

### 5.3. Coexistencia Web + Native — Estrategia recomendada

EUDIStack v1.x opera como **European Business Wallet** con credenciales empresariales (LEARCredential). Para este caso de uso, Web Crypto es suficiente (§11.8.1 del Wallet Holder DT).

Sin embargo, para evolucionar hacia **EUDIW citizen wallet compliance** o soportar **PIDs y attestations LoA High**, la app nativa es **obligatoria**.

```
Estrategia de coexistencia:

┌──────────────────────────────────────────────────────────────────┐
│                    EUDIStack Product Line                        │
│                                                                  │
│  ┌──────────────────────────┐  ┌──────────────────────────────┐  │
│  │  Web Wallet (actual)     │  │  Native Wallet (futuro)      │  │
│  │                          │  │                              │  │
│  │  • Business credentials  │  │  • Business + PID            │  │
│  │  • LEARCredential        │  │  • LoA High attestations     │  │
│  │  • Web Crypto keys       │  │  • Hardware-backed keys      │  │
│  │  • Remote (OID4VP)       │  │  • Remote + Proximity        │  │
│  │  • EUBW scope            │  │  • EUBW + EUDIW scope        │  │
│  │  • COMMUNITY tier        │  │  • COMMUNITY + LICENSED      │  │
│  │                          │  │                              │  │
│  │  Shared: OID4VCI/VP CORE │  │  + EUDIW libs (Kotlin/Swift) │  │
│  └──────────────────────────┘  └──────────────────────────────┘  │
│                                                                  │
│  Shared Enterprise Backend (Java 25, Spring Boot)                │
│  • Credential Issuer CORE                                        │
│  • Verifier CORE                                                 │
│  • Trust Framework (ETSI TS 119 602)                             │
│  • Backup / Recovery                                             │
└──────────────────────────────────────────────────────────────────┘
```

---

## 6. Análisis de personalización

### 6.1. Grado de customización de las EUDIW libs

#### Android (wallet-core + wallet-ui)

| Punto de extensión | Tipo | Descripción |
|-------------------|------|-------------|
| `SecureArea` | Interface | Custom key storage (Android Keystore, HSM, etc.) |
| `Storage` | Interface | Custom document persistence |
| `ReaderTrustStore` | Interface | Custom trusted certificates |
| `Logger` | Interface | Custom logging backend |
| `HttpClientFactory` | Interface | Custom HTTP client (Ktor) |
| `TransactionLogger` | Interface | Custom audit trail |
| `DocumentStatusResolver` | Interface | Custom revocation check |
| `WalletKeyManager` | Interface | Custom wallet key management |
| `WalletAttestationsProvider` | Interface | Custom wallet attestation generation |
| Metadata/Display | Config | Nombres, logos, colores por locale |
| Credential policies | Config | OneTimeUse, RotateUse, batch policies |
| BLE parameters | Config | Configurable BLE settings |

**Evaluación Android: 9/10 en extensibilidad arquitectónica.** La wallet-core ofrece 9+ interfaces inyectables. Sin embargo, la app de referencia (wallet-ui) tiene **documentación limitada de white-labeling** — no hay API formal de theming más allá de Jetpack Compose Material3.

#### iOS (wallet-kit + wallet-ui)

| Punto de extensión | Tipo | Descripción |
|-------------------|------|-------------|
| `SecureArea` | Protocol | Custom secure key storage |
| Per-docType key options | Config | Curva, secure area, unlock policy por tipo |
| Multiple OID4VCI issuer configs | Config | Múltiples issuers configurables |
| `WalletAttestationsProvider` | Protocol | Custom wallet attestations |
| Theme/UI | SwiftUI | Modificable como código SwiftUI estándar |

**Evaluación iOS: 7/10 en extensibilidad.** wallet-kit ofrece buenos puntos de extensión pero menos que Android. La app de referencia es SwiftUI, lo que facilita el theming pero no tiene una API de white-labeling formal.

#### RQES UI (Android + iOS) — Mejor white-labeling del ecosistema

| Punto de extensión | Android (rqes-ui) | iOS (rqes-ui) |
|-------------------|-------------------|---------------|
| Multi-idioma | `Map<String, Map<LocalizableKey, String>>` | Translations configurable |
| Theming | `ThemeManager` interface | `ThemeProtocol` |
| QTSP múltiples | Configurable | Configurable |
| Deep links | Configurable scheme | Universal/deep links |
| Algoritmos | Hash + signing configurable | Hash configurable |

### 6.2. Lo que NO se puede personalizar fácilmente

| Limitación | Android | iOS | Impacto |
|-----------|---------|-----|---------|
| Flujos de navegación | Fijos en feature modules | Fijos en wallet-kit | Requiere fork para cambiar UX flow |
| Credential rendering | Metadata-driven (limitado) | Metadata-driven (limitado) | No hay template engine |
| Consent screens | Built-in | Built-in | Texto personalizable, layout no |
| Onboarding | Built-in | Built-in | Requiere fork |
| Error handling UX | Built-in | Built-in | Mensajes personalizables, UX no |

### 6.3. Estrategia de personalización recomendada

| Enfoque | Descripción | Pros | Contras |
|---------|-------------|------|---------|
| **Fork de wallet-ui** | Fork + customize de la app de referencia | Control total | Mantenimiento de merge con upstream |
| **Wrapper sobre wallet-core/kit** | App propia que usa el SDK | Control UI total, actualizable | Más trabajo inicial |
| **Capacitor bridge** | Bridge nativo desde Ionic/Angular | Reutiliza código web existente | Performance, complejidad bridge |

**Recomendación:** Para EUDIStack, la opción **"Wrapper sobre wallet-core/kit"** es la más viable. Permite:
- Mantener la UI y branding propios
- Beneficiarse de las actualizaciones del SDK sin merge conflicts
- Integrar con el Enterprise Backend existente (Java 25)
- Compartir lógica de negocio con la versión web (via APIs)

---

## 7. Repositorios no relevantes

Los siguientes repositorios **no aportan valor directo** a EUDIStack:

| Repositorio | Razón de exclusión |
|-------------|-------------------|
| `av-*` (7 repos) | Track de Age Verification separado (ZKP-based) |
| `pyMDOC-CBOR` | Python-only mDL issuer, no usa OID4VCI |
| `idpy-oidc` | Fork de librería OIDC genérica Python |
| `openid4v` | Implementación genérica OIDC Python |
| `eudi-lib-podofo` | Manipulación PDF (C++ wrapper) |
| `SwiftCopyableMacro` | Utility macro Swift |
| `eudi-infra-ci` | CI/CD interno |
| `eudi-docs-site` | Configuración del DevHub site |
| `eudi-itb` | Interoperability Test Bed (no público) |
| `eudi-doc-transfer-issues` | Issue tracker interno |
| `eudi-doc-attestation-rulebooks-catalog` | Catálogo de rulebooks (referencia) |
| `eudi-doc-functional-conformance-assessment` | Assessment interno |
| `eudi-app-multiplatform-verifier-ui` | Verifier multiplatform (KMP) — overlap con verifier-endpoint |
| `eudi-web-recruitment-service-demo` | Demo de recruitment |
| `eudi-web-booking-service-demo` | Demo de booking |
| `eudi-app-web-wallet-tester-py` | Tester de wallet |
| `eudi-app-web-walletdriven-tester-py` | Tester RQES |
| `eudi-srv-web-walletdriven-*` (3 repos) | Servicios RQES wallet-driven |
| `eudi-srv-web-rpcentric-*` (2 repos) | Servicios RQES RP-centric |
| `eudi-srv-web-trustprovider-signer-java` | TrustProvider signer RQES |

---

## 8. Análisis en profundidad de las Wallet-UI de referencia

Las apps de referencia (`eudi-app-android-wallet-ui` y `eudi-app-ios-wallet-ui`) son **aplicaciones nativas completas** que implementan la capa de UI sobre los SDKs orquestadores (`wallet-core` / `wallet-kit`). Ambas llevan el sufijo `-Demo` en todas sus releases y están explícitamente marcadas como **no aptas para producción**.

> *"Initial development release… reduced security, privacy, availability, and reliability standards… Not recommended for production deployment."*

### 8.1. Arquitectura por capas

```
Capa 3:  eudi-app-android-wallet-ui  /  eudi-app-ios-wallet-ui    ← APP DE REFERENCIA (UI)
Capa 2:  eudi-lib-android-wallet-core  /  eudi-lib-ios-wallet-kit  ← SDK ORQUESTADOR
Capa 1:  openid4vci, openid4vp, sdjwt, iso18013, statium, etc.    ← LIBRERÍAS DE PROTOCOLO
```

Las wallet-ui NO son simples demos — son apps modulares con 18-19 módulos, inyección de dependencias, CI/CD profesional y 22+ releases cada una. Sin embargo, toda la infraestructura de trust y los endpoints de issuer/verifier que usan son de test (`.eudiw.dev`).

### 8.2. Stack tecnológico comparado

| Aspecto | Android | iOS |
|---------|---------|-----|
| **Lenguaje** | Kotlin | Swift 6.2 |
| **UI Framework** | Jetpack Compose | SwiftUI |
| **Módulos** | 19 (core/features/infra/test) | 18 SPM modules |
| **DI** | Koin | Assembly module |
| **Min OS** | API 29 (Android 10) | iOS 17 |
| **Build System** | Gradle + Fastlane | Xcode + Fastlane |
| **Build Variants** | dev/demo × debug/release (4 variantes) | DEV/DEMO × DEBUG/RELEASE (4 variantes) |
| **Base de datos** | Room (migrado desde Realm, May 2025) | SwiftData (migrado desde Realm, Oct 2025) |
| **CI/CD** | GitHub Actions + SonarQube | Fastlane + TestFlight + SonarQube |
| **Concurrency** | Kotlin Coroutines + MutableStateFlow | Swift Actors + Observation framework |
| **Releases** | 22 releases (Ago 2024 – Feb 2026) | 22 releases (Ago 2024 – Feb 2026) |
| **Última release** | `2026.02.35-Demo` (Feb 2026) | `2026.02.35-Demo` (Feb 2026) |

### 8.3. Soporte de protocolos implementados

| Protocolo | Android | iOS | Versión Spec |
|-----------|---------|-----|--------------|
| **OID4VCI** (issuance) | Completo | Completo | v1.0 (Draft 15) |
| **OID4VP** (presentación remota) | Completo | Completo | v1.0 (Draft 23/24) |
| **ISO 18013-5** (proximidad BLE) | Completo | Completo | QR + NFC engagement, BLE transfer |
| **ISO 18013-5** (proximidad NFC datos) | No implementado | No implementado | — |
| **DCQL** | Soportado (parcial) | Soportado | `claim_sets` no soportados aún (Android) |
| **RQES / CSC API** | Completo | Completo | Local + remota |
| **HAIP** | Schemes soportados | Schemes soportados | Dic 2025 |
| **SD-JWT-VC** | Soportado | Soportado | Nested claims |
| **mso_mdoc** | Formato primario | Formato primario | Completo |
| **W3C credential formats** | No soportado | No soportado | — |
| **OpenID Federation** | No implementado | No implementado | — |
| **Digital Credential API** | No implementado | No implementado | — |
| **Wi-Fi Aware** | No implementado | No implementado | — |

### 8.4. Flujos de issuance implementados

Ambas plataformas implementan todos los flujos principales de OID4VCI v1.0:

| Flujo | Descripción | Desde release |
|-------|-------------|---------------|
| **Authorization Code Flow** | Wallet-initiated, usuario selecciona tipo de credencial | Inicial |
| **Pre-Authorization Code Flow** | Issuer-initiated con PIN opcional | v13 (Ago 2024) |
| **Deferred Issuance** | Credenciales que no se pueden emitir inmediatamente | v13 (Ago 2024) |
| **Batch Issuance** | Múltiples credenciales en una sesión | v28 (Jul 2025), reworked v30 |
| **Credential Offer via QR** | Escaneo de QR del issuer para triggear issuance | Inicial |
| **Credential Offer via Deep Link** | `openid-credential-offer://`, `haip-vci://` | Inicial |
| **Multiple Issuers** | Configurables por build variant, registro dinámico post-init | v32 (Nov 2025) |
| **PAR** (Pushed Authorization Requests) | Usado por defecto cuando soportado | Inicial |
| **DPoP** (Demonstration of Proof of Possession) | ES256, RFC 9449 con nonce handling automático | Inicial |
| **PKCE** | Proof Key for Code Exchange | Inicial |
| **VCI Metadata Localization** | Metadata del issuer en locale del usuario | v20 (Ene 2025) |
| **WIA/WUA** | Wallet Instance/Unit Attestation para client auth | v34 (Dic 2025) |

### 8.5. Flujos de presentación implementados

#### Presentación remota (OID4VP)

| Feature | Descripción |
|---------|-------------|
| **Same-device flow** | Verifier website triggers app via deep link |
| **Cross-device flow** | Via QR code |
| **Selección granular de atributos** | Usuario elige qué claims compartir |
| **Claims opcionales** | Flag `isOptional` respetado |
| **Múltiples deep link schemes** | `eudi-openid4vp://`, `mdoc-openid4vp://`, `openid4vp://`, `haip-vp://` |
| **Client ID schemes** | `pre-registered`, `x509_san_dns`, `x509_san_uri`, `x509_hash`, `redirect_uri`, `verifier_attestation` |
| **Response modes** | `direct_post`, `direct_post.jwt`, `query`, `fragment` (+ variantes `.jwt`) |
| **JAR** (Signed/Encrypted requests) | RFC 9101 |
| **Transaction data** | Soportado en iOS; no aún en Android |
| **Ordenación alfabética** | Claims y atributos ordenados alfabéticamente |

#### Presentación por proximidad (ISO 18013-5)

| Feature | Android | iOS |
|---------|---------|-----|
| **QR code device engagement** | Sí | Sí |
| **NFC device engagement** | Sí (opcional via feature flag) | No |
| **BLE data transfer** | Sí (peripheral + central) | Sí |
| **NFC data transfer** | No implementado | No implementado |
| **Reader certificate validation** | IACA trust chain | IACA trust chain |
| **Gestión permisos Bluetooth** | Sí | Sí |

### 8.6. Tipos de documento soportados

| Tipo | Namespace | Notas |
|------|-----------|-------|
| **PID** (Person Identification Data) | `eu.europa.ec.eudiw.pid.1` | Tipo core, scoped issuance |
| **mDL** (Mobile Driving License) | `org.iso.18013.5.1.mDL` | ISO 18013-5 compliant |
| **Photo ID Attestation** | — | Desde v14 (Sep 2024) |
| **PDA1** (Portable Document A1) | — | Solo iOS, categorización corregida Jul 2025 |
| **Tipos dinámicos** | Cualquiera | Via metadata del issuer (extensible sin modificar la app) |

### 8.7. Seguridad implementada

| Feature | Android | iOS |
|---------|---------|-----|
| **Hardware-backed keys** | Android Keystore + StrongBox (opcional) | Secure Enclave |
| **PIN authentication** | Almacenamiento cifrado (`CryptoController`) | Almacenamiento configurable |
| **Biometric auth** | Integración nativa | Face ID / Touch ID |
| **WIA / WUA** | Dic 2025 | Dic 2025 |
| **Key attestation** | Via `WalletAttestationsProvider` | PoP JWT (duración configurable, default 300s) |
| **DPoP** | ES256 | RFC 9449 con nonce automático |
| **Credential revocation** | WorkManager polling periódico | Checking periódico |
| **Response encryption** | Credential + authorization responses | Credential + authorization responses |
| **ProGuard/R8** | Habilitado (release) | N/A (Swift) |
| **OWASP MASVS** | Targeted | Targeted |
| **Security scanning** | Gitleaks en CI/CD | Gitleaks en CI/CD |
| **Device integrity** | Play Integrity API (via wallet-core) | App Attest |
| **Self-signed cert bypass** | Disponible (solo desarrollo) | Disponible (solo desarrollo) |

**Estados de revocación soportados:** Valid, Invalid, Suspended, ApplicationSpecific, Reserved. Clock skew tolerance: 5 minutos (configurable).

### 8.8. Ciclo de vida de credenciales

| Feature | Descripción |
|---------|-------------|
| **Transaction logs** | Historial completo con pantallas de lista y detalle (desde May 2025) |
| **Revocation checking** | Periódico, intervalo configurable via Wallet Core |
| **Document deletion** | Eliminación de documentos individuales |
| **Persistent storage** | Room (Android) / SwiftData (iOS), ambos migrados desde Realm |
| **Credential policies** | `OneTimeUse` (single presentation), `RotateUse` (multiple with usage tracking) |
| **Batch credentials** | Múltiples credenciales por documento |
| **Status checking** | Via WorkManager (Android) / background tasks (iOS) |

### 8.9. RQES (Firma Electrónica Cualificada Remota)

Ambas plataformas implementan el stack completo de RQES desde Dic 2024:

| Feature | Descripción |
|---------|-------------|
| **CSC protocol** | Cloud Signature Consortium via RQES SDK |
| **Firma local** | Documentos locales en el dispositivo (R5, Jul 2025) |
| **Firma remota** | Recuperación de documento por URL |
| **QTSP** | Lista configurable de Qualified Trust Service Providers |
| **TSA** | Time Stamp Authority (desde Jul 2025) |
| **Deep links** | `rqes://oauth/callback`, `eudi-rqes://` |
| **Hash algorithm** | SHA-256 |
| **Personalización** | Theming (`ThemeManager`/`ThemeProtocol`) + traducciones por locale |

### 8.10. Arquitectura modular detallada

#### Android — 19 módulos

| Capa | Módulos |
|------|---------|
| **Core** | `app`, `core-logic` (wallet SDK), `business-logic`, `assembly-logic` (DI) |
| **Features** | `startup-feature`, `dashboard-feature`, `issuance-feature`, `presentation-feature`, `proximity-feature`, `common-feature` |
| **Infraestructura** | `authentication-logic`, `storage-logic` (Room), `network-logic` (Ktor/OkHttp), `ui-logic` (Compose components), `resources-logic`, `analytics-logic` |
| **Testing** | `test-logic`, `test-feature`, `baseline-profile` |

#### iOS — 18 módulos SPM

| Capa | Módulos |
|------|---------|
| **Logic** | `logic-core` (wallet SDK), `logic-business`, `logic-storage` (SwiftData), `logic-authentication`, `logic-analytics`, `logic-api`, `logic-ui`, `logic-resources`, `logic-assembly` (DI + navigation) |
| **Features** | `feature-startup`, `feature-dashboard`, `feature-issuance`, `feature-presentation`, `feature-proximity`, `feature-login`, `feature-common` |
| **Testing** | `feature-test`, `logic-test` |

### 8.11. UI y personalización

| Aspecto | Android | iOS |
|---------|---------|-----|
| **Theming** | `ThemeManager.Builder()`: colors, images, shapes, fonts, dimensions | SwiftUI standard + `ThemeProtocol` (RQES) |
| **Dark mode** | Sí (via color roles) | Indicadores no documentados explícitamente |
| **Localization** | String resources por módulo, VCI metadata i18n, `Locale.forLanguageTag()` | Mecanismo reworked (Feb 2025), `uiCulture` config |
| **Accessibility** | UI automation tags como resource IDs (Feb 2026) | Accessibility locators (Feb 2026) |
| **Onboarding** | Welcome + PIN setup | Splash + router + PIN setup |
| **Dashboard** | Home tab + Documents tab | Documents con categorización y filtrado |
| **QR Scanner** | Dense QR fix (Sep 2024) | Validación con error messaging |
| **Settings** | App Settings screen (Jul 2025) | Settings screen (Jul 2025) |
| **WebView** | Para formularios de autenticación del issuer | Para formularios de autenticación del issuer |

### 8.12. Infraestructura de trust embebida

Las apps incluyen certificados IACA de desarrollo para validación de reader trust:

| Certificado | Propósito |
|-------------|-----------|
| `eudi_pid_issuer_ut` | PID issuer (utility/test) |
| `pidissuerca02_eu.pem` | EU-wide PID issuer CA |
| `pidissuerca02_cz.pem` | República Checa |
| `pidissuerca02_ee.pem` | Estonia |
| `pidissuerca02_lu.pem` | Luxemburgo |
| `pidissuerca02_nl.pem` | Países Bajos |
| `pidissuerca02_pt.pem` | Portugal |
| `dc4eu.pem` | Proyecto DC4EU |
| `r45_staging.pem` | R45 staging (Feb 2026, interop Japón) |

**Todos estos certificados son de desarrollo** — no son de CAs gubernamentales reales.

### 8.13. Demo services conectados

| Servicio | URL | Propósito |
|----------|-----|-----------|
| EUDI Issuer | `https://issuer.eudiw.dev/` | OID4VCI credential issuance |
| EUDI Verifier | `https://verifier.eudiw.dev` | OID4VP remote presentation |
| Wallet Provider | `https://wallet-provider.eudiw.dev` | WIA/WUA attestation |

### 8.14. Lo que es REAL vs DEMO

**Implementación real** (código production-grade):

- Todos los flujos de protocolo (OID4VCI, OID4VP, ISO 18013-5, RQES) usan las librerías EUDIW reales
- Operaciones criptográficas usan hardware real (Keystore / Secure Enclave)
- BLE proximity transfer es funcional
- PIN/biometría usan APIs reales del OS
- Deep linking y QR scanning son implementaciones nativas

**Infraestructura demo/test** (no producción):

- Todos los endpoints `.eudiw.dev` son servidores de test
- Certificados IACA embebidos son solo de desarrollo
- Cada release lleva el sufijo `-Demo`
- Bypass de certificados self-signed disponible (para desarrollo local)
- Configuración de seguridad descrita como "reducida" respecto a producción

### 8.15. Release history consolidada (ambas plataformas)

| Release | Fecha | Hitos principales |
|---------|-------|--------------------|
| v13 | Ago 2024 | Pre-auth code flow, deferred issuance, self-signed cert support |
| v14 | Sep 2024 | Photo ID attestation, dynamic issuance, persistent logging |
| v15 | Oct 2024 | iOS: Swift 6, iOS 18, min target iOS 16; Android: QR fixes |
| v17 | Nov 2024 | Swift 6 para todos los módulos, unit tests |
| v19 | Dic 2024 | **RQES integration**, RQESCore, configuration refactoring |
| v20 | Ene 2025 | **SD-JWT support**, VCI metadata localization, new storage module |
| v21 | Ene 2025 | **Major UI/UX rework** (breaking, requiere reinstalación) |
| v22 | Feb 2025 | Compose StateFlow migration (Android), localization rework (iOS) |
| v24 | Mar 2025 | **VP Draft 23**, nested SD-JWT claims, QR scan para PID activation |
| v25 | Abr 2025 | Deep link improvements, TestFlight external distribution |
| v26 | May 2025 | **Transaction logs**, revoked documents, **VP Draft 24**, SD-JWT ARF 1.8 |
| v27 | May 2025 | RQES updates, unit tests, biometry error descriptions |
| v28 | Jul 2025 | **Batch credentials**, **App Settings**, **PIN encryption**, min SDK 29 |
| v30 | Jul 2025 | Batch issuance rework, TSA URL for RQES |
| v31 | Oct 2025 | **OpenID4VP v1**, SwiftData (reemplaza Realm), Swift 6.2, NFC opcional |
| v32 | Nov 2025 | **OpenID4VCI v1**, **múltiples issuers**, `isOptional` claims |
| v33 | Nov 2025 | Dependency updates |
| v34 | Dic 2025 | **WIA/WUA support**, HAIP schemas, actors migration (iOS), ProGuard optimization |
| v35 | Feb 2026 | AGP 9, JP certificate chain (interop Japón), accessibility locators, HTTP logging by build type |

### 8.16. Gaps y limitaciones conocidas

| Limitación | Impacto |
|-----------|---------|
| **NFC data transfer** no implementado | Solo engagement via NFC; datos solo via BLE |
| **Wi-Fi Aware** no implementado | Sin transferencias de gran volumen |
| **W3C credential formats** no soportados | Solo mso_mdoc y SD-JWT-VC |
| **OpenID Federation** no implementado | No puede federar trust dinámicamente |
| **Digital Credential API** no implementado | Sin flujos browser-based |
| **DCQL `claim_sets`** no implementado (Android) | Queries complejas no posibles |
| **Multiple credentials in CredentialQuery** ignorados (Android) | — |
| **Transaction data** no soportado (Android) | Soportado solo en iOS |
| **`credential_identifier`** no soportado en credential requests (iOS) | — |
| **`Accept-Language` header** no implementado para metadata localization (iOS) | — |
| **v21 breaking change** | Requirió reinstalación completa (Ene 2025) |
| **No backward compatibility** | Solo la última versión recibe soporte |

### 8.17. Valoración para EUDIStack

Las wallet-ui de referencia son **implementaciones feature-complete** que cubren todos los flujos principales del ARF. Son significativamente más que demos — son apps modulares, bien arquitecturizadas, con CI/CD profesional.

**Sin embargo, para EUDIStack la recomendación sigue siendo construir un wrapper sobre `wallet-core`/`wallet-kit`** en lugar de fork de wallet-ui, por las siguientes razones:

1. **Control de UI/UX** — La wallet-ui tiene flujos de navegación fijos y onboarding built-in que requieren fork para cambiar
2. **Branding propio** — No hay API formal de white-labeling más allá de Material3 (Android) / SwiftUI standard (iOS)
3. **Integración backend** — EUDIStack usa Enterprise Backend propio (Java 25); la wallet-ui apunta a servicios `.eudiw.dev`
4. **Actualizaciones del SDK** — Un wrapper permite actualizar `wallet-core`/`wallet-kit` sin merge conflicts
5. **Coexistencia web + native** — La lógica de negocio se comparte via APIs, no via código

Lo que **sí se puede reutilizar** de la wallet-ui como referencia de implementación:

- Estructura modular (19 módulos) como template arquitectónico
- Configuración de `WalletCoreConfig` / `WalletKitConfig` para los SDKs
- Deep link schemes y manifest/plist configuration
- IACA certificate embedding y trust store setup
- RQES integration patterns (`ThemeManager`, `LocalizableKey`)
- CI/CD pipeline con Fastlane + SonarQube + Gitleaks

---

## 9. Conclusiones y recomendaciones

### 9.1. Conclusión general

El EUDIW Reference Implementation es un **ecosistema funcional pero no production-ready** que cubre los principales flujos de identidad digital. Las librerías de **protocolo** (OID4VCI, OID4VP, SD-JWT) son las más maduras; la **infraestructura de trust y revocación** es la menos madura.

### 9.2. Impacto en EUDIStack

| Decisión | Recomendación | Justificación |
|----------|--------------|---------------|
| **App Nativa** | **Sí, iniciar el desarrollo** | Obligatoria para PIDs, proximity, device integrity, certificación ARF |
| **Formato dc+sd-jwt** | **Priorizar migración** | ARF Mandatory; librerías maduras en ambas plataformas |
| **DCQL** | **Implementar en Verifier** | Reemplaza presentation_definition; soportado en openid4vp-kt/swift |
| **Trust infrastructure** | **Desarrollar independientemente** | Los componentes EUDIW son demasiado inmaduros para producción |
| **Web Wallet** | **Mantener para EUBW** | Suficiente para credenciales empresariales (LEARCredential) |
| **Proximity (BLE)** | **Roadmap v2.x** | Requiere app nativa; librerías funcionales pero tempranas |
| **RQES** | **Evaluar para LICENSED tier** | Stack coherente (core + UI) en ambas plataformas |

### 9.3. Cadena de dependencias recomendada para App Nativa

```
EUDIStack Native Wallet (nuestra app)
│
├── Android:
│   └── eudi-lib-android-wallet-core (SDK)
│       ├── eudi-lib-android-wallet-document-manager
│       ├── eudi-lib-android-iso18013-data-transfer
│       ├── eudi-lib-jvm-openid4vci-kt
│       ├── eudi-lib-jvm-openid4vp-kt
│       │   ├── eudi-lib-jvm-presentation-exchange-kt
│       │   └── eudi-lib-jvm-sdjwt-kt
│       └── eudi-lib-kmp-statium
│
├── iOS:
│   └── eudi-lib-ios-wallet-kit (SDK)
│       ├── eudi-lib-ios-wallet-storage
│       ├── eudi-lib-ios-iso18013-data-transfer
│       │   ├── eudi-lib-ios-iso18013-data-model
│       │   └── eudi-lib-ios-iso18013-security
│       ├── eudi-lib-ios-openid4vci-swift
│       ├── eudi-lib-ios-openid4vp-swift
│       │   └── eudi-lib-ios-presentation-exchange-swift
│       ├── eudi-lib-sdjwt-swift
│       └── eudi-lib-ios-statium-swift
│
└── Enterprise Backend (existente):
    ├── Credential Issuer CORE (Java 25)
    ├── Verifier CORE (Java 25)
    ├── Trust Framework (ETSI TS 119 602)
    └── Backup / Recovery / Audit
```

### 9.4. Riesgos identificados

| Riesgo | Severidad | Mitigación |
|--------|-----------|------------|
| Todas las librerías son 0.x con breaking changes frecuentes | **Alta** | Pinear versiones; seguir changelog; tests de integración |
| Trust infrastructure inmadura (14-35 commits) | **Alta** | Desarrollar implementación propia del SPI `TrustFrameworkProvider` |
| Dependencia de `multipaz` (OpenWallet Foundation) | **Media** | Librería activa con respaldo institucional |
| NFC data transfer no soportado | **Media** | BLE cubre la mayoría de casos; NFC en roadmap EUDIW |
| No hay garantía de backwards compatibility | **Alta** | Wrapper pattern aísla cambios de las EUDIW libs |
| `presentation-exchange` posiblemente deprecada por DCQL | **Baja** | DCQL es el camino forward; PE es fallback |

### 9.5. Próximos pasos sugeridos

1. **Crear PoC de integración** — App nativa mínima (Android) usando `eudi-lib-android-wallet-core` + Enterprise Backend existente
2. **Migrar a dc+sd-jwt** — Usar `eudi-lib-jvm-sdjwt-kt` como referencia para el Issuer CORE
3. **Implementar DCQL** — En el Verifier CORE, usando `eudi-lib-jvm-openid4vp-kt` como referencia
4. **Monitorizar roadmap EUDIW** — `eudi-wallet-reference-implementation-roadmap` para anticipar cambios
5. **Evaluar RQES** — Para el tier LICENSED, usando `eudi-lib-android-rqes-core` + `rqes-ui`

---

## Referencias

- [EUDIW Architecture and Reference Framework (ARF v2.8.0)](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework)
- [EUDIW DevHub](https://eu-digital-identity-wallet.github.io/)
- [EUDIW Reference Implementation Roadmap](https://github.com/eu-digital-identity-wallet/eudi-wallet-reference-implementation-roadmap)
- [EUDIW Standards and Technical Specifications](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications)
- [EUDIStack Wallet Holder DT v1.1](../dt/holder-wallet-v1.1.md)
- [EUDIStack Credential Issuer DT v1.1](../dt/credential-issuer-v1.1.md)
- [EUDIStack Verifier DT v1.1](../dt/verifier-v1.1.md)
