# OIDF Conformance Test Configurations

**Created:** 2026-02-17
**Source:** https://www.certification.openid.net/

This document catalogs all 12 OIDF conformance test plans relevant to Fikua Lab, with their configurable parameters and how each maps to a profile preset.

## Overview

| #  | Test Plan                                  | Role     | Spec Version   | Status      |
|----|-------------------------------------------|----------|----------------|-------------|
| 1  | OID4VCI Issuer Final/HAIP                 | Issuer   | 1.0 Final/HAIP | Alpha       |
| 2  | OID4VCI Issuer Final                      | Issuer   | 1.0 Final      | Alpha       |
| 3  | OID4VCI Wallet Final/HAIP                 | Wallet   | 1.0 Final/HAIP | Alpha       |
| 4  | OID4VCI Wallet Final                      | Wallet   | 1.0 Final      | Alpha       |
| 5  | OID4VP Verifier Final/HAIP               | Verifier | 1.0 Final/HAIP | Alpha       |
| 6  | OID4VP Verifier Final                     | Verifier | 1.0 Final      | Alpha       |
| 7  | OID4VP Verifier ID2                       | Verifier | ID2            | Alpha       |
| 8  | OID4VP Verifier ID3 (draft 24)           | Verifier | ID3            | Alpha       |
| 9  | OID4VP Wallet Final/HAIP                 | Wallet   | 1.0 Final/HAIP | Alpha       |
| 10 | OID4VP Wallet Final                       | Wallet   | 1.0 Final      | Alpha       |
| 11 | OID4VP Wallet ID2                         | Wallet   | ID2            | Alpha       |
| 12 | OID4VP Wallet ID3 (draft 24)             | Wallet   | ID3            | Alpha       |

## Test #1 — OID4VCI Issuer Final/HAIP

**Suite acts as:** Wallet testing our Issuer

| Parameter                      | Options                              |
|--------------------------------|--------------------------------------|
| Authorization Code Flow Variant | `wallet_initiated`, `issuer_initiated` |
| Credential Format              | `sd_jwt_vc`, `mdoc`                  |

**HAIP fixes:** authorization_code grant, DPoP, PAR, PKCE S256, wallet attestation. These are not configurable — they are mandatory.

**Fikua preset:** HAIP Issuer (sd_jwt_vc + issuer_initiated)

## Test #2 — OID4VCI Issuer Final

**Suite acts as:** Wallet testing our Issuer

| Parameter                      | Options                                        |
|--------------------------------|------------------------------------------------|
| Sender Constraining            | `mtls`, `dpop`                                 |
| Client Authentication Type     | `mtls`, `private_key_jwt`, `client_attestation` |
| Authorization Code Flow Variant | `wallet_initiated`, `issuer_initiated`          |
| Credential Format              | `sd_jwt_vc`, `mdoc`                            |
| Authorization Request Type     | `simple`, `rar`                                |
| VCI Profile                    | `haip`                                         |
| Request Method                 | `unsigned`, `signed_non_repudiation`           |
| Grant Type                     | `authorization_code`, `pre_authorization_code` |
| Credential Response Encryption | `plain`, `encrypted`                           |

**Fikua preset:** Plain Issuer (pre_authorization_code / authorization_code + sd_jwt_vc + simple + unsigned + plain)

**Important constraints:**
- When grant_type = `pre_authorization_code`: sender constraining and client authentication do not apply
- When grant_type = `authorization_code`: sender constraining and client authentication are required
- VCI Profile `haip` forces same constraints as Test #1

## Test #3 — OID4VCI Wallet Final/HAIP

**Suite acts as:** Issuer testing our Wallet

| Parameter                      | Options                                                      |
|--------------------------------|--------------------------------------------------------------|
| Authorization Code Flow Variant | `wallet_initiated`, `issuer_initiated`, `issuer_initiated_dc_api` |
| Credential Format              | `sd_jwt_vc`, `mdoc`                                          |
| Credential Offer Variant       | `by_value`, `by_reference`                                   |

**HAIP fixes:** Same as Test #1 — DPoP, PAR, PKCE S256, wallet attestation mandatory.

## Test #4 — OID4VCI Wallet Final

**Suite acts as:** Issuer testing our Wallet

| Parameter                      | Options                                                      |
|--------------------------------|--------------------------------------------------------------|
| Sender Constraining            | `mtls`, `dpop`                                               |
| Client Authentication Type     | `mtls`, `private_key_jwt`, `client_attestation`              |
| Authorization Code Flow Variant | `wallet_initiated`, `issuer_initiated`, `issuer_initiated_dc_api` |
| Credential Format              | `sd_jwt_vc`, `mdoc`                                          |
| Authorization Request Type     | `simple`, `rar`                                              |
| Credential Issuance Mode       | `immediate`, `deferred`                                      |
| VCI Profile                    | `haip`                                                       |
| Request Method                 | `unsigned`, `signed_non_repudiation`                         |
| Grant Type                     | `authorization_code`, `pre_authorization_code`               |
| Credential Offer Variant       | `by_value`, `by_reference`                                   |
| Credential Response Encryption | `plain`, `encrypted`                                         |

## Test #5 — OID4VP Verifier Final/HAIP

**Suite acts as:** Fake Wallet waiting for our Verifier's requests

| Parameter          | Options                            |
|--------------------|------------------------------------|
| Credential Format  | `sd_jwt_vc`, `mdoc`                |
| Response Mode      | `direct_post`, `direct_post.jwt`   |

**HAIP fixes:** x509_hash client_id prefix, JAR (signed request_uri), DCQL, response encryption mandatory.

**Fikua preset:** HAIP Verifier (sd_jwt_vc + direct_post.jwt)

## Test #6 — OID4VP Verifier Final

**Suite acts as:** Fake Wallet waiting for our Verifier's requests

| Parameter          | Options                            |
|--------------------|------------------------------------|
| Credential Format  | `sd_jwt_vc`, `mdoc`                |
| Client ID Prefix   | `x509_san_dns`, `x509_hash`       |
| Request Method     | `request_uri_signed`               |
| VP Profile         | `plain_vp`, `haip`                 |
| Response Mode      | `direct_post`, `direct_post.jwt`   |

**Fikua preset:** Plain Verifier (sd_jwt_vc + x509_san_dns + direct_post + plain_vp)

## Test #7 — OID4VP Verifier ID2

**Suite acts as:** Fake Wallet (older spec version)

| Parameter          | Options                            |
|--------------------|------------------------------------|
| Credential Format  | `sd_jwt_vc`, `iso_mdl`             |
| Client ID Scheme   | `x509_san_dns`                     |
| Request Method     | `request_uri_signed`               |
| Response Mode      | `direct_post`, `direct_post.jwt`   |

**Note:** Uses `client_id_scheme` (ID2 terminology) instead of `client_id_prefix` (1.0 Final).

## Test #8 — OID4VP Verifier ID3 (draft 24)

**Suite acts as:** Fake Wallet (draft 24)

| Parameter          | Options                                    |
|--------------------|--------------------------------------------|
| Credential Format  | `sd_jwt_vc`, `iso_mdl`                     |
| Client ID Scheme   | `x509_san_dns`                             |
| Request Method     | `request_uri_signed`                       |
| Query Language     | `presentation_exchange`, `dcql`            |
| Response Mode      | `direct_post`, `direct_post.jwt`           |

**Note:** First version to support DCQL alongside Presentation Exchange.

## Test #9 — OID4VP Wallet Final/HAIP

**Suite acts as:** Verifier testing our Wallet

| Parameter          | Options                                            |
|--------------------|----------------------------------------------------|
| Credential Format  | `sd_jwt_vc`, `iso_mdl`                             |
| Request Method     | `request_uri_signed`, `request_uri_unsigned`       |
| Response Mode      | `direct_post.jwt`, `dc_api.jwt`                    |

**HAIP fixes:** x509_hash accepted, DCQL, response encryption.

## Test #10 — OID4VP Wallet Final

**Suite acts as:** Verifier testing our Wallet

| Parameter          | Options                                                                                    |
|--------------------|--------------------------------------------------------------------------------------------|
| Credential Format  | `sd_jwt_vc`, `iso_mdl`                                                                     |
| Client ID Prefix   | `decentralized_identifier`, `pre_registered`, `redirect_uri`, `web_origin`, `x509_san_dns`, `x509_hash` |
| Request Method     | `request_uri_signed`, `request_uri_unsigned`                                               |
| VP Profile         | `plain_vp`, `haip`                                                                         |
| Response Mode      | `direct_post`, `direct_post.jwt`, `dc_api`, `dc_api.jwt`                                  |

**Note:** `decentralized_identifier` prefix exists in the test but Fikua Lab does NOT implement DIDs. Skip this option.

## Test #11 — OID4VP Wallet ID2

**Suite acts as:** Verifier testing our Wallet (ID2 spec)

| Parameter          | Options                                                  |
|--------------------|----------------------------------------------------------|
| Credential Format  | `sd_jwt_vc`, `iso_mdl`                                   |
| Client ID Scheme   | `did`, `pre_registered`, `redirect_uri`, `x509_san_dns`  |
| Request Method     | `request_uri_signed`, `request_uri_unsigned`             |
| Response Mode      | `direct_post`, `direct_post.jwt`, `dc_api`, `dc_api.jwt` |

**Note:** `did` scheme exists but Fikua Lab skips DID support.

## Test #12 — OID4VP Wallet ID3 (draft 24)

**Suite acts as:** Verifier testing our Wallet (ID3/draft 24)

| Parameter          | Options                                                                |
|--------------------|------------------------------------------------------------------------|
| Credential Format  | `sd_jwt_vc`, `iso_mdl`                                                 |
| Client ID Scheme   | `did`, `pre_registered`, `redirect_uri`, `web_origin`, `x509_san_dns` |
| Request Method     | `request_uri_signed`, `request_uri_unsigned`                           |
| Query Language     | `presentation_exchange`, `dcql`                                        |
| Response Mode      | `direct_post`, `direct_post.jwt`, `dc_api`, `dc_api.jwt`              |

## Parameter cross-reference

### Which parameters apply to which role

| Parameter                  | Issuer | Wallet (VCI) | Verifier | Wallet (VP) |
|----------------------------|--------|--------------|----------|-------------|
| Sender Constraining        | x      | x            |          |             |
| Client Authentication      | x      | x            |          |             |
| Auth Code Flow Variant     | x      | x            |          |             |
| Credential Format          | x      | x            | x        | x           |
| Auth Request Type          | x      | x            |          |             |
| VCI Profile                | x      | x            |          |             |
| Request Method (VCI)       | x      | x            |          |             |
| Grant Type                 | x      | x            |          |             |
| Credential Response Enc    | x      | x            |          |             |
| Credential Offer Variant   |        | x            |          |             |
| Credential Issuance Mode   |        | x            |          |             |
| Client ID Prefix/Scheme    |        |              | x        | x           |
| Request Method (VP)        |        |              | x        | x           |
| VP Profile                 |        |              | x        | x           |
| Response Mode              |        |              | x        | x           |
| Query Language             |        |              | x        | x           |

### Grant type constraints

| Grant Type                 | DPoP    | Client Auth | PAR     | PKCE    |
|----------------------------|---------|-------------|---------|---------|
| `pre_authorization_code`   | N/A     | N/A         | N/A     | N/A     |
| `authorization_code`       | Required if configured | Required | Optional (HAIP: required) | Recommended (HAIP: required S256) |

### HAIP mandatory settings

| Parameter                  | HAIP Value                    |
|----------------------------|-------------------------------|
| Grant Type                 | `authorization_code`          |
| Sender Constraining        | `dpop`                        |
| Client Authentication      | `client_attestation`          |
| PKCE                       | `S256`                        |
| PAR                        | Required                      |
| Client ID Prefix (VP)      | `x509_hash`                   |
| Request Method (VP)        | `request_uri_signed`          |
| Response Mode (VP)         | `direct_post.jwt`             |
| Query Language (VP)        | `dcql`                        |
| Response Encryption Alg    | `ECDH-ES` (P-256)            |
| Response Encryption Enc    | `A128GCM` or `A256GCM`       |
| Signing Algorithm          | `ES256` minimum               |

## Priority order for implementation

1. **Test #2** — OID4VCI Issuer Final (pre_authorization_code + sd_jwt_vc) — simplest path
2. **Test #1** — OID4VCI Issuer Final/HAIP (authorization_code + HAIP) — EU requirement
3. **Test #6** — OID4VP Verifier Final (sd_jwt_vc + x509_san_dns + direct_post) — verifier basics
4. **Test #5** — OID4VP Verifier Final/HAIP — EU requirement
5. **Test #4** — OID4VCI Wallet Final — wallet issuance flow
6. **Test #10** — OID4VP Wallet Final — wallet presentation flow
7. Tests #3, #7, #8, #9, #11, #12 — remaining coverage
