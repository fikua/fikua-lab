/**
 * Fikua Lab — Integration Tests (k6)
 *
 * Validates all API endpoints against a running Docker deployment.
 *
 * Usage:
 *   k6 run suite/k6/tests/integration.js
 *   k6 run suite/k6/tests/integration.js --env BASE_URL=http://other:8080
 */

import http from "k6/http";
import { check, group } from "k6";
import { textSummary } from "https://jslib.k6.io/k6-summary/0.1.0/index.js";

const BASE_URL = __ENV.BASE_URL || "http://localhost:8080";

export const options = {
  // Single iteration — functional test, not load test
  vus: 1,
  iterations: 1,
  thresholds: {
    checks: ["rate==1.0"], // all checks must pass
  },
};

// ---------------------------------------------------------------------------
// 1. Health
// ---------------------------------------------------------------------------
export default function () {
  group("Health", () => {
    const res = http.get(`${BASE_URL}/health`);
    check(res, {
      "GET /health → 200": (r) => r.status === 200,
      "status is up": (r) => r.json().status === "up",
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Admin — Presets
  // ---------------------------------------------------------------------------
  group("Admin — Presets", () => {
    const res = http.get(`${BASE_URL}/admin/presets`);
    const body = res.json();
    check(res, {
      "GET /admin/presets → 200": (r) => r.status === 200,
      "returns array": () => Array.isArray(body),
      "has at least 1 preset": () => body.length >= 1,
      "contains Plain Issuer": () =>
        body.some((p) => p.name === "Plain Issuer"),
      "contains HAIP Issuer": () =>
        body.some((p) => p.name === "HAIP Issuer"),
      "contains Plain Verifier": () =>
        body.some((p) => p.name === "Plain Verifier"),
      "contains HAIP Verifier": () =>
        body.some((p) => p.name === "HAIP Verifier"),
    });
  });

  // ---------------------------------------------------------------------------
  // 3. Admin — Profile CRUD
  // ---------------------------------------------------------------------------
  let haipProfileId = null;

  group("Admin — Profile CRUD", () => {
    // Create pre-auth profile
    const preAuthBody = JSON.stringify({
      name: "IT Pre-Auth",
      role: "issuer",
      config: {
        grantType: "pre_authorization_code",
        credentialFormat: "sd_jwt_vc",
        vciProfile: "plain",
        credentialOffer: "by_reference",
        issuanceMode: "immediate",
      },
    });
    const createRes = http.post(`${BASE_URL}/admin/profiles`, preAuthBody, {
      headers: { "Content-Type": "application/json" },
    });
    check(createRes, {
      "POST /admin/profiles → 201": (r) => r.status === 201,
      "returns profile with id": (r) => r.json().id !== undefined,
    });

    // Create HAIP profile
    const haipBody = JSON.stringify({
      name: "IT HAIP",
      role: "issuer",
      config: {
        grantType: "authorization_code",
        senderConstraining: "dpop",
        clientAuth: "client_attestation",
        credentialFormat: "sd_jwt_vc",
        vciProfile: "haip",
        credentialOffer: "by_reference",
        issuanceMode: "immediate",
        credentialResponseEnc: "encrypted",
        par: true,
        pkce: "S256",
      },
    });
    const haipRes = http.post(`${BASE_URL}/admin/profiles`, haipBody, {
      headers: { "Content-Type": "application/json" },
    });
    check(haipRes, {
      "POST /admin/profiles (HAIP) → 201": (r) => r.status === 201,
    });
    haipProfileId = haipRes.json().id;

    // List profiles
    const listRes = http.get(`${BASE_URL}/admin/profiles`);
    check(listRes, {
      "GET /admin/profiles → 200": (r) => r.status === 200,
      "profiles is array": (r) => Array.isArray(r.json()),
      "at least 2 profiles": (r) => r.json().length >= 2,
    });
  });

  // ---------------------------------------------------------------------------
  // 4. Profile Activation + HAIP Metadata
  // ---------------------------------------------------------------------------
  group("Profile Activation — HAIP", () => {
    check(null, {
      "HAIP profile was created": () => haipProfileId !== null,
    });
    if (!haipProfileId) return;

    const activateRes = http.put(
      `${BASE_URL}/admin/profiles/${haipProfileId}/activate`
    );
    check(activateRes, {
      "PUT /admin/profiles/{id}/activate → 200": (r) => r.status === 200,
      "status is activated": (r) => r.json().status === "activated",
    });
  });

  // ---------------------------------------------------------------------------
  // 5. Credential Issuer Metadata
  // ---------------------------------------------------------------------------
  group("Credential Issuer Metadata", () => {
    const res = http.get(`${BASE_URL}/.well-known/openid-credential-issuer`);
    const meta = res.json();
    check(res, {
      "GET /.well-known/openid-credential-issuer → 200": (r) =>
        r.status === 200,
      "has credential_issuer": () => meta.credential_issuer !== undefined,
      "has credential_endpoint": () => meta.credential_endpoint !== undefined,
      "has nonce_endpoint": () => meta.nonce_endpoint !== undefined,
      "has notification_endpoint": () =>
        meta.notification_endpoint !== undefined,
      "has credential_configurations_supported": () =>
        meta.credential_configurations_supported !== undefined,
      "format is dc+sd-jwt": () => {
        const configs = meta.credential_configurations_supported;
        return configs["eu.europa.ec.eudi.pid.1"] !== undefined &&
          configs["eu.europa.ec.eudi.pid.1"].format === "dc+sd-jwt";
      },
      "has proof_types_supported": () => {
        const configs = meta.credential_configurations_supported;
        return configs["eu.europa.ec.eudi.pid.1"] !== undefined &&
          configs["eu.europa.ec.eudi.pid.1"].proof_types_supported !== undefined;
      },
    });
  });

  // ---------------------------------------------------------------------------
  // 6. Authorization Server Metadata (HAIP active)
  // ---------------------------------------------------------------------------
  group("Auth Server Metadata — HAIP", () => {
    const res = http.get(
      `${BASE_URL}/.well-known/oauth-authorization-server`
    );
    const meta = res.json();
    check(res, {
      "GET /.well-known/oauth-authorization-server → 200": (r) =>
        r.status === 200,
      "has issuer": () => meta.issuer !== undefined,
      "has token_endpoint": () => meta.token_endpoint !== undefined,
      "has authorization_endpoint": () =>
        meta.authorization_endpoint !== undefined,
      "has pushed_authorization_request_endpoint": () =>
        meta.pushed_authorization_request_endpoint !== undefined,
      "has dpop_signing_alg_values_supported": () =>
        meta.dpop_signing_alg_values_supported !== undefined,
      "has code_challenge_methods_supported": () =>
        meta.code_challenge_methods_supported !== undefined,
    });
  });

  // ---------------------------------------------------------------------------
  // 7. JWKS
  // ---------------------------------------------------------------------------
  group("JWKS", () => {
    const res = http.get(`${BASE_URL}/oid4vci/v1/jwks`);
    check(res, {
      "GET /oid4vci/v1/jwks → 200": (r) => r.status === 200,
      "contains keys": (r) => r.body.includes("keys"),
    });
  });

  // ---------------------------------------------------------------------------
  // 8. Nonce Endpoint
  // ---------------------------------------------------------------------------
  group("Nonce Endpoint", () => {
    const res = http.post(`${BASE_URL}/oid4vci/v1/nonce`, null);
    check(res, {
      "POST /oid4vci/v1/nonce → 200": (r) => r.status === 200,
      "returns c_nonce": (r) => r.json().c_nonce !== undefined,
    });
  });

  // ---------------------------------------------------------------------------
  // 9. Credential Offer (deprecated GET returns 400)
  // ---------------------------------------------------------------------------
  group("Credential Offer — deprecated GET", () => {
    const res = http.get(`${BASE_URL}/oid4vci/v1/credential-offer`);
    check(res, {
      "GET /credential-offer → 400 (deprecated)": (r) => r.status === 400,
      "error suggests POST /issuance": (r) =>
        r.body.includes("issuance"),
    });
  });

  // ---------------------------------------------------------------------------
  // 10. Credential Offer by Reference (via POST /issuance)
  // ---------------------------------------------------------------------------
  group("Credential Offer by Reference", () => {
    const issuanceBody = JSON.stringify({
      credential_type: "eu.europa.ec.eudi.pid.1",
      credential_data: { given_name: "Offer", family_name: "Test" },
    });
    const res = http.post(`${BASE_URL}/oid4vci/v1/issuance`, issuanceBody, {
      headers: { "Content-Type": "application/json" },
    });
    const data = res.json();
    check(res, {
      "POST /issuance → 200": (r) => r.status === 200,
      "returns credential_offer_uri": () =>
        data.credential_offer_uri !== undefined,
    });

    // Resolve the offer URI
    if (data.credential_offer_uri) {
      const offerRes = http.get(
        data.credential_offer_uri.replace("https://issuer.lab.fikua.com", BASE_URL)
      );
      check(offerRes, {
        "resolved offer has credential_configuration_ids": (r) =>
          r.json().credential_configuration_ids !== undefined,
      });
    }
  });

  // ---------------------------------------------------------------------------
  // 11. Switch to Pre-Auth and verify metadata
  // ---------------------------------------------------------------------------
  group("Pre-Auth Profile Metadata", () => {
    // Create and activate a pre-auth profile
    const body = JSON.stringify({
      name: "IT Plain PreAuth",
      role: "issuer",
      config: {
        grantType: "pre_authorization_code",
        credentialFormat: "sd_jwt_vc",
        vciProfile: "plain",
        credentialOffer: "by_reference",
        issuanceMode: "immediate",
      },
    });
    const createRes = http.post(`${BASE_URL}/admin/profiles`, body, {
      headers: { "Content-Type": "application/json" },
    });
    const profileId = createRes.json().id;

    if (profileId) {
      http.put(`${BASE_URL}/admin/profiles/${profileId}/activate`);

      const meta = http
        .get(`${BASE_URL}/.well-known/oauth-authorization-server`)
        .json();
      check(meta, {
        "pre-auth: has pre-authorized_code grant type": (m) =>
          JSON.stringify(m).includes("pre-authorized_code"),
        "pre-auth: has token_endpoint": (m) =>
          m.token_endpoint !== undefined,
      });
    }
  });

  // ---------------------------------------------------------------------------
  // 12. Issuance Trigger — by_reference (pre-auth profile active from group 11)
  // ---------------------------------------------------------------------------
  group("Issuance Trigger — by_reference", () => {
    const body = JSON.stringify({
      credential_type: "eu.europa.ec.eudi.pid.1",
      credential_data: {
        given_name: "Test",
        family_name: "User",
        birth_date: "1990-01-01",
      },
      source_type: "x509_cert",
      source_ref: "CN=Test User, O=Fikua Lab",
    });
    const res = http.post(`${BASE_URL}/oid4vci/v1/issuance`, body, {
      headers: { "Content-Type": "application/json" },
    });
    const data = res.json();
    check(res, {
      "POST /issuance (by_ref) → 200": (r) => r.status === 200,
      "returns credential_offer_uri": () =>
        data.credential_offer_uri !== undefined,
      "returns issuance_id": () => data.issuance_id !== undefined,
    });

    // Resolve the offer URI
    if (data.credential_offer_uri) {
      const offerRes = http.get(
        data.credential_offer_uri.replace(
          "https://issuer.lab.fikua.com",
          BASE_URL
        )
      );
      check(offerRes, {
        "resolved issuance offer has credential_configuration_ids": (r) =>
          r.json().credential_configuration_ids !== undefined,
        "resolved issuance offer has pre-authorized_code": (r) =>
          JSON.stringify(r.json()).includes("pre-authorized_code"),
      });
    }
  });

  // ---------------------------------------------------------------------------
  // 13. Issuance Trigger — by_value (switch to by_value profile)
  // ---------------------------------------------------------------------------
  group("Issuance Trigger — by_value", () => {
    // Create and activate a by_value pre-auth profile
    const profileBody = JSON.stringify({
      name: "IT PreAuth ByValue",
      role: "issuer",
      config: {
        grantType: "pre_authorization_code",
        credentialFormat: "sd_jwt_vc",
        vciProfile: "plain",
        credentialOffer: "by_value",
        issuanceMode: "immediate",
      },
    });
    const profileRes = http.post(
      `${BASE_URL}/admin/profiles`,
      profileBody,
      { headers: { "Content-Type": "application/json" } }
    );
    const byValueProfileId = profileRes.json().id;

    if (byValueProfileId) {
      http.put(`${BASE_URL}/admin/profiles/${byValueProfileId}/activate`);

      // Test POST /issuance with by_value
      const issuanceBody = JSON.stringify({
        credential_type: "eu.europa.ec.eudi.pid.1",
        credential_data: {
          given_name: "Maria",
          family_name: "Garcia",
        },
        source_type: "manual",
      });
      const issuanceRes = http.post(
        `${BASE_URL}/oid4vci/v1/issuance`,
        issuanceBody,
        { headers: { "Content-Type": "application/json" } }
      );
      const issuanceData = issuanceRes.json();
      check(issuanceRes, {
        "POST /issuance (by_value) → 200": (r) => r.status === 200,
        "returns credential_offer object": () =>
          issuanceData.credential_offer !== undefined,
        "credential_offer has credential_configuration_ids": () =>
          issuanceData.credential_offer.credential_configuration_ids !==
          undefined,
        "returns issuance_id": () => issuanceData.issuance_id !== undefined,
      });
    }
  });
}

export function handleSummary(data) {
  const out = { stdout: textSummary(data, { indent: " ", enableColors: false }) };
  const file = __ENV.SUMMARY_FILE;
  if (file) out[file] = JSON.stringify(data);
  return out;
}
