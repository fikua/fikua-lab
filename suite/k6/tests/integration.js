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
      "has 4 presets": () => body.length === 4,
      "contains Plain Pre-Auth Issuer": () =>
        body.some((p) => p.name === "Plain Pre-Auth Issuer"),
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
        const key = Object.keys(configs)[0];
        return configs[key].format === "dc+sd-jwt";
      },
      "has proof_types_supported": () => {
        const configs = meta.credential_configurations_supported;
        const key = Object.keys(configs)[0];
        return configs[key].proof_types_supported !== undefined;
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
      "returns c_nonce_expires_in": (r) =>
        r.json().c_nonce_expires_in !== undefined,
    });
  });

  // ---------------------------------------------------------------------------
  // 9. Credential Offer
  // ---------------------------------------------------------------------------
  group("Credential Offer", () => {
    const res = http.get(`${BASE_URL}/oid4vci/v1/credential-offer`);
    const offer = res.json();
    check(res, {
      "GET /credential-offer → 200": (r) => r.status === 200,
      "has credential_issuer": () => offer.credential_issuer !== undefined,
      "has credential_configuration_ids": () =>
        offer.credential_configuration_ids !== undefined,
    });
  });

  // ---------------------------------------------------------------------------
  // 10. Credential Offer by Reference
  // ---------------------------------------------------------------------------
  group("Credential Offer by Reference", () => {
    const res = http.get(
      `${BASE_URL}/oid4vci/v1/credential-offer?mode=by_reference`
    );
    check(res, {
      "GET /credential-offer?mode=by_reference → 200": (r) =>
        r.status === 200,
      "returns credential_offer_uri": (r) =>
        r.json().credential_offer_uri !== undefined,
    });
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
}
