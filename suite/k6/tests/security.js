/**
 * Fikua Lab — Security & Error Path Tests (k6)
 *
 * Validates that the OID4VCI endpoints correctly reject invalid, malformed,
 * and abusive requests with the proper error codes per spec.
 *
 * Uses a real pre-auth flow as baseline, then tests each rejection path.
 *
 * Usage:
 *   k6 run suite/k6/tests/security.js
 *   k6 run suite/k6/tests/security.js --env BASE_URL=http://other:8080
 */

import http from "k6/http";
import { check, group } from "k6";
import encoding from "k6/encoding";

const BASE_URL = __ENV.BASE_URL || "http://localhost:8080";

export const options = {
  vus: 1,
  iterations: 1,
  thresholds: {
    checks: ["rate==1.0"],
  },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function toBase64url(buf) {
  return encoding
    .b64encode(new Uint8Array(buf), "rawstd")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function strToArrayBuffer(str) {
  const buf = new ArrayBuffer(str.length);
  const view = new Uint8Array(buf);
  for (let i = 0; i < str.length; i++) {
    view[i] = str.charCodeAt(i);
  }
  return buf;
}

async function generateWalletKey() {
  return await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
}

async function signJwtProof(keyPair, audience, nonce, overrides = {}) {
  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);

  const header = JSON.stringify({
    typ: overrides.typ !== undefined ? overrides.typ : "openid4vci-proof+jwt",
    alg: overrides.alg !== undefined ? overrides.alg : "ES256",
    jwk: overrides.jwk !== undefined ? overrides.jwk : {
      kty: publicJwk.kty,
      crv: publicJwk.crv,
      x: publicJwk.x,
      y: publicJwk.y,
    },
  });

  const payload = JSON.stringify({
    aud: overrides.aud !== undefined ? overrides.aud : audience,
    nonce: overrides.nonce !== undefined ? overrides.nonce : nonce,
    iat: overrides.iat !== undefined ? overrides.iat : Math.floor(Date.now() / 1000),
  });

  const headerB64 = toBase64url(strToArrayBuffer(header));
  const payloadB64 = toBase64url(strToArrayBuffer(payload));
  const signingInput = `${headerB64}.${payloadB64}`;

  if (overrides.badSignature) {
    return `${signingInput}.AAAA_invalid_signature_AAAA`;
  }

  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    keyPair.privateKey,
    strToArrayBuffer(signingInput)
  );

  return `${signingInput}.${toBase64url(signature)}`;
}

function jsonPost(url, body, headers = {}) {
  return http.post(url, JSON.stringify(body), {
    headers: { "Content-Type": "application/json", ...headers },
  });
}

function formPost(url, params, headers = {}) {
  const encoded = Object.entries(params)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join("&");
  return http.post(url, encoded, {
    headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
  });
}

// ---------------------------------------------------------------------------
// Setup: create profile, trigger issuance, get baseline tokens
// ---------------------------------------------------------------------------

export async function setup() {
  // Create and activate pre-auth profile
  const profileBody = JSON.stringify({
    name: "Security Test Profile",
    role: "issuer",
    config: {
      grantType: "pre_authorization_code",
      credentialFormat: "sd_jwt_vc",
      vciProfile: "plain",
      credentialOffer: "by_reference",
      issuanceMode: "immediate",
    },
  });
  const createRes = http.post(`${BASE_URL}/admin/profiles`, profileBody, {
    headers: { "Content-Type": "application/json" },
  });
  if (createRes.status !== 201) {
    console.error(`Setup: profile creation failed ${createRes.status}: ${createRes.body}`);
    return { ok: false };
  }
  const profileId = createRes.json().id;
  http.put(`${BASE_URL}/admin/profiles/${profileId}/activate`);

  // Discover issuer URL
  const metaRes = http.get(`${BASE_URL}/.well-known/openid-credential-issuer`);
  const issuerUrl = metaRes.json().credential_issuer;

  // Trigger issuance to get a pre-auth code
  const issuanceRes = jsonPost(`${BASE_URL}/oid4vci/v1/issuance`, {
    credential_type: "eu.europa.ec.eudi.pid.1",
    credential_data: {
      given_name: "Security",
      family_name: "Test",
      birth_date: "1990-01-01",
    },
  });
  const offerUri = issuanceRes.json().credential_offer_uri;
  const offerRes = http.get(offerUri.replace("https://issuer.lab.fikua.com", BASE_URL));
  const offer = offerRes.json();
  const preAuthCode =
    offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"][
      "pre-authorized_code"
    ];

  // Exchange for access token
  const tokenRes = formPost(`${BASE_URL}/oid4vci/v1/token`, {
    grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    "pre-authorized_code": preAuthCode,
  });
  const tokenBody = tokenRes.json();

  // Get a valid nonce
  const nonceRes = http.post(`${BASE_URL}/oid4vci/v1/nonce`, null);
  const cNonce = nonceRes.json().c_nonce;

  // Trigger a second issuance for replay tests
  const issuanceRes2 = jsonPost(`${BASE_URL}/oid4vci/v1/issuance`, {
    credential_type: "eu.europa.ec.eudi.pid.1",
    credential_data: {
      given_name: "Replay",
      family_name: "Test",
      birth_date: "1995-06-15",
    },
  });
  const offerUri2 = issuanceRes2.json().credential_offer_uri;
  const offerRes2 = http.get(offerUri2.replace("https://issuer.lab.fikua.com", BASE_URL));
  const preAuthCode2 =
    offerRes2
      .json()
      .grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"][
        "pre-authorized_code"
      ];

  console.log("Security test setup OK");
  return {
    ok: true,
    issuerUrl,
    accessToken: tokenBody.access_token,
    cNonce,
    preAuthCode2,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

export default async function (data) {
  if (!data.ok) {
    console.error("Skipping: setup failed");
    return;
  }

  const walletKey = await generateWalletKey();

  // Pre-generate all proof JWTs outside group() callbacks (k6 group callbacks are sync)
  const proofWrongTyp = await signJwtProof(walletKey, data.issuerUrl, data.cNonce, { typ: "jwt" });
  const proofWrongAlg = await signJwtProof(walletKey, data.issuerUrl, data.cNonce, { alg: "RS256" });
  const proofBadSig = await signJwtProof(walletKey, data.issuerUrl, data.cNonce, { badSignature: true });
  const proofWrongAud = await signJwtProof(walletKey, data.issuerUrl, data.cNonce, { aud: "https://evil-issuer.example.com" });
  const proofExpiredIat = await signJwtProof(walletKey, data.issuerUrl, data.cNonce, { iat: Math.floor(Date.now() / 1000) - 600 });
  const proofBadNonce = await signJwtProof(walletKey, data.issuerUrl, "fake-nonce-xyz");
  const proofForCrossSession = await signJwtProof(walletKey, data.issuerUrl, data.cNonce);

  // =========================================================================
  // TOKEN ENDPOINT — Error paths
  // =========================================================================

  group("Token — missing grant_type", () => {
    const res = formPost(`${BASE_URL}/oid4vci/v1/token`, {
      "pre-authorized_code": "doesnt-matter",
    });
    check(res, {
      "→ 400": (r) => r.status === 400,
      "error: unsupported_grant_type": (r) => r.json().error === "unsupported_grant_type",
    });
  });

  group("Token — unsupported grant_type", () => {
    const res = formPost(`${BASE_URL}/oid4vci/v1/token`, {
      grant_type: "client_credentials",
    });
    check(res, {
      "→ 400": (r) => r.status === 400,
      "error: unsupported_grant_type": (r) => r.json().error === "unsupported_grant_type",
    });
  });

  group("Token — missing pre-authorized_code", () => {
    const res = formPost(`${BASE_URL}/oid4vci/v1/token`, {
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    });
    check(res, {
      "→ 400": (r) => r.status === 400,
      "error: invalid_grant": (r) => r.json().error === "invalid_grant",
    });
  });

  group("Token — invalid pre-authorized_code", () => {
    const res = formPost(`${BASE_URL}/oid4vci/v1/token`, {
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": "fake-code-12345",
    });
    check(res, {
      "→ 400": (r) => r.status === 400,
      "error: invalid_grant": (r) => r.json().error === "invalid_grant",
    });
  });

  group("Token — pre-authorized_code replay", () => {
    // First use — should succeed
    const res1 = formPost(`${BASE_URL}/oid4vci/v1/token`, {
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": data.preAuthCode2,
    });
    check(res1, {
      "first use → 200": (r) => r.status === 200,
    });

    // Second use — should fail (code already consumed)
    const res2 = formPost(`${BASE_URL}/oid4vci/v1/token`, {
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": data.preAuthCode2,
    });
    check(res2, {
      "replay → 400": (r) => r.status === 400,
      "error: invalid_grant": (r) => r.json().error === "invalid_grant",
    });
  });

  // =========================================================================
  // CREDENTIAL ENDPOINT — Access token errors
  // =========================================================================

  group("Credential — missing Authorization header", () => {
    const res = jsonPost(`${BASE_URL}/oid4vci/v1/credential`, {
      credential_configuration_id: "eu.europa.ec.eudi.pid.1",
    });
    check(res, {
      "→ 401": (r) => r.status === 401,
      "error: invalid_token": (r) => r.json().error === "invalid_token",
    });
  });

  group("Credential — invalid access token", () => {
    const res = jsonPost(`${BASE_URL}/oid4vci/v1/credential`, {
      credential_configuration_id: "eu.europa.ec.eudi.pid.1",
    }, { Authorization: "Bearer fake-token-xyz" });
    check(res, {
      "→ 401": (r) => r.status === 401,
      "error: invalid_token": (r) => r.json().error === "invalid_token",
    });
  });

  // =========================================================================
  // CREDENTIAL ENDPOINT — credential_configuration_id errors
  // =========================================================================

  group("Credential — missing credential_configuration_id", () => {
    const res = jsonPost(`${BASE_URL}/oid4vci/v1/credential`, {}, {
      Authorization: `Bearer ${data.accessToken}`,
    });
    check(res, {
      "→ 400": (r) => r.status === 400,
      "error: invalid_credential_request": (r) =>
        r.json().error === "invalid_credential_request",
    });
  });

  group("Credential — unknown credential_configuration_id", () => {
    const res = jsonPost(
      `${BASE_URL}/oid4vci/v1/credential`,
      { credential_configuration_id: "com.fake.nonexistent.1" },
      { Authorization: `Bearer ${data.accessToken}` }
    );
    check(res, {
      "→ 400": (r) => r.status === 400,
      "error: unknown_credential_configuration": (r) =>
        r.json().error === "unknown_credential_configuration",
    });
  });

  // =========================================================================
  // CREDENTIAL ENDPOINT — Proof validation errors
  // =========================================================================

  group("Credential — missing proof", () => {
    const res = jsonPost(
      `${BASE_URL}/oid4vci/v1/credential`,
      { credential_configuration_id: "eu.europa.ec.eudi.pid.1" },
      { Authorization: `Bearer ${data.accessToken}` }
    );
    check(res, {
      "→ 400": (r) => r.status === 400,
      "error: invalid_proof": (r) => r.json().error === "invalid_proof",
    });
  });

  group("Credential — proof with wrong typ", () => {
    const res = jsonPost(
      `${BASE_URL}/oid4vci/v1/credential`,
      {
        credential_configuration_id: "eu.europa.ec.eudi.pid.1",
        proofs: { jwt: [proofWrongTyp] },
      },
      { Authorization: `Bearer ${data.accessToken}` }
    );
    check(res, {
      "→ 400": (r) => r.status === 400,
      "error: invalid_proof": (r) => r.json().error === "invalid_proof",
    });
  });

  group("Credential — proof with wrong alg", () => {
    const res = jsonPost(
      `${BASE_URL}/oid4vci/v1/credential`,
      {
        credential_configuration_id: "eu.europa.ec.eudi.pid.1",
        proofs: { jwt: [proofWrongAlg] },
      },
      { Authorization: `Bearer ${data.accessToken}` }
    );
    check(res, {
      "→ 400": (r) => r.status === 400,
      "error: invalid_proof": (r) => r.json().error === "invalid_proof",
    });
  });

  group("Credential — proof with invalid signature", () => {
    const res = jsonPost(
      `${BASE_URL}/oid4vci/v1/credential`,
      {
        credential_configuration_id: "eu.europa.ec.eudi.pid.1",
        proofs: { jwt: [proofBadSig] },
      },
      { Authorization: `Bearer ${data.accessToken}` }
    );
    check(res, {
      "→ 400": (r) => r.status === 400,
      "error: invalid_proof": (r) => r.json().error === "invalid_proof",
    });
  });

  group("Credential — proof with wrong audience", () => {
    const res = jsonPost(
      `${BASE_URL}/oid4vci/v1/credential`,
      {
        credential_configuration_id: "eu.europa.ec.eudi.pid.1",
        proofs: { jwt: [proofWrongAud] },
      },
      { Authorization: `Bearer ${data.accessToken}` }
    );
    check(res, {
      "→ 400": (r) => r.status === 400,
      "error: invalid_proof": (r) => r.json().error === "invalid_proof",
    });
  });

  group("Credential — proof with expired iat", () => {
    const res = jsonPost(
      `${BASE_URL}/oid4vci/v1/credential`,
      {
        credential_configuration_id: "eu.europa.ec.eudi.pid.1",
        proofs: { jwt: [proofExpiredIat] },
      },
      { Authorization: `Bearer ${data.accessToken}` }
    );
    check(res, {
      "→ 400": (r) => r.status === 400,
      "error: invalid_proof": (r) => r.json().error === "invalid_proof",
    });
  });

  group("Credential — proof with invalid nonce", () => {
    const res = jsonPost(
      `${BASE_URL}/oid4vci/v1/credential`,
      {
        credential_configuration_id: "eu.europa.ec.eudi.pid.1",
        proofs: { jwt: [proofBadNonce] },
      },
      { Authorization: `Bearer ${data.accessToken}` }
    );
    check(res, {
      "→ 400": (r) => r.status === 400,
      "error: invalid_nonce or invalid_proof": (r) => {
        const err = r.json().error;
        return err === "invalid_nonce" || err === "invalid_proof";
      },
    });
  });

  // =========================================================================
  // CREDENTIAL ENDPOINT — Token substitution (cross-session)
  // =========================================================================

  group("Credential — token from different session", () => {
    // Trigger a new issuance (creates a new session)
    const issuanceRes = jsonPost(`${BASE_URL}/oid4vci/v1/issuance`, {
      credential_type: "eu.europa.ec.eudi.pid.1",
      credential_data: { given_name: "Other", family_name: "Session" },
    });
    const offerUri = issuanceRes.json().credential_offer_uri;
    const offerRes = http.get(
      offerUri.replace("https://issuer.lab.fikua.com", BASE_URL)
    );
    const preAuthCode =
      offerRes.json().grants[
        "urn:ietf:params:oauth:grant-type:pre-authorized_code"
      ]["pre-authorized_code"];

    const tokenRes = formPost(`${BASE_URL}/oid4vci/v1/token`, {
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": preAuthCode,
    });
    const otherToken = tokenRes.json().access_token;

    // Use token from session B with a proof built for session A's nonce
    const res = jsonPost(
      `${BASE_URL}/oid4vci/v1/credential`,
      {
        credential_configuration_id: "eu.europa.ec.eudi.pid.1",
        proofs: { jwt: [proofForCrossSession] },
      },
      { Authorization: `Bearer ${otherToken}` }
    );
    check(res, {
      "cross-session → rejected (400 or 401)": (r) =>
        r.status === 400 || r.status === 401,
      "error is auth or nonce related": (r) => {
        const err = r.json().error;
        return (
          err === "invalid_nonce" ||
          err === "invalid_proof" ||
          err === "invalid_token"
        );
      },
    });
  });

  // =========================================================================
  // HTTP METHOD VALIDATION
  // =========================================================================

  group("Method not allowed — GET on POST-only endpoints", () => {
    const tokenGet = http.get(`${BASE_URL}/oid4vci/v1/token`);
    check(tokenGet, {
      "GET /token → 404 or 405": (r) => r.status === 404 || r.status === 405,
    });

    const credGet = http.get(`${BASE_URL}/oid4vci/v1/credential`);
    check(credGet, {
      "GET /credential → 404 or 405": (r) =>
        r.status === 404 || r.status === 405,
    });

    const nonceGet = http.get(`${BASE_URL}/oid4vci/v1/nonce`);
    check(nonceGet, {
      "GET /nonce → 404 or 405": (r) =>
        r.status === 404 || r.status === 405,
    });
  });

  // =========================================================================
  // MALFORMED INPUT
  // =========================================================================

  group("Malformed JSON body", () => {
    const res = http.post(
      `${BASE_URL}/oid4vci/v1/credential`,
      "{ this is not json }}}",
      {
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${data.accessToken}`,
        },
      }
    );
    check(res, {
      "malformed JSON → 400": (r) => r.status === 400,
    });
  });

  group("Empty body on credential endpoint", () => {
    const res = http.post(`${BASE_URL}/oid4vci/v1/credential`, null, {
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${data.accessToken}`,
      },
    });
    check(res, {
      "empty body → 400": (r) => r.status === 400,
    });
  });

  // =========================================================================
  // NONEXISTENT ENDPOINTS (404)
  // =========================================================================

  group("404 — nonexistent endpoints", () => {
    const res1 = http.get(`${BASE_URL}/oid4vci/v1/nonexistent`);
    check(res1, {
      "/nonexistent → 404": (r) => r.status === 404,
    });

    const res2 = http.get(`${BASE_URL}/.well-known/openid-configuration`);
    check(res2, {
      "/.well-known/openid-configuration → 404": (r) => r.status === 404,
    });
  });

  // =========================================================================
  // SECURITY HEADERS
  // =========================================================================

  group("Security headers on metadata", () => {
    const res = http.get(`${BASE_URL}/.well-known/openid-credential-issuer`);
    check(res, {
      "Content-Type is application/json": (r) =>
        r.headers["Content-Type"] &&
        r.headers["Content-Type"].includes("application/json"),
      "no server version leak": (r) =>
        !r.headers["Server"] || !r.headers["Server"].includes("Jetty"),
    });
  });

  group("Security headers on token endpoint", () => {
    const res = formPost(`${BASE_URL}/oid4vci/v1/token`, {
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": "x",
    });
    check(res, {
      "Cache-Control present or no caching": (r) => {
        const cc = r.headers["Cache-Control"];
        // Token endpoint should not be cached; either explicit no-store or absent
        return !cc || cc.includes("no-store") || cc.includes("no-cache");
      },
    });
  });
}
