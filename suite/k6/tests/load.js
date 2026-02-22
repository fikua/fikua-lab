/**
 * Fikua Lab — Load & Performance Tests (k6)
 *
 * Tests the REAL issuance flow: offer → token → credential (with JWT proof).
 * Measures actual system performance including DB, crypto, and state management.
 *
 * Scenarios:
 *   - smoke:   5 VUs for 30s — sanity check
 *   - load:    ramp to 50 VUs over 70s — sustained load
 *   - stress:  ramp to 200 VUs — find breaking point
 *   - soak:    20 VUs for 10min — detect memory leaks
 *
 * Usage:
 *   k6 run suite/k6/tests/load.js                          # default (load)
 *   k6 run suite/k6/tests/load.js --env SCENARIO=smoke
 *   k6 run suite/k6/tests/load.js --env SCENARIO=stress
 *   k6 run suite/k6/tests/load.js --env SCENARIO=soak
 *   k6 run suite/k6/tests/load.js --env BASE_URL=http://other:8080
 */

import http from "k6/http";
import { check, group, sleep } from "k6";
import { Rate, Trend, Counter } from "k6/metrics";
import encoding from "k6/encoding";

const BASE_URL = __ENV.BASE_URL || "http://localhost:8080";
const SCENARIO = __ENV.SCENARIO || "load";

// Custom metrics — per flow stage
const errorRate = new Rate("errors");
const offerLatency = new Trend("offer_latency", true);
const tokenLatency = new Trend("token_latency", true);
const credentialLatency = new Trend("credential_latency", true);
const metadataLatency = new Trend("metadata_latency", true);
const fullFlowLatency = new Trend("full_flow_latency", true);
const issuanceCount = new Counter("credentials_issued");

// Scenario definitions
const scenarios = {
  smoke: {
    stages: [{ duration: "30s", target: 5 }],
  },
  load: {
    stages: [
      { duration: "15s", target: 10 },
      { duration: "30s", target: 30 },
      { duration: "15s", target: 50 },
      { duration: "10s", target: 0 },
    ],
  },
  stress: {
    stages: [
      { duration: "10s", target: 20 },
      { duration: "20s", target: 50 },
      { duration: "20s", target: 100 },
      { duration: "20s", target: 200 },
      { duration: "10s", target: 0 },
    ],
  },
  soak: {
    stages: [
      { duration: "30s", target: 20 },
      { duration: "9m", target: 20 },
      { duration: "30s", target: 0 },
    ],
  },
};

export const options = {
  stages: scenarios[SCENARIO]?.stages || scenarios.load.stages,
  thresholds: {
    // NFR: overall p95 under 500ms, p99 under 1s
    http_req_duration: ["p(95)<500", "p(99)<1000"],
    // NFR: error rate below 1%
    errors: ["rate<0.01"],
    // NFR: credential offer (DB read + state write)
    offer_latency: ["p(95)<300"],
    // NFR: token exchange (state consume + create)
    token_latency: ["p(95)<300"],
    // NFR: credential issuance (JWT verify + SD-JWT sign — heaviest endpoint)
    credential_latency: ["p(95)<500"],
    // NFR: metadata (DB read + JSON build)
    metadata_latency: ["p(95)<200"],
    // NFR: full issuance flow end-to-end
    full_flow_latency: ["p(95)<1500"],
  },
};

// ---------------------------------------------------------------------------
// JWT Proof builder (ES256 via WebCrypto)
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

async function signJwtProof(keyPair, audience, nonce) {
  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);

  const header = JSON.stringify({
    typ: "openid4vci-proof+jwt",
    alg: "ES256",
    jwk: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y },
  });

  const payload = JSON.stringify({
    aud: audience,
    nonce: nonce,
    iat: Math.floor(Date.now() / 1000),
  });

  const headerB64 = toBase64url(strToArrayBuffer(header));
  const payloadB64 = toBase64url(strToArrayBuffer(payload));
  const signingInput = `${headerB64}.${payloadB64}`;

  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    keyPair.privateKey,
    strToArrayBuffer(signingInput)
  );

  // WebCrypto returns raw R||S (64 bytes) for P-256
  const sigB64 = toBase64url(signature);
  return `${signingInput}.${sigB64}`;
}

// ---------------------------------------------------------------------------
// Setup: create & activate profile, verify setup works
// ---------------------------------------------------------------------------

export async function setup() {
  const body = JSON.stringify({
    name: "Load Test Profile",
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

  if (createRes.status !== 201) {
    console.error(`Setup failed: profile creation returned ${createRes.status}: ${createRes.body}`);
    return { ok: false };
  }

  const profileId = createRes.json().id;
  const activateRes = http.put(`${BASE_URL}/admin/profiles/${profileId}/activate`);

  if (activateRes.status !== 200) {
    console.error(`Setup failed: activation returned ${activateRes.status}`);
    return { ok: false };
  }

  // Discover the real credential_issuer URL (may differ from BASE_URL)
  const metaRes = http.get(`${BASE_URL}/.well-known/openid-credential-issuer`);
  const issuerUrl = metaRes.json().credential_issuer;
  console.log(`Discovered credential_issuer: ${issuerUrl}`);

  // Smoke-check: verify a single full issuance flow works
  const keyPair = await generateWalletKey();

  // Trigger issuance via POST /issuance (creates offer with pre-auth code)
  const issuanceBody = JSON.stringify({
    credential_type: "eu.europa.ec.eudi.pid.1",
    credential_data: { given_name: "Smoke", family_name: "Test", birth_date: "2000-01-01" },
  });
  const issuanceRes = http.post(`${BASE_URL}/oid4vci/v1/issuance`, issuanceBody, {
    headers: { "Content-Type": "application/json" },
  });
  if (issuanceRes.status !== 200) {
    console.error(`Setup failed: issuance trigger returned ${issuanceRes.status}: ${issuanceRes.body}`);
    return { ok: false };
  }

  // Resolve offer URI to get pre-auth code
  const offerUri = issuanceRes.json().credential_offer_uri;
  const offerRes = http.get(offerUri.replace("https://issuer.lab.fikua.com", BASE_URL));
  const offer = offerRes.json();
  const preAuthCode =
    offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"];

  const tokenRes = http.post(
    `${BASE_URL}/oid4vci/v1/token`,
    `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=${preAuthCode}`,
    { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
  );
  const tokenBody = tokenRes.json();

  // Get nonce from Nonce Endpoint (OID4VCI 1.0 Final §7)
  const nonceRes = http.post(`${BASE_URL}/oid4vci/v1/nonce`, null);
  const cNonce = nonceRes.json().c_nonce;

  const jwtProof = await signJwtProof(keyPair, issuerUrl, cNonce);
  const credReq = JSON.stringify({
    credential_configuration_id: "eu.europa.ec.eudi.pid.1",
    proofs: { jwt: [jwtProof] },
  });

  const credRes = http.post(`${BASE_URL}/oid4vci/v1/credential`, credReq, {
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${tokenBody.access_token}`,
    },
  });

  if (credRes.status !== 200) {
    console.error(`Setup smoke-check FAILED: credential endpoint returned ${credRes.status}: ${credRes.body}`);
    return { ok: false };
  }

  console.log(`Setup OK: full issuance flow verified. Scenario: ${SCENARIO}`);
  return { ok: true, profileId, issuerUrl };
}

// ---------------------------------------------------------------------------
// Main test iteration — full OID4VCI pre-auth issuance flow
// ---------------------------------------------------------------------------

export default async function (data) {
  if (!data.ok) {
    console.error("Skipping iteration: setup failed");
    sleep(1);
    return;
  }

  const flowStart = Date.now();

  // Each VU generates its own wallet key (simulates different wallets)
  const walletKeyPair = await generateWalletKey();

  // --- Step 1: Trigger issuance + resolve offer (DB write + state) ---
  let preAuthCode = null;

  const issuanceBody = JSON.stringify({
    credential_type: "eu.europa.ec.eudi.pid.1",
    credential_data: { given_name: "Load", family_name: "Test", birth_date: "1995-06-15" },
  });
  const issuanceRes = http.post(`${BASE_URL}/oid4vci/v1/issuance`, issuanceBody, {
    headers: { "Content-Type": "application/json" },
  });
  offerLatency.add(issuanceRes.timings.duration);

  const offerOk = check(issuanceRes, {
    "issuance → 200": (r) => r.status === 200,
    "issuance has offer URI": (r) => {
      try {
        return r.json().credential_offer_uri !== undefined;
      } catch (e) {
        return false;
      }
    },
  });
  errorRate.add(!offerOk);

  if (issuanceRes.status !== 200) {
    sleep(0.3);
    return;
  }

  // Resolve offer URI to get pre-auth code
  const offerUri = issuanceRes.json().credential_offer_uri;
  const offerRes = http.get(offerUri.replace("https://issuer.lab.fikua.com", BASE_URL));

  const resolveOk = check(offerRes, {
    "offer resolve → 200": (r) => r.status === 200,
    "offer has pre-auth code": (r) => {
      try {
        const grants = r.json().grants;
        preAuthCode =
          grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"];
        return preAuthCode !== undefined;
      } catch (e) {
        return false;
      }
    },
  });
  errorRate.add(!resolveOk);

  if (!preAuthCode) {
    sleep(0.3);
    return;
  }

  // --- Step 2: Exchange pre-auth code for access token (state consume + create) ---
  let accessToken = null;
  let cNonce = null;

  const tokenRes = http.post(
    `${BASE_URL}/oid4vci/v1/token`,
    `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=${preAuthCode}`,
    { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
  );
  tokenLatency.add(tokenRes.timings.duration);

  const tokenOk = check(tokenRes, {
    "token → 200": (r) => r.status === 200,
    "token has access_token + c_nonce": (r) => {
      try {
        const body = r.json();
        accessToken = body.access_token;
        cNonce = body.c_nonce;
        return accessToken !== undefined && cNonce !== undefined;
      } catch (e) {
        return false;
      }
    },
  });
  errorRate.add(!tokenOk);

  if (!accessToken || !cNonce) {
    sleep(0.3);
    return;
  }

  // --- Step 2b: Get nonce from Nonce Endpoint (OID4VCI 1.0 Final §7) ---
  const nonceRes = http.post(`${BASE_URL}/oid4vci/v1/nonce`, null);
  const nonce = nonceRes.json().c_nonce;

  // --- Step 3: Request credential with JWT proof (JWT verify + SD-JWT sign) ---
  const jwtProof = await signJwtProof(walletKeyPair, data.issuerUrl, nonce || cNonce);

  const credReqBody = JSON.stringify({
    credential_configuration_id: "eu.europa.ec.eudi.pid.1",
    proofs: { jwt: [jwtProof] },
  });

  const credRes = http.post(`${BASE_URL}/oid4vci/v1/credential`, credReqBody, {
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${accessToken}`,
    },
  });
  credentialLatency.add(credRes.timings.duration);

  const credOk = check(credRes, {
    "credential → 200": (r) => r.status === 200,
    "credential has SD-JWT": (r) => {
      try {
        // OID4VCI 1.0 Final: credentials[0].credential
        const cred = r.json().credentials[0].credential;
        // SD-JWT format: header.payload~disclosure1~disclosure2~
        return cred !== undefined && cred.includes("~");
      } catch (e) {
        return false;
      }
    },
  });
  if (credOk) issuanceCount.add(1);
  errorRate.add(!credOk);

  // --- Step 4: Metadata read under load (DB query + JSON serialization) ---
  const metaRes = http.get(`${BASE_URL}/.well-known/openid-credential-issuer`);
  metadataLatency.add(metaRes.timings.duration);
  const metaOk = check(metaRes, {
    "metadata → 200": (r) => r.status === 200,
  });
  errorRate.add(!metaOk);

  fullFlowLatency.add(Date.now() - flowStart);

  // Think time — simulate real wallet behavior
  sleep(0.3 + Math.random() * 0.4);
}
