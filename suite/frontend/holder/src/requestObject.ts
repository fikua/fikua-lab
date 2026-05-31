// =============================================================================
// JAR (RFC 9101) request-object handling for OID4VP / HAIP.
//
// The Verifier's Authorization Request arrives as a signed JWT (typ
// oauth-authz-req+jwt) with the signing cert chain in the x5c header, rather
// than as bare JSON. This module:
//   1. detects and splits the JWT,
//   2. verifies the ES256 signature against the leaf cert in x5c[0],
//   3. checks the leaf chains to a pinned trust anchor,
//   4. returns the decoded request parameters (the JWT payload).
//
// HAIP leaves trust-anchor management out of scope, so the anchor set is a
// small bundled list (trusted-anchors.json) — see verifyTrustAnchor().
// =============================================================================

import { base64urlDecode, base64urlDecodeJson } from './utils';
import type { Oid4vpAuthorizationRequest } from './types';
import { getTrustedAnchors } from './trustedAnchors';

interface JwsHeader {
    alg?: string;
    typ?: string;
    x5c?: string[];
}

/** True if the body looks like a compact JWS (three base64url segments). */
export function looksLikeJwt(body: string): boolean {
    const s = body.trim();
    if (s.startsWith('{')) return false;
    const parts = s.split('.');
    return parts.length === 3 && parts.every(p => p.length > 0);
}

/**
 * Verify a JAR JWT and return its request-parameter payload.
 * Throws if the signature, typ, or trust chain is invalid.
 */
export async function verifyRequestObjectJwt(jwt: string): Promise<Oid4vpAuthorizationRequest> {
    const [headerB64, payloadB64, sigB64] = jwt.trim().split('.');
    const header = base64urlDecodeJson(headerB64) as JwsHeader;

    if (header.alg !== 'ES256') {
        throw new Error(`Unsupported JAR alg: ${header.alg ?? 'none'} (expected ES256)`);
    }
    // typ is RECOMMENDED as oauth-authz-req+jwt; accept it but don't hard-fail
    // on absence, since some verifiers omit it.
    if (header.typ && header.typ !== 'oauth-authz-req+jwt') {
        throw new Error(`Unexpected JAR typ: ${header.typ}`);
    }
    if (!header.x5c || header.x5c.length === 0) {
        throw new Error('JAR header missing x5c — cannot establish signer');
    }

    const leafDer = base64ToBytes(header.x5c[0]);

    // 1. Signature: verify ES256 over "header.payload" with the leaf's pubkey.
    const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const sig = base64urlDecode(sigB64);
    const leafKey = await importEcP256FromCertDer(leafDer);
    const ok = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        leafKey,
        sig as Uint8Array<ArrayBuffer>,
        signingInput as Uint8Array<ArrayBuffer>,
    );
    if (!ok) {
        throw new Error('JAR signature verification failed');
    }

    // 2. Trust: the leaf must be issued by one of our pinned anchors.
    await verifyTrustAnchor(leafDer);

    const payload = base64urlDecodeJson(payloadB64) as unknown as Oid4vpAuthorizationRequest;
    return payload;
}

/**
 * Confirm the leaf was signed by a trusted anchor: verify the leaf's
 * signature using each anchor's public key. (A full path/validity check is
 * out of scope for the lab; this proves the issuing CA is one we trust.)
 */
async function verifyTrustAnchor(leafDer: Uint8Array): Promise<void> {
    const tbs = extractTbsCertificate(leafDer);
    const sig = extractCertSignature(leafDer);

    const anchors = await getTrustedAnchors();
    for (const anchorPem of anchors) {
        try {
            const anchorDer = pemToDer(anchorPem);
            const anchorKey = await importEcP256FromCertDer(anchorDer);
            const ok = await crypto.subtle.verify(
                { name: 'ECDSA', hash: 'SHA-256' },
                anchorKey,
                derEcdsaToRaw(sig) as Uint8Array<ArrayBuffer>,
                tbs as Uint8Array<ArrayBuffer>,
            );
            if (ok) return; // chained to a trusted anchor
        } catch {
            // try the next anchor
        }
    }
    throw new Error('Verifier certificate is not anchored to a trusted root');
}

// ---------------------------------------------------------------------------
// Minimal DER helpers — enough to pull the SPKI + signature out of an X.509
// EC P-256 certificate without a full ASN.1 library.
// ---------------------------------------------------------------------------

/** Import an EC P-256 public key from a DER-encoded X.509 certificate. */
async function importEcP256FromCertDer(certDer: Uint8Array): Promise<CryptoKey> {
    const spki = extractSpki(certDer);
    return crypto.subtle.importKey(
        'spki',
        bytesToArrayBuffer(spki),
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify'],
    );
}

/** TLV reader: returns {tag, len, headerLen, valueStart, end} at offset. */
function readTlv(buf: Uint8Array, off: number) {
    const tag = buf[off];
    let len = buf[off + 1];
    let headerLen = 2;
    if (len & 0x80) {
        const n = len & 0x7f;
        len = 0;
        for (let i = 0; i < n; i++) len = (len << 8) | buf[off + 2 + i];
        headerLen = 2 + n;
    }
    const valueStart = off + headerLen;
    return { tag, len, headerLen, valueStart, end: valueStart + len };
}

/** Certificate ::= SEQ { tbsCertificate SEQ, signatureAlgorithm SEQ, signature BIT STRING }. */
function certParts(certDer: Uint8Array) {
    const cert = readTlv(certDer, 0); // outer SEQUENCE
    const tbs = readTlv(certDer, cert.valueStart); // tbsCertificate SEQUENCE
    const sigAlg = readTlv(certDer, tbs.end); // signatureAlgorithm
    const sig = readTlv(certDer, sigAlg.end); // signature BIT STRING
    return { tbs, sig };
}

/** The bytes of tbsCertificate INCLUDING its own SEQUENCE header (what's signed). */
function extractTbsCertificate(certDer: Uint8Array): Uint8Array {
    const { tbs } = certParts(certDer);
    return certDer.slice(tbs.valueStart - tbs.headerLen, tbs.end);
}

/** The signature BIT STRING value (DER-encoded ECDSA Sig), minus the unused-bits byte. */
function extractCertSignature(certDer: Uint8Array): Uint8Array {
    const { sig } = certParts(certDer);
    // BIT STRING: first content byte is the count of unused bits (0 here).
    return certDer.slice(sig.valueStart + 1, sig.end);
}

/**
 * Walk tbsCertificate to the subjectPublicKeyInfo SEQUENCE and return it.
 * tbs ::= SEQ { [0] version?, serial INT, sigAlg SEQ, issuer SEQ, validity SEQ,
 *               subject SEQ, subjectPublicKeyInfo SEQ, ... }
 */
function extractSpki(certDer: Uint8Array): Uint8Array {
    const cert = readTlv(certDer, 0);
    const tbs = readTlv(certDer, cert.valueStart);
    let p = tbs.valueStart;

    const first = readTlv(certDer, p);
    if (first.tag === 0xa0) p = first.end; // skip [0] version
    p = readTlv(certDer, p).end; // serialNumber
    p = readTlv(certDer, p).end; // signature AlgorithmIdentifier
    p = readTlv(certDer, p).end; // issuer
    p = readTlv(certDer, p).end; // validity
    p = readTlv(certDer, p).end; // subject

    const spki = readTlv(certDer, p); // subjectPublicKeyInfo
    return certDer.slice(spki.valueStart - spki.headerLen, spki.end);
}

/** Convert a DER-encoded ECDSA-Sig-Value (SEQ{ r INT, s INT }) to raw r||s (64 bytes). */
function derEcdsaToRaw(der: Uint8Array): Uint8Array {
    const seq = readTlv(der, 0);
    const r = readTlv(der, seq.valueStart);
    const s = readTlv(der, r.end);
    const rb = trimLeadingZeros(der.slice(r.valueStart, r.end));
    const sb = trimLeadingZeros(der.slice(s.valueStart, s.end));
    const out = new Uint8Array(64);
    out.set(rb, 32 - rb.length);
    out.set(sb, 64 - sb.length);
    return out;
}

function trimLeadingZeros(b: Uint8Array): Uint8Array {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0x00) i++;
    return b.slice(i);
}

function base64ToBytes(b64: string): Uint8Array {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

function pemToDer(pem: string): Uint8Array {
    const b64 = pem
        .replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\s+/g, '');
    return base64ToBytes(b64);
}

function bytesToArrayBuffer(b: Uint8Array): ArrayBuffer {
    return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;
}
