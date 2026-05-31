package com.fikua.core.mdoc;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Full mso_mdoc {@code DeviceResponse} verification for the OID4VP verifier.
 *
 * <p>Mirrors the contract of {@code SdJwtVcVerifier}: a single static
 * {@code verify} that returns the disclosed claims or throws
 * {@link VerificationException} (which the verifier maps to a 4xx rejection).
 *
 * <p>Checks, in order:
 * <ol>
 *   <li>structural validity of the {@code DeviceResponse} ({@code version},
 *       {@code status}, one {@code Document});</li>
 *   <li>{@code issuerAuth} COSE_Sign1 signature against its x5chain leaf, and
 *       the leaf's certificate chain via {@link CertChainValidator};</li>
 *   <li>MSO {@code version} / {@code digestAlgorithm}, and {@code docType}
 *       consistency across Document, MSO, and the requested docType;</li>
 *   <li>every disclosed {@code IssuerSignedItem} digest matches
 *       {@code MSO.valueDigests};</li>
 *   <li>MSO {@code validityInfo} window (with a small clock-skew tolerance);</li>
 *   <li>{@code deviceSignature} COSE_Sign1 over the reconstructed
 *       {@code DeviceAuthenticationBytes}, against the MSO {@code deviceKey} —
 *       this is the SessionTranscript binding the conformance
 *       {@code invalid-session-transcript} test exercises.</li>
 * </ol>
 */
public final class MdocDeviceResponseVerifier {

    /** Tolerated clock skew on validityInfo, matching the SD-JWT verifier philosophy. */
    private static final long VALIDITY_SKEW_SECONDS = 300;

    private MdocDeviceResponseVerifier() {}

    /** Thrown when a DeviceResponse fails any verification step. */
    public static final class VerificationException extends Exception {
        public VerificationException(String message) {
            super(message);
        }
    }

    /**
     * Verify an OID4VP mso_mdoc DeviceResponse and return the disclosed claims.
     *
     * @param base64urlDeviceResponse the vp_token value (base64url DeviceResponse CBOR)
     * @param expectedDocType         the requested docType (from DCQL doctype_value)
     * @param clientId                the full client_id (with prefix) sent in the request
     * @param nonce                   the request nonce
     * @param encJwkThumbprint        raw 32-byte RFC 7638 thumbprint of the
     *                                response-encryption key (null if unencrypted)
     * @param responseUri             the response_uri sent in the request
     * @param trustAnchor             optional pinned issuer trust anchor (null ⇒
     *                                anchor on the x5chain's own root)
     * @throws VerificationException if any check fails
     */
    public static Map<String, Object> verify(
            String base64urlDeviceResponse, String expectedDocType,
            String clientId, String nonce, byte[] encJwkThumbprint, String responseUri,
            X509Certificate trustAnchor) throws VerificationException {

        CBORObject document = parseSingleDocument(base64urlDeviceResponse);
        String docType = getString(document, "docType");
        CBORObject issuerSigned = require(document, "issuerSigned", "Document missing issuerSigned");
        CBORObject deviceSigned = require(document, "deviceSigned", "Document missing deviceSigned");

        CBORObject issuerAuth = require(issuerSigned, "issuerAuth", "issuerSigned missing issuerAuth");
        CBORObject mso = verifyIssuerAuthAndExtractMso(issuerAuth, trustAnchor);

        verifyMsoMeta(mso);
        verifyDocType(docType, mso, expectedDocType);

        Map<String, Object> claims = verifyDigestsAndCollectClaims(issuerSigned, mso);

        verifyValidity(mso);

        verifyDeviceSignature(deviceSigned, mso, docType,
                clientId, nonce, encJwkThumbprint, responseUri);

        return claims;
    }

    // --- Structural parsing -------------------------------------------------

    private static CBORObject parseSingleDocument(String base64url) throws VerificationException {
        CBORObject deviceResponse;
        try {
            byte[] cbor = Base64.getUrlDecoder().decode(stripPadding(base64url));
            deviceResponse = CBORObject.DecodeFromBytes(cbor);
        } catch (Exception e) {
            throw new VerificationException("Malformed DeviceResponse CBOR: " + e.getMessage());
        }
        if (deviceResponse.getType() != CBORType.Map) {
            throw new VerificationException("DeviceResponse must be a CBOR map");
        }
        String version = getString(deviceResponse, "version");
        if (!"1.0".equals(version)) {
            throw new VerificationException("Unsupported DeviceResponse version: " + version);
        }
        CBORObject status = deviceResponse.get("status");
        if (status != null && status.AsInt32() != 0) {
            throw new VerificationException("DeviceResponse status is not OK: " + status.AsInt32());
        }
        CBORObject documents = deviceResponse.get("documents");
        if (documents == null || documents.getType() != CBORType.Array || documents.size() == 0) {
            throw new VerificationException("DeviceResponse has no documents");
        }
        return documents.get(0);
    }

    // --- Issuer signature + MSO --------------------------------------------

    private static CBORObject verifyIssuerAuthAndExtractMso(CBORObject issuerAuth,
                                                            X509Certificate trustAnchor)
            throws VerificationException {
        try {
            List<X509Certificate> chain = CoseSign1Verifier.certChain(issuerAuth);
            if (chain.isEmpty()) {
                throw new VerificationException("issuerAuth has no x5chain certificate");
            }
            ECPublicKey issuerKey = (ECPublicKey) chain.get(0).getPublicKey();
            if (!CoseSign1Verifier.verify(issuerAuth, issuerKey)) {
                throw new VerificationException("issuerAuth signature is invalid");
            }
            try {
                CertChainValidator.validate(chain, trustAnchor);
            } catch (CertChainValidator.ChainException e) {
                throw new VerificationException("Issuer certificate chain invalid: " + e.getMessage());
            }
        } catch (VerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new VerificationException("Failed to verify issuerAuth: " + e.getMessage());
        }

        // payload (element 2) = #6.24(bstr .cbor MSO)
        byte[] payload = issuerAuth.get(2).GetByteString();
        CBORObject taggedMso = CBORObject.DecodeFromBytes(payload);
        if (taggedMso.getMostOuterTag().ToInt32Unchecked() != 24) {
            throw new VerificationException("MSO payload is not tag 24 (MobileSecurityObjectBytes)");
        }
        return CBORObject.DecodeFromBytes(taggedMso.Untag().GetByteString());
    }

    private static void verifyMsoMeta(CBORObject mso) throws VerificationException {
        String version = getString(mso, "version");
        if (!"1.0".equals(version)) {
            throw new VerificationException("Unsupported MSO version: " + version);
        }
        String digestAlg = getString(mso, "digestAlgorithm");
        if (!"SHA-256".equals(digestAlg)) {
            throw new VerificationException("Unsupported MSO digestAlgorithm: " + digestAlg);
        }
    }

    private static void verifyDocType(String docType, CBORObject mso, String expectedDocType)
            throws VerificationException {
        String msoDocType = getString(mso, "docType");
        if (docType == null || !docType.equals(msoDocType)) {
            throw new VerificationException(
                    "Document docType '" + docType + "' does not match MSO docType '" + msoDocType + "'");
        }
        if (expectedDocType != null && !expectedDocType.equals(docType)) {
            throw new VerificationException(
                    "docType '" + docType + "' does not match requested '" + expectedDocType + "'");
        }
    }

    // --- Digest verification + claim collection ----------------------------

    private static Map<String, Object> verifyDigestsAndCollectClaims(CBORObject issuerSigned,
                                                                     CBORObject mso)
            throws VerificationException {
        CBORObject nameSpaces = require(issuerSigned, "nameSpaces", "issuerSigned missing nameSpaces");
        CBORObject valueDigests = require(mso, "valueDigests", "MSO missing valueDigests");

        Map<String, Object> claims = new LinkedHashMap<>();

        for (CBORObject nsKey : nameSpaces.getKeys()) {
            String ns = nsKey.AsString();
            CBORObject items = nameSpaces.get(nsKey);
            CBORObject nsDigests = valueDigests.get(nsKey);
            if (nsDigests == null) {
                throw new VerificationException("MSO has no valueDigests for namespace " + ns);
            }
            for (int i = 0; i < items.size(); i++) {
                CBORObject tagged = items.get(i);
                if (tagged.getMostOuterTag().ToInt32Unchecked() != 24) {
                    throw new VerificationException("IssuerSignedItem is not tag 24");
                }
                byte[] innerBytes = tagged.Untag().GetByteString();
                byte[] digest = sha256(innerBytes);

                CBORObject item = CBORObject.DecodeFromBytes(innerBytes);
                int digestId = item.get("digestID").AsInt32();
                String elementId = item.get("elementIdentifier").AsString();

                CBORObject expected = nsDigests.get(CBORObject.FromObject(digestId));
                if (expected == null) {
                    throw new VerificationException(
                            "No MSO digest for digestID " + digestId + " in namespace " + ns);
                }
                if (!java.util.Arrays.equals(expected.GetByteString(), digest)) {
                    throw new VerificationException(
                            "Digest mismatch for '" + elementId + "' (tampered IssuerSignedItem)");
                }
                claims.put(elementId, cborToJava(item.get("elementValue")));
            }
        }
        return claims;
    }

    private static void verifyValidity(CBORObject mso) throws VerificationException {
        CBORObject validity = mso.get("validityInfo");
        if (validity == null) {
            throw new VerificationException("MSO missing validityInfo");
        }
        Instant now = Instant.now();
        Instant validFrom = parseTdate(validity.get("validFrom"));
        Instant validUntil = parseTdate(validity.get("validUntil"));
        if (validFrom != null && now.plusSeconds(VALIDITY_SKEW_SECONDS).isBefore(validFrom)) {
            throw new VerificationException("Credential is not yet valid (validFrom " + validFrom + ")");
        }
        if (validUntil != null && now.minusSeconds(VALIDITY_SKEW_SECONDS).isAfter(validUntil)) {
            throw new VerificationException("Credential is expired (validUntil " + validUntil + ")");
        }
    }

    // --- Device signature (SessionTranscript binding) ----------------------

    private static void verifyDeviceSignature(CBORObject deviceSigned, CBORObject mso, String docType,
                                              String clientId, String nonce, byte[] encJwkThumbprint,
                                              String responseUri) throws VerificationException {
        CBORObject deviceAuth = require(deviceSigned, "deviceAuth", "deviceSigned missing deviceAuth");
        CBORObject deviceSignature = deviceAuth.get("deviceSignature");
        if (deviceSignature == null) {
            if (deviceAuth.get("deviceMac") != null) {
                throw new VerificationException("deviceMac is not supported; deviceSignature required");
            }
            throw new VerificationException("deviceAuth missing deviceSignature");
        }

        ECPublicKey deviceKey = deviceKey(mso);

        // DeviceNameSpacesBytes must be the verbatim bytes the wallet sent.
        CBORObject deviceNameSpaces = require(deviceSigned, "nameSpaces", "deviceSigned missing nameSpaces");
        byte[] deviceNameSpacesBytes = deviceNameSpaces.EncodeToBytes();

        byte[] sessionTranscript = SessionTranscript.openid4vpHandover(
                clientId, nonce, encJwkThumbprint, responseUri);
        byte[] deviceAuthBytes = SessionTranscript.deviceAuthenticationBytes(
                sessionTranscript, docType, deviceNameSpacesBytes);

        if (!CoseSign1Verifier.verifyDetached(deviceSignature, deviceAuthBytes, deviceKey)) {
            throw new VerificationException(
                    "deviceSignature does not verify against the reconstructed SessionTranscript");
        }
    }

    private static ECPublicKey deviceKey(CBORObject mso) throws VerificationException {
        try {
            CBORObject deviceKeyInfo = require(mso, "deviceKeyInfo", "MSO missing deviceKeyInfo");
            CBORObject coseKey = require(deviceKeyInfo, "deviceKey", "deviceKeyInfo missing deviceKey");
            // COSE_Key: 1=kty(2=EC2), -1=crv(1=P-256), -2=x, -3=y
            byte[] x = coseKey.get(CBORObject.FromObject(-2)).GetByteString();
            byte[] y = coseKey.get(CBORObject.FromObject(-3)).GetByteString();
            ECKey ecKey = new ECKey.Builder(Curve.P_256,
                    Base64URL.encode(x), Base64URL.encode(y)).build();
            return ecKey.toECPublicKey();
        } catch (VerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new VerificationException("Failed to read device key from MSO: " + e.getMessage());
        }
    }

    // --- Helpers ------------------------------------------------------------

    private static Instant parseTdate(CBORObject value) throws VerificationException {
        if (value == null) {
            return null;
        }
        try {
            String iso = value.isTagged() ? value.Untag().AsString() : value.AsString();
            return Instant.parse(iso);
        } catch (Exception e) {
            throw new VerificationException("Invalid validityInfo date: " + e.getMessage());
        }
    }

    /** Convert a CBOR element value to a plain Java value (mirrors mdoc.ts cborValueToJs). */
    private static Object cborToJava(CBORObject value) {
        if (value == null || value.isNull()) {
            return null;
        }
        if (value.isTagged()) {
            int tag = value.getMostOuterTag().ToInt32Unchecked();
            // tag 0 (datetime), tag 1004 (full-date) → ISO string
            if (tag == 0 || tag == 1004) {
                return value.Untag().AsString();
            }
            return cborToJava(value.Untag());
        }
        return switch (value.getType()) {
            case TextString -> value.AsString();
            case Boolean -> value.AsBoolean();
            case Integer -> value.AsInt64Value();
            case FloatingPoint -> value.AsDoubleValue();
            case ByteString -> value.GetByteString();
            case Array -> {
                java.util.List<Object> list = new java.util.ArrayList<>();
                for (int i = 0; i < value.size(); i++) {
                    list.add(cborToJava(value.get(i)));
                }
                yield list;
            }
            case Map -> {
                Map<String, Object> map = new LinkedHashMap<>();
                for (CBORObject k : value.getKeys()) {
                    map.put(k.AsString(), cborToJava(value.get(k)));
                }
                yield map;
            }
            default -> value.toString();
        };
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private static String stripPadding(String s) {
        int eq = s.indexOf('=');
        return eq >= 0 ? s.substring(0, eq) : s;
    }

    private static CBORObject require(CBORObject map, String key, String error)
            throws VerificationException {
        CBORObject v = map.get(key);
        if (v == null) {
            throw new VerificationException(error);
        }
        return v;
    }

    private static String getString(CBORObject map, String key) {
        CBORObject v = map.get(key);
        return v != null && v.getType() == CBORType.TextString ? v.AsString() : null;
    }
}
