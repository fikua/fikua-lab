package com.fikua.core.mdoc;

import com.fikua.core.crypto.EcKeyManager;
import com.upokecenter.cbor.CBORObject;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class MdocDeviceResponseVerifierTest {

    private static final String DOC_TYPE = "eu.europa.ec.eudi.pid.1";
    private static final String CLIENT_ID = "x509_hash:abc123";
    private static final String NONCE = "request-nonce-xyz";
    private static final String RESPONSE_URI = "https://verifier.example.com/oid4vp/v1/response";
    private static final byte[] THUMBPRINT = sha256Bytes("enc-key");

    private static byte[] sha256Bytes(String s) {
        try {
            return java.security.MessageDigest.getInstance("SHA-256").digest(s.getBytes());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** Build a base64url DeviceResponse with a correct deviceSignature over the given transcript inputs. */
    private static String buildDeviceResponse(TestCerts.IssuerChain issuer, EcKeyManager deviceKey,
                                              String clientId, String nonce, byte[] thumbprint,
                                              String responseUri, long validityDays) throws Exception {
        // 1. IssuerSigned via MdocBuilder.
        MdocBuilder builder = new MdocBuilder(issuer.key())
                .docType(DOC_TYPE)
                .namespace(DOC_TYPE)
                .element("given_name", "Jan")
                .element("family_name", "Kowalski")
                .deviceKey(deviceKey.publicKey())
                .x5cChain(issuer.key().x5cChain())
                .validityDays(validityDays);
        CBORObject issuerSigned = CBORObject.DecodeFromBytes(builder.build().cborBytes());

        // 2. deviceSigned.nameSpaces = #6.24(bstr .cbor {}) (empty).
        byte[] deviceNameSpacesBytes = CBORObject.FromObject(CBORObject.NewMap().EncodeToBytes())
                .WithTag(24).EncodeToBytes();

        // 3. Build DeviceAuthenticationBytes and sign it with the device key.
        byte[] st = SessionTranscript.openid4vpHandover(clientId, nonce, thumbprint, responseUri);
        byte[] deviceAuthBytes = SessionTranscript.deviceAuthenticationBytes(
                st, DOC_TYPE, deviceNameSpacesBytes);

        CBORObject protectedMap = CBORObject.NewMap();
        protectedMap.set(CBORObject.FromObject(1), CBORObject.FromObject(-7));
        byte[] protectedBytes = protectedMap.EncodeToBytes();

        CBORObject sigStructure = CBORObject.NewArray();
        sigStructure.Add("Signature1");
        sigStructure.Add(protectedBytes);
        sigStructure.Add(new byte[0]);
        sigStructure.Add(deviceAuthBytes);
        byte[] sig = deviceKey.signRawBytes(sigStructure.EncodeToBytes());

        // deviceSignature COSE_Sign1 with detached (null) payload.
        CBORObject deviceSignature = CBORObject.NewArray();
        deviceSignature.Add(CBORObject.FromObject(protectedBytes));
        deviceSignature.Add(CBORObject.NewMap());
        deviceSignature.Add(CBORObject.Null);
        deviceSignature.Add(CBORObject.FromObject(sig));

        CBORObject deviceAuth = CBORObject.NewMap();
        deviceAuth.set(CBORObject.FromObject("deviceSignature"), deviceSignature);

        CBORObject deviceSigned = CBORObject.NewMap();
        deviceSigned.set(CBORObject.FromObject("nameSpaces"),
                CBORObject.DecodeFromBytes(deviceNameSpacesBytes));
        deviceSigned.set(CBORObject.FromObject("deviceAuth"), deviceAuth);

        // 4. Document + DeviceResponse.
        CBORObject document = CBORObject.NewMap();
        document.set(CBORObject.FromObject("docType"), CBORObject.FromObject(DOC_TYPE));
        document.set(CBORObject.FromObject("issuerSigned"), issuerSigned);
        document.set(CBORObject.FromObject("deviceSigned"), deviceSigned);

        CBORObject documents = CBORObject.NewArray();
        documents.Add(document);

        CBORObject deviceResponse = CBORObject.NewMap();
        deviceResponse.set(CBORObject.FromObject("version"), CBORObject.FromObject("1.0"));
        deviceResponse.set(CBORObject.FromObject("documents"), documents);
        deviceResponse.set(CBORObject.FromObject("status"), CBORObject.FromObject(0));

        return Base64.getUrlEncoder().withoutPadding().encodeToString(deviceResponse.EncodeToBytes());
    }

    @Test
    void happyPath_verifiesAndReturnsClaims() throws Exception {
        TestCerts.IssuerChain issuer = TestCerts.selfSignedIssuer("Test Issuer");
        EcKeyManager deviceKey = EcKeyManager.generate();
        String dr = buildDeviceResponse(issuer, deviceKey, CLIENT_ID, NONCE, THUMBPRINT, RESPONSE_URI, 365);

        Map<String, Object> claims = MdocDeviceResponseVerifier.verify(
                dr, DOC_TYPE, CLIENT_ID, NONCE, THUMBPRINT, RESPONSE_URI, null);

        assertEquals("Jan", claims.get("given_name"));
        assertEquals("Kowalski", claims.get("family_name"));
    }

    /**
     * Interop regression: ISO 18013-5 §9.1.2.5 hashes the *tagged*
     * IssuerSignedItemBytes (#6.24(...)), not the inner untagged bytes. This
     * asserts the MSO digest independently of the builder, so a verifier that
     * hashes the wrong bytes (as ours did) fails here even when builder and
     * verifier agree with each other.
     */
    @Test
    void msoDigest_isOverTaggedIssuerSignedItemBytes() throws Exception {
        TestCerts.IssuerChain issuer = TestCerts.selfSignedIssuer("Test Issuer");
        EcKeyManager deviceKey = EcKeyManager.generate();
        String dr = buildDeviceResponse(issuer, deviceKey, CLIENT_ID, NONCE, THUMBPRINT, RESPONSE_URI, 365);

        CBORObject deviceResponse = CBORObject.DecodeFromBytes(Base64.getUrlDecoder().decode(dr));
        CBORObject issuerSigned = deviceResponse.get("documents").get(0).get("issuerSigned");
        CBORObject nameSpaces = issuerSigned.get("nameSpaces");
        CBORObject items = nameSpaces.get(nameSpaces.getKeys().iterator().next());

        // MSO.valueDigests for the namespace.
        CBORObject issuerAuth = issuerSigned.get("issuerAuth");
        CBORObject mso = CBORObject.DecodeFromBytes(
                CBORObject.DecodeFromBytes(issuerAuth.get(2).GetByteString()).Untag().GetByteString());
        CBORObject nsDigests = mso.get("valueDigests").get(nameSpaces.getKeys().iterator().next());

        CBORObject tagged = items.get(0);
        int digestId = CBORObject.DecodeFromBytes(tagged.Untag().GetByteString()).get("digestID").AsInt32();
        byte[] expected = nsDigests.get(CBORObject.FromObject(digestId)).GetByteString();
        byte[] overTagged = java.security.MessageDigest.getInstance("SHA-256")
                .digest(tagged.EncodeToBytes());

        assertArrayEquals(expected, overTagged,
                "MSO digest must be SHA-256 over the tagged IssuerSignedItemBytes");
    }

    @Test
    void caSignedChain_verifiesAgainstAnchor() throws Exception {
        TestCerts.Ca ca = TestCerts.selfSignedCa("Test Root CA");
        TestCerts.IssuerChain issuer = TestCerts.issuerSignedBy(ca, "Test Issuer");
        EcKeyManager deviceKey = EcKeyManager.generate();
        String dr = buildDeviceResponse(issuer, deviceKey, CLIENT_ID, NONCE, THUMBPRINT, RESPONSE_URI, 365);

        // x5c is [leaf] only; pin the CA as the trust anchor.
        Map<String, Object> claims = MdocDeviceResponseVerifier.verify(
                dr, DOC_TYPE, CLIENT_ID, NONCE, THUMBPRINT, RESPONSE_URI, ca.cert());
        assertEquals("Jan", claims.get("given_name"));
    }

    @Test
    void wrongSessionTranscript_isRejected() throws Exception {
        TestCerts.IssuerChain issuer = TestCerts.selfSignedIssuer("Test Issuer");
        EcKeyManager deviceKey = EcKeyManager.generate();
        // deviceSignature built over a DIFFERENT nonce than the verifier will use.
        String dr = buildDeviceResponse(issuer, deviceKey, CLIENT_ID, "WRONG-NONCE", THUMBPRINT, RESPONSE_URI, 365);

        assertThrows(MdocDeviceResponseVerifier.VerificationException.class, () ->
                MdocDeviceResponseVerifier.verify(dr, DOC_TYPE, CLIENT_ID, NONCE, THUMBPRINT, RESPONSE_URI, null));
    }

    @Test
    void wrongClientId_isRejected() throws Exception {
        TestCerts.IssuerChain issuer = TestCerts.selfSignedIssuer("Test Issuer");
        EcKeyManager deviceKey = EcKeyManager.generate();
        String dr = buildDeviceResponse(issuer, deviceKey, "x509_hash:OTHER", NONCE, THUMBPRINT, RESPONSE_URI, 365);

        assertThrows(MdocDeviceResponseVerifier.VerificationException.class, () ->
                MdocDeviceResponseVerifier.verify(dr, DOC_TYPE, CLIENT_ID, NONCE, THUMBPRINT, RESPONSE_URI, null));
    }

    @Test
    void wrongDocType_isRejected() throws Exception {
        TestCerts.IssuerChain issuer = TestCerts.selfSignedIssuer("Test Issuer");
        EcKeyManager deviceKey = EcKeyManager.generate();
        String dr = buildDeviceResponse(issuer, deviceKey, CLIENT_ID, NONCE, THUMBPRINT, RESPONSE_URI, 365);

        assertThrows(MdocDeviceResponseVerifier.VerificationException.class, () ->
                MdocDeviceResponseVerifier.verify(dr, "org.iso.18013.5.1.mDL", CLIENT_ID, NONCE, THUMBPRINT, RESPONSE_URI, null));
    }

    @Test
    void expiredValidity_isRejected() throws Exception {
        TestCerts.IssuerChain issuer = TestCerts.selfSignedIssuer("Test Issuer");
        EcKeyManager deviceKey = EcKeyManager.generate();
        // validityDays = -1 ⇒ validUntil in the past.
        String dr = buildDeviceResponse(issuer, deviceKey, CLIENT_ID, NONCE, THUMBPRINT, RESPONSE_URI, -1);

        assertThrows(MdocDeviceResponseVerifier.VerificationException.class, () ->
                MdocDeviceResponseVerifier.verify(dr, DOC_TYPE, CLIENT_ID, NONCE, THUMBPRINT, RESPONSE_URI, null));
    }

    @Test
    void tamperedClaim_isRejected() throws Exception {
        TestCerts.IssuerChain issuer = TestCerts.selfSignedIssuer("Test Issuer");
        EcKeyManager deviceKey = EcKeyManager.generate();
        String dr = buildDeviceResponse(issuer, deviceKey, CLIENT_ID, NONCE, THUMBPRINT, RESPONSE_URI, 365);

        // Decode, mutate an elementValue inside the first IssuerSignedItem, re-encode.
        CBORObject deviceResponse = CBORObject.DecodeFromBytes(
                Base64.getUrlDecoder().decode(dr));
        CBORObject nameSpaces = deviceResponse.get("documents").get(0)
                .get("issuerSigned").get("nameSpaces");
        CBORObject items = nameSpaces.get(nameSpaces.getKeys().iterator().next());
        CBORObject taggedItem = items.get(0);
        CBORObject item = CBORObject.DecodeFromBytes(taggedItem.Untag().GetByteString());
        item.set(CBORObject.FromObject("elementValue"), CBORObject.FromObject("HACKED"));
        items.set(0, CBORObject.FromObject(item.EncodeToBytes()).WithTag(24));

        String tampered = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(deviceResponse.EncodeToBytes());

        assertThrows(MdocDeviceResponseVerifier.VerificationException.class, () ->
                MdocDeviceResponseVerifier.verify(tampered, DOC_TYPE, CLIENT_ID, NONCE, THUMBPRINT, RESPONSE_URI, null));
    }

    @Test
    void badIssuerSignature_isRejected() throws Exception {
        TestCerts.IssuerChain issuer = TestCerts.selfSignedIssuer("Test Issuer");
        EcKeyManager deviceKey = EcKeyManager.generate();
        String dr = buildDeviceResponse(issuer, deviceKey, CLIENT_ID, NONCE, THUMBPRINT, RESPONSE_URI, 365);

        // Flip a byte in the issuerAuth signature.
        CBORObject deviceResponse = CBORObject.DecodeFromBytes(Base64.getUrlDecoder().decode(dr));
        CBORObject issuerAuth = deviceResponse.get("documents").get(0).get("issuerSigned").get("issuerAuth");
        byte[] sig = issuerAuth.get(3).GetByteString();
        sig[0] ^= 0x01;
        issuerAuth.set(3, CBORObject.FromObject(sig));

        String broken = Base64.getUrlEncoder().withoutPadding().encodeToString(deviceResponse.EncodeToBytes());

        assertThrows(MdocDeviceResponseVerifier.VerificationException.class, () ->
                MdocDeviceResponseVerifier.verify(broken, DOC_TYPE, CLIENT_ID, NONCE, THUMBPRINT, RESPONSE_URI, null));
    }
}
