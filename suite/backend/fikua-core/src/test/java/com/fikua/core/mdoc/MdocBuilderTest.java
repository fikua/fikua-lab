package com.fikua.core.mdoc;

import com.fikua.core.crypto.EcKeyManager;
import com.nimbusds.jose.jwk.ECKey;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MdocBuilderTest {

    private static final EcKeyManager ISSUER_KEY = EcKeyManager.generate();
    private static final ECKey WALLET_KEY = EcKeyManager.generate().publicKey();
    private static final String DOC_TYPE = "eu.europa.ec.eudi.pid.1";
    private static final String NAMESPACE = "eu.europa.ec.eudi.pid.1";

    private MdocBuilder defaultBuilder() {
        return new MdocBuilder(ISSUER_KEY)
                .docType(DOC_TYPE)
                .namespace(NAMESPACE)
                .element("given_name", "Jan")
                .element("family_name", "Kowalski")
                .deviceKey(WALLET_KEY);
    }

    /** Extract the MSO from the issuerAuth COSE_Sign1 payload (tag 24 wrapped). */
    private CBORObject extractMso(CBORObject issuerSigned) {
        CBORObject issuerAuth = issuerSigned.get("issuerAuth");
        // Payload is element [2], which is tag 24(bstr) — unwrap tag then decode inner bstr
        byte[] payloadBytes = issuerAuth.get(2).GetByteString();
        CBORObject taggedMso = CBORObject.DecodeFromBytes(payloadBytes);
        assertEquals(24, taggedMso.getMostOuterTag().ToInt32Checked(),
                "COSE_Sign1 payload must be tag 24 (MobileSecurityObjectBytes)");
        byte[] msoBytes = taggedMso.Untag().GetByteString();
        return CBORObject.DecodeFromBytes(msoBytes);
    }

    @Test
    void build_producesIssuerSignedStructure() {
        MdocDocument doc = defaultBuilder().build();

        byte[] cbor = doc.cborBytes();
        assertNotNull(cbor);
        assertTrue(cbor.length > 0, "CBOR bytes must not be empty");

        // Per OID4VCI A.2.4: credential is the IssuerSigned structure, not a Document
        CBORObject issuerSigned = CBORObject.DecodeFromBytes(cbor);
        assertNotNull(issuerSigned.get("issuerAuth"),
                "IssuerSigned must contain issuerAuth");
        assertNotNull(issuerSigned.get("nameSpaces"),
                "IssuerSigned must contain nameSpaces");
        assertNull(issuerSigned.get("docType"),
                "IssuerSigned must NOT contain docType (that's the Document wrapper)");
    }

    @Test
    void build_hasNameSpacesWithElements() {
        MdocDocument doc = defaultBuilder().build();

        CBORObject issuerSigned = CBORObject.DecodeFromBytes(doc.cborBytes());
        CBORObject nameSpaces = issuerSigned.get("nameSpaces");
        assertNotNull(nameSpaces, "IssuerSigned must have nameSpaces");

        CBORObject nsItems = nameSpaces.get(NAMESPACE);
        assertNotNull(nsItems, "nameSpaces must contain the namespace");
        assertEquals(2, nsItems.size(),
                "Namespace must have 2 elements (given_name, family_name)");

        // Each item should be tag 24 (encoded-cbor)
        for (int i = 0; i < nsItems.size(); i++) {
            assertEquals(24, nsItems.get(i).getMostOuterTag().ToInt32Checked(),
                    "IssuerSignedItem must be wrapped in CBOR tag 24");
        }
    }

    @Test
    void build_issuerAuthIsCoseSign1() {
        MdocDocument doc = defaultBuilder().build();

        CBORObject issuerSigned = CBORObject.DecodeFromBytes(doc.cborBytes());
        CBORObject issuerAuth = issuerSigned.get("issuerAuth");
        assertNotNull(issuerAuth, "IssuerSigned must have issuerAuth");

        // issuerAuth is an untagged COSE_Sign1 array (no tag 18 when embedded in map)
        assertEquals(CBORType.Array, issuerAuth.getType(),
                "issuerAuth must be a CBOR array (untagged COSE_Sign1)");
        assertFalse(issuerAuth.isTagged(),
                "issuerAuth must NOT be tagged with 18 when inside IssuerSigned map");
        assertEquals(4, issuerAuth.size(),
                "COSE_Sign1 must have 4 elements");
    }

    @Test
    void build_issuerAuthPayloadIsTagged24Mso() {
        MdocDocument doc = defaultBuilder().build();

        CBORObject issuerSigned = CBORObject.DecodeFromBytes(doc.cborBytes());
        CBORObject issuerAuth = issuerSigned.get("issuerAuth");

        // Payload (element [2]) must decode to tag 24(bstr) per ISO 18013-5
        byte[] payloadBytes = issuerAuth.get(2).GetByteString();
        CBORObject taggedMso = CBORObject.DecodeFromBytes(payloadBytes);
        assertEquals(24, taggedMso.getMostOuterTag().ToInt32Checked(),
                "COSE_Sign1 payload must be MobileSecurityObjectBytes = #6.24(bstr .cbor MSO)");
    }

    @Test
    void build_issuerAuthFirstField() {
        MdocDocument doc = defaultBuilder().build();

        CBORObject issuerSigned = CBORObject.DecodeFromBytes(doc.cborBytes());
        var keys = issuerSigned.getKeys();
        assertEquals("issuerAuth", keys.iterator().next().AsString(),
                "issuerAuth must be the first field in IssuerSigned");
    }

    @Test
    void build_withDeviceKey_includesDeviceKeyInfo() {
        MdocDocument doc = defaultBuilder().build();

        CBORObject issuerSigned = CBORObject.DecodeFromBytes(doc.cborBytes());
        CBORObject mso = extractMso(issuerSigned);

        CBORObject deviceKeyInfo = mso.get("deviceKeyInfo");
        assertNotNull(deviceKeyInfo, "MSO must contain deviceKeyInfo when deviceKey is set");

        CBORObject deviceKey = deviceKeyInfo.get("deviceKey");
        assertNotNull(deviceKey, "deviceKeyInfo must contain deviceKey");

        // COSE_Key: kty=2 (EC2), crv=1 (P-256)
        assertEquals(2, deviceKey.get(CBORObject.FromObject(1)).AsInt32(),
                "deviceKey kty must be EC2 (2)");
        assertEquals(1, deviceKey.get(CBORObject.FromObject(-1)).AsInt32(),
                "deviceKey crv must be P-256 (1)");
        assertNotNull(deviceKey.get(CBORObject.FromObject(-2)),
                "deviceKey must have x coordinate");
        assertNotNull(deviceKey.get(CBORObject.FromObject(-3)),
                "deviceKey must have y coordinate");
    }

    @Test
    void build_msoContainsValidityInfo() {
        MdocDocument doc = defaultBuilder().build();

        CBORObject issuerSigned = CBORObject.DecodeFromBytes(doc.cborBytes());
        CBORObject mso = extractMso(issuerSigned);

        CBORObject validity = mso.get("validityInfo");
        assertNotNull(validity, "MSO must contain validityInfo");
        assertNotNull(validity.get("signed"), "validityInfo must have signed");
        assertNotNull(validity.get("validFrom"), "validityInfo must have validFrom");
        assertNotNull(validity.get("validUntil"), "validityInfo must have validUntil");
    }

    @Test
    void build_msoContainsValueDigests() {
        MdocDocument doc = defaultBuilder().build();

        CBORObject issuerSigned = CBORObject.DecodeFromBytes(doc.cborBytes());
        CBORObject mso = extractMso(issuerSigned);

        assertEquals("1.0", mso.get("version").AsString());
        assertEquals("SHA-256", mso.get("digestAlgorithm").AsString());

        CBORObject valueDigests = mso.get("valueDigests");
        assertNotNull(valueDigests, "MSO must contain valueDigests");

        CBORObject nsDigests = valueDigests.get(NAMESPACE);
        assertNotNull(nsDigests, "valueDigests must contain the namespace");
        assertEquals(2, nsDigests.getKeys().size(),
                "Namespace must have 2 digest entries");
    }

    @Test
    void toBase64Url_returnsValidString() {
        MdocDocument doc = defaultBuilder().build();
        String base64url = doc.toBase64Url();

        assertNotNull(base64url);
        assertFalse(base64url.isEmpty());
        assertFalse(base64url.contains("+"), "Base64url must not contain '+'");
        assertFalse(base64url.contains("/"), "Base64url must not contain '/'");
        assertFalse(base64url.contains("="), "Base64url must not contain padding '='");
    }

    @Test
    void build_withoutDocType_throws() {
        assertThrows(IllegalStateException.class, () ->
                new MdocBuilder(ISSUER_KEY)
                        .namespace(NAMESPACE)
                        .element("given_name", "Jan")
                        .build(),
                "Building without docType must throw IllegalStateException"
        );
    }

    @Test
    void build_withoutNamespace_throws() {
        assertThrows(IllegalStateException.class, () ->
                new MdocBuilder(ISSUER_KEY)
                        .docType(DOC_TYPE)
                        .build(),
                "Building without any namespace/elements must throw IllegalStateException"
        );
    }

    @Test
    void element_beforeNamespace_throws() {
        assertThrows(IllegalStateException.class, () ->
                new MdocBuilder(ISSUER_KEY)
                        .docType(DOC_TYPE)
                        .element("given_name", "Jan"),
                "Calling element() before namespace() must throw IllegalStateException"
        );
    }
}
