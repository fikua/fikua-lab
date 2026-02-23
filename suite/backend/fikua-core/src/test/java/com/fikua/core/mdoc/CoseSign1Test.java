package com.fikua.core.mdoc;

import com.fikua.core.crypto.EcKeyManager;
import com.upokecenter.cbor.CBORObject;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CoseSign1Test {

    private static final EcKeyManager ISSUER_KEY = EcKeyManager.generate();

    // Dummy payload (CBOR-encoded MSO would go here)
    private static final byte[] PAYLOAD = CBORObject.FromObject("test-payload").EncodeToBytes();

    // Dummy DER certificate (not a real cert, but sufficient for structural tests)
    private static final byte[] DUMMY_CERT = new byte[]{0x30, 0x01, 0x00};

    @Test
    void sign_producesCoseSign1WithTag18() {
        byte[] result = CoseSign1.sign(PAYLOAD, ISSUER_KEY, List.of(DUMMY_CERT));

        CBORObject decoded = CBORObject.DecodeFromBytes(result);
        assertEquals(18, decoded.getMostOuterTag().ToInt32Checked(),
                "COSE_Sign1 must be tagged with tag 18");
    }

    @Test
    void sign_hasFourElements() {
        byte[] result = CoseSign1.sign(PAYLOAD, ISSUER_KEY, List.of(DUMMY_CERT));

        CBORObject decoded = CBORObject.DecodeFromBytes(result).Untag();
        assertEquals(4, decoded.size(),
                "COSE_Sign1 array must have 4 elements: protected, unprotected, payload, signature");
    }

    @Test
    void sign_protectedHeaderContainsAlgEs256() {
        byte[] result = CoseSign1.sign(PAYLOAD, ISSUER_KEY, List.of(DUMMY_CERT));

        CBORObject decoded = CBORObject.DecodeFromBytes(result).Untag();
        byte[] protectedBytes = decoded.get(0).GetByteString();
        CBORObject protectedHeader = CBORObject.DecodeFromBytes(protectedBytes);

        // alg label = 1, ES256 value = -7
        assertEquals(-7, protectedHeader.get(CBORObject.FromObject(1)).AsInt32(),
                "Protected header alg must be ES256 (-7)");
    }

    @Test
    void sign_signatureIs64Bytes() {
        byte[] result = CoseSign1.sign(PAYLOAD, ISSUER_KEY, List.of(DUMMY_CERT));

        CBORObject decoded = CBORObject.DecodeFromBytes(result).Untag();
        byte[] signature = decoded.get(3).GetByteString();

        assertEquals(64, signature.length,
                "P-256 ECDSA signature in P1363 format must be 64 bytes (32 r + 32 s)");
    }

    @Test
    void sign_unprotectedHeaderContainsX5chain() {
        byte[] result = CoseSign1.sign(PAYLOAD, ISSUER_KEY, List.of(DUMMY_CERT));

        CBORObject decoded = CBORObject.DecodeFromBytes(result).Untag();
        CBORObject unprotected = decoded.get(1);

        // x5chain label = 33
        assertNotNull(unprotected.get(CBORObject.FromObject(33)),
                "Unprotected header must contain x5chain (label 33)");
    }

    @Test
    void sign_singleCert_x5chainIsBstr() {
        byte[] result = CoseSign1.sign(PAYLOAD, ISSUER_KEY, List.of(DUMMY_CERT));

        CBORObject decoded = CBORObject.DecodeFromBytes(result).Untag();
        CBORObject x5chain = decoded.get(1).get(CBORObject.FromObject(33));

        // Single cert should be bstr, not array
        assertArrayEquals(DUMMY_CERT, x5chain.GetByteString(),
                "Single cert x5chain must be a bstr (not wrapped in array)");
    }

    @Test
    void sign_multipleCerts_x5chainIsArray() {
        byte[] cert2 = new byte[]{0x30, 0x02, 0x00, 0x00};
        byte[] result = CoseSign1.sign(PAYLOAD, ISSUER_KEY, List.of(DUMMY_CERT, cert2));

        CBORObject decoded = CBORObject.DecodeFromBytes(result).Untag();
        CBORObject x5chain = decoded.get(1).get(CBORObject.FromObject(33));

        assertEquals(2, x5chain.size(),
                "Multiple certs x5chain must be an array");
        assertArrayEquals(DUMMY_CERT, x5chain.get(0).GetByteString());
        assertArrayEquals(cert2, x5chain.get(1).GetByteString());
    }

    @Test
    void sign_payloadIsPreserved() {
        byte[] result = CoseSign1.sign(PAYLOAD, ISSUER_KEY, List.of(DUMMY_CERT));

        CBORObject decoded = CBORObject.DecodeFromBytes(result).Untag();
        byte[] embeddedPayload = decoded.get(2).GetByteString();

        assertArrayEquals(PAYLOAD, embeddedPayload,
                "COSE_Sign1 payload must match the input payload bytes");
    }
}
