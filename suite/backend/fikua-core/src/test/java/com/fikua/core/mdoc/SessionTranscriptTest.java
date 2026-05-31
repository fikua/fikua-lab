package com.fikua.core.mdoc;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.*;

class SessionTranscriptTest {

    private static final String CLIENT_ID = "x509_hash:abc123";
    private static final String NONCE = "request-nonce-xyz";
    private static final byte[] THUMBPRINT = new byte[32]; // 32 zero bytes
    private static final String RESPONSE_URI = "https://verifier.example.com/oid4vp/v1/response";

    @Test
    void sessionTranscript_hasNullNullHandoverShape() {
        byte[] st = SessionTranscript.openid4vpHandover(CLIENT_ID, NONCE, THUMBPRINT, RESPONSE_URI);
        CBORObject decoded = CBORObject.DecodeFromBytes(st);

        assertEquals(CBORType.Array, decoded.getType());
        assertEquals(3, decoded.size());
        assertTrue(decoded.get(0).isNull(), "DeviceEngagementBytes must be null");
        assertTrue(decoded.get(1).isNull(), "EReaderKeyBytes must be null");
    }

    @Test
    void handover_isIdentifierPlusSha256Hash() throws Exception {
        byte[] st = SessionTranscript.openid4vpHandover(CLIENT_ID, NONCE, THUMBPRINT, RESPONSE_URI);
        CBORObject handover = CBORObject.DecodeFromBytes(st).get(2);

        assertEquals(2, handover.size());
        assertEquals("OpenID4VPHandover", handover.get(0).AsString());

        byte[] hash = handover.get(1).GetByteString();
        assertEquals(32, hash.length, "Handover hash must be a 32-byte SHA-256");

        // Independently recompute sha256(CBOR([clientId, nonce, thumbprint, responseUri])).
        CBORObject info = CBORObject.NewArray();
        info.Add(CBORObject.FromObject(CLIENT_ID));
        info.Add(CBORObject.FromObject(NONCE));
        info.Add(CBORObject.FromObject(THUMBPRINT));
        info.Add(CBORObject.FromObject(RESPONSE_URI));
        byte[] expected = MessageDigest.getInstance("SHA-256").digest(info.EncodeToBytes());

        assertArrayEquals(expected, hash);
    }

    @Test
    void nullThumbprint_encodesNullThirdElement() throws Exception {
        byte[] st = SessionTranscript.openid4vpHandover(CLIENT_ID, NONCE, null, RESPONSE_URI);
        byte[] hash = CBORObject.DecodeFromBytes(st).get(2).get(1).GetByteString();

        CBORObject info = CBORObject.NewArray();
        info.Add(CBORObject.FromObject(CLIENT_ID));
        info.Add(CBORObject.FromObject(NONCE));
        info.Add(CBORObject.Null);
        info.Add(CBORObject.FromObject(RESPONSE_URI));
        byte[] expected = MessageDigest.getInstance("SHA-256").digest(info.EncodeToBytes());

        assertArrayEquals(expected, hash);
    }

    @Test
    void deterministic_sameInputsSameBytes() {
        byte[] a = SessionTranscript.openid4vpHandover(CLIENT_ID, NONCE, THUMBPRINT, RESPONSE_URI);
        byte[] b = SessionTranscript.openid4vpHandover(CLIENT_ID, NONCE, THUMBPRINT, RESPONSE_URI);
        assertArrayEquals(a, b);
    }

    @Test
    void differentNonce_changesHandoverHash() {
        byte[] a = SessionTranscript.openid4vpHandover(CLIENT_ID, "nonce-a", THUMBPRINT, RESPONSE_URI);
        byte[] b = SessionTranscript.openid4vpHandover(CLIENT_ID, "nonce-b", THUMBPRINT, RESPONSE_URI);
        assertFalse(java.util.Arrays.equals(a, b));
    }

    @Test
    void deviceAuthenticationBytes_isTag24OverFourElementArray() {
        byte[] st = SessionTranscript.openid4vpHandover(CLIENT_ID, NONCE, THUMBPRINT, RESPONSE_URI);
        byte[] emptyDeviceNameSpaces = CBORObject.FromObject(CBORObject.NewMap().EncodeToBytes())
                .WithTag(24).EncodeToBytes();

        byte[] dab = SessionTranscript.deviceAuthenticationBytes(st, "eu.europa.ec.eudi.pid.1",
                emptyDeviceNameSpaces);

        CBORObject tagged = CBORObject.DecodeFromBytes(dab);
        assertEquals(24, tagged.getMostOuterTag().ToInt32Checked(), "Must be tag 24");
        CBORObject inner = CBORObject.DecodeFromBytes(tagged.Untag().GetByteString());
        assertEquals(CBORType.Array, inner.getType());
        assertEquals(4, inner.size());
        assertEquals("DeviceAuthentication", inner.get(0).AsString());
        assertEquals("eu.europa.ec.eudi.pid.1", inner.get(2).AsString());
    }
}
