package com.fikua.core.mdoc;

import com.fikua.core.crypto.EcKeyManager;
import com.upokecenter.cbor.CBORObject;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CoseSign1VerifierTest {

    private static final TestCerts.IssuerChain ISSUER = TestCerts.selfSignedIssuer("Test Issuer");
    private static final byte[] PAYLOAD = CBORObject.FromObject("test-payload").EncodeToBytes();

    private static byte[] leafDer() throws Exception {
        return ISSUER.leaf().getEncoded();
    }

    @Test
    void attachedPayload_roundTrips() throws Exception {
        byte[] signed = CoseSign1.sign(PAYLOAD, ISSUER.key(), List.of(leafDer()));
        CBORObject cose = CBORObject.DecodeFromBytes(signed);

        assertTrue(CoseSign1Verifier.verify(cose, ISSUER.key().toPublicKey()),
                "A freshly signed COSE_Sign1 must verify against the signer's public key");
    }

    @Test
    void leafCertificate_parsesFromX5chain() throws Exception {
        byte[] signed = CoseSign1.sign(PAYLOAD, ISSUER.key(), List.of(leafDer()));
        CBORObject cose = CBORObject.DecodeFromBytes(signed);

        var leaf = CoseSign1Verifier.leafCertificate(cose);
        assertArrayEquals(ISSUER.leaf().getEncoded(), leaf.getEncoded());
    }

    @Test
    void tamperedPayload_failsVerification() throws Exception {
        byte[] signed = CoseSign1.sign(PAYLOAD, ISSUER.key(), List.of(leafDer()));
        CBORObject cose = CBORObject.DecodeFromBytes(signed);

        // Replace the payload (element 2) with different bytes.
        CBORObject tampered = CBORObject.NewArray();
        tampered.Add(cose.get(0));
        tampered.Add(cose.get(1));
        tampered.Add(CBORObject.FromObject(CBORObject.FromObject("evil").EncodeToBytes()));
        tampered.Add(cose.get(3));

        assertFalse(CoseSign1Verifier.verify(tampered, ISSUER.key().toPublicKey()));
    }

    @Test
    void wrongKey_failsVerification() throws Exception {
        byte[] signed = CoseSign1.sign(PAYLOAD, ISSUER.key(), List.of(leafDer()));
        CBORObject cose = CBORObject.DecodeFromBytes(signed);

        EcKeyManager other = EcKeyManager.generate();
        assertFalse(CoseSign1Verifier.verify(cose, other.toPublicKey()));
    }

    @Test
    void detachedPayload_roundTrips() throws Exception {
        // Sign over a detached payload directly (mirrors deviceSignature).
        byte[] detached = CBORObject.FromObject("device-auth-bytes").EncodeToBytes();

        CBORObject protectedMap = CBORObject.NewMap();
        protectedMap.set(CBORObject.FromObject(1), CBORObject.FromObject(-7));
        byte[] protectedBytes = protectedMap.EncodeToBytes();

        CBORObject sigStructure = CBORObject.NewArray();
        sigStructure.Add("Signature1");
        sigStructure.Add(protectedBytes);
        sigStructure.Add(new byte[0]);
        sigStructure.Add(detached);
        byte[] sig = ISSUER.key().signRawBytes(sigStructure.EncodeToBytes());

        // COSE_Sign1 with null payload (detached).
        CBORObject cose = CBORObject.NewArray();
        cose.Add(CBORObject.FromObject(protectedBytes));
        cose.Add(CBORObject.NewMap());
        cose.Add(CBORObject.Null);
        cose.Add(CBORObject.FromObject(sig));

        assertTrue(CoseSign1Verifier.verifyDetached(cose, detached, ISSUER.key().toPublicKey()));
        assertFalse(CoseSign1Verifier.verifyDetached(cose,
                CBORObject.FromObject("other").EncodeToBytes(), ISSUER.key().toPublicKey()),
                "Verifying against a different detached payload must fail");
    }
}
