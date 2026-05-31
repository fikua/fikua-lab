package com.fikua.core.mdoc;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import java.io.ByteArrayInputStream;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * Verifies COSE_Sign1 structures per RFC 9052 §4.4 — the verify-side companion
 * to {@link CoseSign1}. Used for mso_mdoc {@code issuerAuth} (attached payload)
 * and {@code deviceSignature} (detached payload).
 *
 * <p>The Sig_structure rebuilt here matches {@link CoseSign1#sign}:
 * {@code ["Signature1", protected_bytes, h'' (empty external_aad), payload]},
 * signed with ES256 in P1363 format (r || s, 64 bytes for P-256).
 */
public final class CoseSign1Verifier {

    private static final int COSE_ALG_ES256 = -7;
    private static final int COSE_HEADER_ALG = 1;
    private static final int COSE_HEADER_X5CHAIN = 33;

    private CoseSign1Verifier() {}

    /**
     * Verify an attached-payload COSE_Sign1 (e.g. issuerAuth). The payload is
     * read from element 2 of the array.
     */
    public static boolean verify(CBORObject coseSign1, ECPublicKey key) {
        byte[] payload = coseSign1.get(2).GetByteString();
        return verifyDetached(coseSign1, payload, key);
    }

    /**
     * Verify a COSE_Sign1 whose payload is detached (element 2 is null), against
     * the externally supplied {@code detachedPayload} (e.g. deviceSignature over
     * DeviceAuthenticationBytes).
     */
    public static boolean verifyDetached(CBORObject coseSign1, byte[] detachedPayload, ECPublicKey key) {
        if (coseSign1.getType() != CBORType.Array || coseSign1.size() != 4) {
            return false;
        }

        byte[] protectedBytes = coseSign1.get(0).GetByteString();

        // The protected header must declare alg ES256 (-7).
        CBORObject protectedHeader = CBORObject.DecodeFromBytes(protectedBytes);
        CBORObject alg = protectedHeader.get(CBORObject.FromObject(COSE_HEADER_ALG));
        if (alg == null || alg.AsInt32() != COSE_ALG_ES256) {
            return false;
        }

        byte[] signature = coseSign1.get(3).GetByteString();

        // Sig_structure = ["Signature1", protected_bytes, h'' (external_aad), payload]
        CBORObject sigStructure = CBORObject.NewArray();
        sigStructure.Add("Signature1");
        sigStructure.Add(protectedBytes);
        sigStructure.Add(new byte[0]);
        sigStructure.Add(detachedPayload);
        byte[] toBeSigned = sigStructure.EncodeToBytes();

        return verifyEs256(toBeSigned, signature, key);
    }

    /**
     * Extract the leaf X.509 certificate from the unprotected header's x5chain
     * (label 33). A single cert is a bstr; multiple is an array of bstr (leaf
     * first), mirroring {@link CoseSign1#sign}.
     */
    public static X509Certificate leafCertificate(CBORObject coseSign1) {
        List<X509Certificate> chain = certChain(coseSign1);
        if (chain.isEmpty()) {
            throw new IllegalArgumentException("COSE_Sign1 has no x5chain (label 33)");
        }
        return chain.get(0);
    }

    /** Full x5chain (leaf first) from the unprotected header (label 33). */
    public static List<X509Certificate> certChain(CBORObject coseSign1) {
        CBORObject unprotected = coseSign1.get(1);
        CBORObject x5chain = unprotected.get(CBORObject.FromObject(COSE_HEADER_X5CHAIN));
        if (x5chain == null) {
            return List.of();
        }
        List<X509Certificate> chain = new ArrayList<>();
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            if (x5chain.getType() == CBORType.ByteString) {
                chain.add(parseCert(cf, x5chain.GetByteString()));
            } else if (x5chain.getType() == CBORType.Array) {
                for (int i = 0; i < x5chain.size(); i++) {
                    chain.add(parseCert(cf, x5chain.get(i).GetByteString()));
                }
            } else {
                throw new IllegalArgumentException("Unexpected x5chain CBOR type: " + x5chain.getType());
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse x5chain certificate: " + e.getMessage(), e);
        }
        return chain;
    }

    private static X509Certificate parseCert(CertificateFactory cf, byte[] der) throws Exception {
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
    }

    private static boolean verifyEs256(byte[] toBeSigned, byte[] sig64, ECPublicKey key) {
        try {
            Signature sig = Signature.getInstance("SHA256withECDSAinP1363Format");
            sig.initVerify(key);
            sig.update(toBeSigned);
            return sig.verify(sig64);
        } catch (Exception e) {
            return false;
        }
    }
}
