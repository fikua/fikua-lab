package com.fikua.core.mdoc;

import com.fikua.core.crypto.SigningKey;
import com.upokecenter.cbor.CBORObject;

import java.util.List;

/**
 * Builds COSE_Sign1 structures per RFC 9052 §4.4.
 * Used for mso_mdoc issuerAuth signing.
 *
 * COSE_Sign1 = [
 *   protected   : bstr,   // CBOR-serialized {1: -7} (alg: ES256)
 *   unprotected : map,    // {33: x5chain}
 *   payload     : bstr,   // CBOR-serialized MSO
 *   signature   : bstr    // ECDSA(Sig_structure)
 * ]
 */
public final class CoseSign1 {

    // COSE algorithm identifier: ES256 = -7
    static final int COSE_ALG_ES256 = -7;
    // COSE header labels
    static final int COSE_HEADER_ALG = 1;
    static final int COSE_HEADER_X5CHAIN = 33;

    private CoseSign1() {}

    /**
     * Build and sign a COSE_Sign1 message.
     *
     * @param payload     CBOR-serialized payload bytes (e.g. MobileSecurityObject)
     * @param issuerKey   signing key (EC P-256 / ES256)
     * @param x5cDerChain list of DER-encoded X.509 certificates (leaf first)
     * @return CBOR-serialized COSE_Sign1 (tagged with tag 18) as byte array
     */
    public static byte[] sign(byte[] payload, SigningKey issuerKey, List<byte[]> x5cDerChain) {
        // Protected header: {1: -7} (alg: ES256)
        CBORObject protectedMap = CBORObject.NewMap();
        protectedMap.set(CBORObject.FromObject(COSE_HEADER_ALG),
                CBORObject.FromObject(COSE_ALG_ES256));
        byte[] protectedBytes = protectedMap.EncodeToBytes();

        // Unprotected header: {33: <x5chain>}
        CBORObject unprotectedMap = CBORObject.NewMap();
        if (x5cDerChain != null && !x5cDerChain.isEmpty()) {
            if (x5cDerChain.size() == 1) {
                // Single cert: bstr (not array)
                unprotectedMap.set(CBORObject.FromObject(COSE_HEADER_X5CHAIN),
                        CBORObject.FromObject(x5cDerChain.getFirst()));
            } else {
                CBORObject certArray = CBORObject.NewArray();
                for (byte[] cert : x5cDerChain) {
                    certArray.Add(CBORObject.FromObject(cert));
                }
                unprotectedMap.set(CBORObject.FromObject(COSE_HEADER_X5CHAIN), certArray);
            }
        }

        // Sig_structure = ["Signature1", protected_bytes, external_aad (empty), payload]
        CBORObject sigStructure = CBORObject.NewArray();
        sigStructure.Add("Signature1");
        sigStructure.Add(protectedBytes);
        sigStructure.Add(new byte[0]);
        sigStructure.Add(payload);
        byte[] toBeSigned = sigStructure.EncodeToBytes();

        // Sign with ECDSA-SHA256 (r || s, 64 bytes for P-256)
        byte[] signature = issuerKey.signRawBytes(toBeSigned);

        // COSE_Sign1 = [protected_bytes, unprotected, payload, signature]
        CBORObject coseSign1 = CBORObject.NewArray();
        coseSign1.Add(CBORObject.FromObject(protectedBytes));
        coseSign1.Add(unprotectedMap);
        coseSign1.Add(CBORObject.FromObject(payload));
        coseSign1.Add(CBORObject.FromObject(signature));

        // Tag 18 = COSE_Sign1
        return coseSign1.WithTag(18).EncodeToBytes();
    }
}
