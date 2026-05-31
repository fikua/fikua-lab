package com.fikua.core.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;

import java.util.Map;

/**
 * Verifier response-encryption key (ECDH-ES, P-256) for OID4VP
 * {@code direct_post.jwt}. The public half is published in the Authorization
 * Request's {@code client_metadata.jwks}; the wallet encrypts its response to
 * it, and the private half decrypts the received JWE.
 *
 * <p>HAIP §5 mandates encrypted responses, so the verifier must advertise this
 * key plus {@code encrypted_response_enc_values_supported}.
 */
public final class ResponseEncryptionKey {

    /** JWE key-agreement algorithm advertised and required by HAIP. */
    public static final String ALG = "ECDH-ES";

    /** Content-encryption method advertised in encrypted_response_enc_values_supported. */
    public static final String ENC = "A128GCM";

    /**
     * Content-encryption methods advertised in
     * encrypted_response_enc_values_supported. HAIP §5 requires both A128GCM
     * and A256GCM. Decryption picks the method from the JWE {@code enc} header,
     * so either works regardless of order.
     */
    public static final java.util.List<String> ENC_VALUES_SUPPORTED =
            java.util.List.of("A128GCM", "A256GCM");

    private final ECKey ecKey;

    private ResponseEncryptionKey(ECKey ecKey) {
        this.ecKey = ecKey;
    }

    /** Generate a fresh P-256 ECDH-ES key with its SHA-256 thumbprint as kid. */
    public static ResponseEncryptionKey generate() {
        try {
            ECKey key = new ECKeyGenerator(Curve.P_256)
                    .keyUse(KeyUse.ENCRYPTION)
                    .algorithm(JWEAlgorithm.ECDH_ES)
                    .generate();
            String kid = key.computeThumbprint("SHA-256").toString();
            return new ResponseEncryptionKey(new ECKey.Builder(key).keyID(kid).build());
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to generate response encryption key", e);
        }
    }

    /** Key ID (SHA-256 thumbprint), matching the published JWK. */
    public String kid() {
        return ecKey.getKeyID();
    }

    /**
     * Public JWK as a plain map for embedding in client_metadata.jwks.keys.
     * Carries kid, use=enc, and alg=ECDH-ES; never the private key.
     */
    public Map<String, Object> publicJwk() {
        return ecKey.toPublicJWK().toJSONObject();
    }

    /**
     * Decrypt a compact JWE produced by the wallet for direct_post.jwt and
     * return its plaintext payload (the JSON carrying vp_token, state, etc.).
     */
    public String decrypt(String compactJwe) {
        try {
            JWEObject jwe = JWEObject.parse(compactJwe);
            jwe.decrypt(new ECDHDecrypter(ecKey));
            return jwe.getPayload().toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to decrypt direct_post.jwt response", e);
        }
    }
}
