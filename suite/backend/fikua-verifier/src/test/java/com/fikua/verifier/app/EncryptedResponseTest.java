package com.fikua.verifier.app;

import com.fikua.core.crypto.ResponseEncryptionKey;
import com.fikua.core.crypto.SigningKey;
import com.fikua.core.profile.ProfileConfig;
import com.fikua.core.profile.ProfilePresets;
import com.fikua.verifier.app.port.ProfileStore;
import com.fikua.verifier.app.port.SessionStore.VerificationSession;
import com.fikua.verifier.infra.InMemorySessionStore;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * direct_post.jwt / HAIP §5: the verifier must publish a response-encryption
 * key in client_metadata and decrypt the wallet's JWE response.
 */
class EncryptedResponseTest {

    /** ProfileStore stub returning the HAIP verifier profile (direct_post.jwt). */
    private static final ProfileStore HAIP_PROFILE = () ->
            new ProfileStore.ActiveProfile("haip", ProfilePresets.haipVerifier());

    private VerificationService newService(Path certsDir, ResponseEncryptionKey encKey) {
        SigningKey key = com.fikua.verifier.infra.PemKeyLoader.loadOrGenerate(certsDir.toString());
        // PemKeyLoader lives in com.fikua.verifier.infra
        return new VerificationService(
                key, encKey, new InMemorySessionStore(), HAIP_PROFILE,
                "https://verifier.example.test");
    }

    @Test
    void haipRequest_carriesClientMetadataForEncryption(@TempDir Path certsDir) throws Exception {
        var encKey = ResponseEncryptionKey.generate();
        VerificationService service = newService(certsDir, encKey);

        VerificationSession session =
                service.createSession("urn:eudi:pid:1", List.of("given_name"));

        var jwt = com.nimbusds.jwt.SignedJWT.parse(session.requestJwt());
        @SuppressWarnings("unchecked")
        Map<String, Object> cm =
                (Map<String, Object>) jwt.getJWTClaimsSet().getClaim("client_metadata");

        assertNotNull(cm, "HAIP request must include client_metadata");
        assertNotNull(cm.get("vp_formats"), "client_metadata must include vp_formats");
        assertNotNull(cm.get("jwks"), "client_metadata must include jwks for encryption");
        assertEquals(List.of(ResponseEncryptionKey.ENC),
                cm.get("encrypted_response_enc_values_supported"));
    }

    @Test
    void encryptedResponse_decryptsToVpTokenAndState(@TempDir Path certsDir) throws Exception {
        var encKey = ResponseEncryptionKey.generate();
        VerificationService service = newService(certsDir, encKey);

        VerificationSession session =
                service.createSession("urn:eudi:pid:1", List.of("given_name"));

        // Encrypt a response to the published public key, as a wallet would.
        ECKey publicJwk = ECKey.parse(
                new com.fasterxml.jackson.databind.ObjectMapper()
                        .writeValueAsString(encKey.publicJwk()));

        // Minimal SD-JWT-shaped vp_token (issuer JWT~ with no disclosures).
        String vpToken = "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJ1cm46ZXVkaTpwaWQ6MSJ9.sig~";
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("vp_token", vpToken)
                .claim("state", session.state())
                .build();

        EncryptedJWT jwe = new EncryptedJWT(
                new JWEHeader(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128GCM), claims);
        jwe.encrypt(new ECDHEncrypter(publicJwk));
        String compact = jwe.serialize();

        var outcome = service.handleEncryptedResponse(compact);

        assertEquals(session.state(), outcome.state(), "state recovered from JWE");
        assertNotNull(outcome.result());
        assertEquals("success", outcome.result().status(),
                "single-disclosureless SD-JWT should parse and verify as success");
    }
}
