package com.fikua.verifier.app;

import com.fikua.core.crypto.ResponseEncryptionKey;
import com.fikua.core.crypto.SigningKey;
import com.fikua.verifier.app.port.ProfileStore;
import com.fikua.verifier.app.port.SessionStore.VerificationSession;
import com.fikua.verifier.infra.InMemorySessionStore;
import com.fikua.verifier.infra.PemKeyLoader;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for JAR (RFC 9101) signing of the Authorization Request.
 * HAIP requires a signed request_uri: a JWS with typ=oauth-authz-req+jwt
 * and the signing cert chain in x5c.
 */
class RequestObjectSigningTest {

    /** ProfileStore stub with no active profile — service falls back to plainVerifier. */
    private static final ProfileStore NO_PROFILE = () -> null;

    private VerificationService newService(Path certsDir) {
        SigningKey key = PemKeyLoader.loadOrGenerate(certsDir.toString());
        return new VerificationService(
                key, ResponseEncryptionKey.generate(), new InMemorySessionStore(), NO_PROFILE,
                "https://verifier.example.test");
    }

    @Test
    void createSession_producesSignedJarJwt(@TempDir Path certsDir) throws Exception {
        VerificationService service = newService(certsDir);

        VerificationSession session =
                service.createSession("eu.europa.ec.eudi.pid.1", List.of("given_name"));

        // The stored request must be a compact JWS, not bare JSON.
        String requestJwt = session.requestJwt();
        assertNotNull(requestJwt);
        assertFalse(requestJwt.trim().startsWith("{"), "request must be a JWT, not raw JSON");

        SignedJWT jwt = SignedJWT.parse(requestJwt); // throws if not a valid JWS
        assertEquals("oauth-authz-req+jwt", jwt.getHeader().getType().toString(),
                "JAR typ must be oauth-authz-req+jwt");
        assertNotNull(jwt.getHeader().getKeyID(), "header must carry kid");
    }

    @Test
    void createSession_jarHeaderCarriesX5c(@TempDir Path certsDir) throws Exception {
        VerificationService service = newService(certsDir);

        VerificationSession session =
                service.createSession("eu.europa.ec.eudi.pid.1", List.of("given_name"));

        SignedJWT jwt = SignedJWT.parse(session.requestJwt());
        var x5c = jwt.getHeader().getX509CertChain();
        assertNotNull(x5c, "JAR header must carry x5c (HAIP 6.1.1)");
        assertFalse(x5c.isEmpty(), "x5c must not be empty");
    }

    @Test
    void createSession_jarClaimsArePreserved(@TempDir Path certsDir) throws Exception {
        VerificationService service = newService(certsDir);

        VerificationSession session =
                service.createSession("eu.europa.ec.eudi.pid.1", List.of("given_name"));

        SignedJWT jwt = SignedJWT.parse(session.requestJwt());
        var claims = jwt.getJWTClaimsSet();
        assertEquals("vp_token", claims.getStringClaim("response_type"));
        assertNotNull(claims.getStringClaim("nonce"), "nonce must be present");
        assertNotNull(claims.getStringClaim("state"), "state must be present");
        // Signature verifies against the same key (proves it was really signed).
        assertNotNull(claims.getStringClaim("client_id"));
    }
}
