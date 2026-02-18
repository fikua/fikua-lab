package com.fikua.core.oauth2;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class ClientAttestationValidatorTest {

    private static final String EXPECTED_TYPE =
            "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation";

    private final ClientAttestationValidator validator = new ClientAttestationValidator();

    @Test
    void validate_nullBoth_returnsNull() {
        assertNull(validator.validate(null, null));
    }

    @Test
    void validate_wrongAssertionType_throwsInvalidClient() {
        var ex = assertThrows(OAuthErrorException.class,
                () -> validator.validate("wrong_type", "dummy"));
        assertEquals(400, ex.httpStatus());
        assertEquals(OAuthError.INVALID_CLIENT, ex.error().error());
    }

    @Test
    void validate_missingAssertion_throwsInvalidClient() {
        var ex = assertThrows(OAuthErrorException.class,
                () -> validator.validate(EXPECTED_TYPE, null));
        assertEquals(400, ex.httpStatus());
        assertEquals(OAuthError.INVALID_CLIENT, ex.error().error());
    }

    @Test
    void validate_blankAssertion_throwsInvalidClient() {
        var ex = assertThrows(OAuthErrorException.class,
                () -> validator.validate(EXPECTED_TYPE, "   "));
        assertEquals(400, ex.httpStatus());
        assertEquals(OAuthError.INVALID_CLIENT, ex.error().error());
    }

    @Test
    void validate_singleJwt_throwsInvalidClient() throws Exception {
        String singleJwt = createSignedJwt("test-client", "https://as.example.com").serialize();
        var ex = assertThrows(OAuthErrorException.class,
                () -> validator.validate(EXPECTED_TYPE, singleJwt));
        assertEquals(400, ex.httpStatus());
        assertTrue(ex.error().errorDescription().contains("WIA~PoP"));
    }

    @Test
    void validate_validWiaPoP_returnsClientId() throws Exception {
        String clientId = "https://wallet.example.com";
        SignedJWT wia = createSignedJwt(clientId, "https://attestation-service.example.com");
        SignedJWT pop = createSignedJwt(null, clientId);

        String assertion = wia.serialize() + "~" + pop.serialize();
        String result = validator.validate(EXPECTED_TYPE, assertion);

        assertEquals(clientId, result);
    }

    @Test
    void validate_malformedJwt_throwsInvalidClient() {
        String assertion = "not-a-jwt~also-not-a-jwt";
        var ex = assertThrows(OAuthErrorException.class,
                () -> validator.validate(EXPECTED_TYPE, assertion));
        assertEquals(400, ex.httpStatus());
        assertEquals(OAuthError.INVALID_CLIENT, ex.error().error());
    }

    private SignedJWT createSignedJwt(String subject, String issuer) throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256).generate();
        var claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(subject)
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 300_000))
                .build();
        var jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).jwk(key.toPublicJWK()).build(),
                claims
        );
        jwt.sign(new ECDSASigner(key));
        return jwt;
    }
}
