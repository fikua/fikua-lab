package com.fikua.core.oauth2;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.Map;

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
        assertEquals(401, ex.httpStatus());
        assertEquals(OAuthError.INVALID_CLIENT, ex.error().error());
    }

    @Test
    void validate_missingAssertion_throwsInvalidClient() {
        var ex = assertThrows(OAuthErrorException.class,
                () -> validator.validate(EXPECTED_TYPE, null));
        assertEquals(401, ex.httpStatus());
        assertEquals(OAuthError.INVALID_CLIENT, ex.error().error());
    }

    @Test
    void validate_blankAssertion_throwsInvalidClient() {
        var ex = assertThrows(OAuthErrorException.class,
                () -> validator.validate(EXPECTED_TYPE, "   "));
        assertEquals(401, ex.httpStatus());
        assertEquals(OAuthError.INVALID_CLIENT, ex.error().error());
    }

    @Test
    void validate_singleJwt_throwsInvalidClient() throws Exception {
        String singleJwt = createSignedJwt("test-client", "https://as.example.com").serialize();
        var ex = assertThrows(OAuthErrorException.class,
                () -> validator.validate(EXPECTED_TYPE, singleJwt));
        assertEquals(401, ex.httpStatus());
        assertTrue(ex.error().errorDescription().contains("WIA~PoP"));
    }

    @Test
    void validate_validWiaPoP_returnsClientId() throws Exception {
        String clientId = "https://wallet.example.com";
        // PoP key — the wallet instance key bound via cnf in WIA
        ECKey popKey = new ECKeyGenerator(Curve.P_256).generate();

        // WIA with cnf containing the PoP public key
        SignedJWT wia = createWiaWithCnf(clientId, "https://attestation-service.example.com", popKey);

        // PoP signed with the same key referenced in cnf
        var popClaims = new JWTClaimsSet.Builder()
                .issuer(clientId)
                .audience("https://as.example.com")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 300_000))
                .build();
        var pop = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).build(), popClaims);
        pop.sign(new ECDSASigner(popKey));

        String assertion = wia.serialize() + "~" + pop.serialize();
        String result = validator.validate(EXPECTED_TYPE, assertion);

        assertEquals(clientId, result);
    }

    @Test
    void validate_wiaMissingCnf_throwsInvalidClient() throws Exception {
        String clientId = "https://wallet.example.com";
        // WIA without cnf claim
        SignedJWT wia = createSignedJwt(clientId, "https://attestation-service.example.com");
        SignedJWT pop = createSignedJwt(null, clientId);

        String assertion = wia.serialize() + "~" + pop.serialize();
        var ex = assertThrows(OAuthErrorException.class,
                () -> validator.validate(EXPECTED_TYPE, assertion));
        assertEquals(401, ex.httpStatus());
        assertTrue(ex.error().errorDescription().contains("cnf"));
    }

    @Test
    void validate_validWiaPoP_withRSAKey_returnsClientId() throws Exception {
        String clientId = "https://wallet.example.com";
        RSAKey rsaKey = new RSAKeyGenerator(2048).generate();

        SignedJWT wia = createWiaWithCnf(clientId, "https://attestation-service.example.com", rsaKey);

        var popClaims = new JWTClaimsSet.Builder()
                .issuer(clientId)
                .audience("https://as.example.com")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 300_000))
                .build();
        var pop = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(), popClaims);
        pop.sign(new RSASSASigner(rsaKey));

        String assertion = wia.serialize() + "~" + pop.serialize();
        String result = validator.validate(EXPECTED_TYPE, assertion);

        assertEquals(clientId, result);
    }

    @Test
    void validate_malformedJwt_throwsInvalidClient() {
        String assertion = "not-a-jwt~also-not-a-jwt";
        var ex = assertThrows(OAuthErrorException.class,
                () -> validator.validate(EXPECTED_TYPE, assertion));
        assertEquals(401, ex.httpStatus());
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

    /** Create a WIA with cnf claim containing the PoP public key. Accepts any JWK type. */
    private SignedJWT createWiaWithCnf(String subject, String issuer, JWK popKey) throws Exception {
        ECKey wiaSigningKey = new ECKeyGenerator(Curve.P_256).generate();
        var claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(subject)
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 300_000))
                .claim("cnf", Map.of("jwk", popKey.toPublicJWK().toJSONObject()))
                .build();
        var jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).jwk(wiaSigningKey.toPublicJWK()).build(),
                claims
        );
        jwt.sign(new ECDSASigner(wiaSigningKey));
        return jwt;
    }
}
