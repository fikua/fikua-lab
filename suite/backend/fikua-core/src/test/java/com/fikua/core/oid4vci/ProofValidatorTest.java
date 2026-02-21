package com.fikua.core.oid4vci;

import com.fikua.core.oauth2.OAuthError;
import com.fikua.core.oauth2.OAuthErrorException;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ProofValidatorTest {

    private static final String ISSUER_URL = "https://issuer.example.com";
    private static final String C_NONCE = "test-nonce-12345";
    /** Well beyond the 5-minute validation window. */
    private static final long TEN_MINUTES_MS = 600_000;

    private ECKey walletKey;

    @BeforeEach
    void setUp() throws Exception {
        walletKey = new ECKeyGenerator(Curve.P_256).keyID("wallet-1").generate();
    }

    // --- Null / wrong proof_type ---

    @Test
    void validate_nullProof_throws() {
        var ex = assertThrows(OAuthErrorException.class,
                () -> ProofValidator.validate(null, ISSUER_URL, C_NONCE));
        assertEquals(OAuthError.INVALID_OR_MISSING_PROOF, ex.error().error());
        assertTrue(ex.error().errorDescription().contains("proof_type"));
    }

    @Test
    void validate_wrongProofType_throws() {
        var proof = new CredentialRequest.Proof("cwt", null);
        var ex = assertThrows(OAuthErrorException.class,
                () -> ProofValidator.validate(proof, ISSUER_URL, C_NONCE));
        assertEquals(OAuthError.INVALID_OR_MISSING_PROOF, ex.error().error());
    }

    @Test
    void validate_nullJwt_throws() {
        var proof = new CredentialRequest.Proof("jwt", null);
        var ex = assertThrows(OAuthErrorException.class,
                () -> ProofValidator.validate(proof, ISSUER_URL, C_NONCE));
        assertTrue(ex.error().errorDescription().contains("jwt"));
    }

    // --- typ header ---

    @Test
    void validate_wrongTyp_throws() throws Exception {
        String jwt = createProofJwt(walletKey, ISSUER_URL, C_NONCE, "jwt", JWSAlgorithm.ES256);
        var proof = new CredentialRequest.Proof("jwt", jwt);
        var ex = assertThrows(OAuthErrorException.class,
                () -> ProofValidator.validate(proof, ISSUER_URL, C_NONCE));
        assertTrue(ex.error().errorDescription().contains("openid4vci-proof+jwt"));
    }

    // --- alg ---

    @Test
    void validate_wrongAlg_throws() throws Exception {
        // Sign valid proof, then tamper header to say ES384
        String validJwt = createValidProofJwt(walletKey, ISSUER_URL, C_NONCE);
        String[] parts = validJwt.split("\\.");
        String headerJson = new String(java.util.Base64.getUrlDecoder().decode(parts[0]),
                java.nio.charset.StandardCharsets.UTF_8);
        String tampered = headerJson.replace("ES256", "ES384");
        String tamperedB64 = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(tampered.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String tamperedJwt = tamperedB64 + "." + parts[1] + "." + parts[2];

        var proof = new CredentialRequest.Proof("jwt", tamperedJwt);
        var ex = assertThrows(OAuthErrorException.class,
                () -> ProofValidator.validate(proof, ISSUER_URL, C_NONCE));
        assertTrue(ex.error().errorDescription().contains("ES256"));
    }

    // --- key reference mutual exclusivity (OID4VCI 1.0 Final Appendix F.1) ---

    @Test
    void validate_noKeyReference_throws() throws Exception {
        var claims = proofClaims(ISSUER_URL, C_NONCE);
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .build(); // no jwk, no x5c, no kid
        var jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(walletKey));

        var proof = new CredentialRequest.Proof("jwt", jwt.serialize());
        var ex = assertThrows(OAuthErrorException.class,
                () -> ProofValidator.validate(proof, ISSUER_URL, C_NONCE));
        assertTrue(ex.error().errorDescription().contains("exactly one"));
    }

    @Test
    void validate_jwkAndKid_throws() throws Exception {
        var claims = proofClaims(ISSUER_URL, C_NONCE);
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(walletKey.toPublicJWK())
                .keyID("some-kid")
                .build();
        var jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(walletKey));

        var proof = new CredentialRequest.Proof("jwt", jwt.serialize());
        var ex = assertThrows(OAuthErrorException.class,
                () -> ProofValidator.validate(proof, ISSUER_URL, C_NONCE));
        assertTrue(ex.error().errorDescription().contains("exactly one"));
    }

    @Test
    void validate_jwkAndX5c_throws() throws Exception {
        var claims = proofClaims(ISSUER_URL, C_NONCE);
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(walletKey.toPublicJWK())
                .x509CertChain(List.of(com.nimbusds.jose.util.Base64.encode("dummy-cert")))
                .build();
        var jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(walletKey));

        var proof = new CredentialRequest.Proof("jwt", jwt.serialize());
        var ex = assertThrows(OAuthErrorException.class,
                () -> ProofValidator.validate(proof, ISSUER_URL, C_NONCE));
        assertTrue(ex.error().errorDescription().contains("exactly one"));
    }

    @Test
    void validate_kidOnly_throwsUnsupported() throws Exception {
        var claims = proofClaims(ISSUER_URL, C_NONCE);
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .keyID("some-kid")
                .build();
        var jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(walletKey));

        var proof = new CredentialRequest.Proof("jwt", jwt.serialize());
        var ex = assertThrows(OAuthErrorException.class,
                () -> ProofValidator.validate(proof, ISSUER_URL, C_NONCE));
        assertTrue(ex.error().errorDescription().contains("Only jwk"));
    }

    // --- invalid signature ---

    @Test
    void validate_invalidSignature_throws() throws Exception {
        ECKey otherKey = new ECKeyGenerator(Curve.P_256).generate();
        var claims = proofClaims(ISSUER_URL, C_NONCE);
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(otherKey.toPublicJWK()) // different key in header
                .build();
        var jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(walletKey)); // signed with walletKey

        var proof = new CredentialRequest.Proof("jwt", jwt.serialize());
        var ex = assertThrows(OAuthErrorException.class,
                () -> ProofValidator.validate(proof, ISSUER_URL, C_NONCE));
        assertTrue(ex.error().errorDescription().contains("signature"));
    }

    // --- wrong audience ---

    @Test
    void validate_wrongAudience_throws() throws Exception {
        String jwt = createValidProofJwt(walletKey, "https://wrong-issuer.example.com", C_NONCE);
        var proof = new CredentialRequest.Proof("jwt", jwt);
        var ex = assertThrows(OAuthErrorException.class,
                () -> ProofValidator.validate(proof, ISSUER_URL, C_NONCE));
        assertTrue(ex.error().errorDescription().contains("aud"));
    }

    // --- nonce mismatch ---

    @Test
    void validate_nonceMismatch_throws() throws Exception {
        String jwt = createValidProofJwt(walletKey, ISSUER_URL, "wrong-nonce");
        var proof = new CredentialRequest.Proof("jwt", jwt);
        var ex = assertThrows(OAuthErrorException.class,
                () -> ProofValidator.validate(proof, ISSUER_URL, C_NONCE));
        assertTrue(ex.error().errorDescription().contains("nonce"));
    }

    // --- expired ---

    @Test
    void validate_expired_throws() throws Exception {
        var claims = new JWTClaimsSet.Builder()
                .audience(List.of(ISSUER_URL))
                .claim("nonce", C_NONCE)
                .issueTime(new Date(System.currentTimeMillis() - TEN_MINUTES_MS))
                .build();
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(walletKey.toPublicJWK())
                .build();
        var jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(walletKey));

        var proof = new CredentialRequest.Proof("jwt", jwt.serialize());
        var ex = assertThrows(OAuthErrorException.class,
                () -> ProofValidator.validate(proof, ISSUER_URL, C_NONCE));
        assertTrue(ex.error().errorDescription().contains("expired"));
    }

    @Test
    void validate_iatWithinWindow_succeeds() throws Exception {
        // 4 minutes ago — within the 5-minute window
        var claims = new JWTClaimsSet.Builder()
                .audience(List.of(ISSUER_URL))
                .claim("nonce", C_NONCE)
                .issueTime(new Date(System.currentTimeMillis() - 240_000))
                .build();
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(walletKey.toPublicJWK())
                .build();
        var jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(walletKey));

        var proof = new CredentialRequest.Proof("jwt", jwt.serialize());
        ECKey result = ProofValidator.validate(proof, ISSUER_URL, C_NONCE);
        assertNotNull(result);
    }

    @Test
    void validate_malformedJwt_throws() {
        var proof = new CredentialRequest.Proof("jwt", "not.a.valid.jwt");
        var ex = assertThrows(OAuthErrorException.class,
                () -> ProofValidator.validate(proof, ISSUER_URL, C_NONCE));
        assertEquals(OAuthError.INVALID_OR_MISSING_PROOF, ex.error().error());
    }

    // --- valid proof ---

    @Test
    void validate_validProof_returnsWalletKey() throws Exception {
        String jwt = createValidProofJwt(walletKey, ISSUER_URL, C_NONCE);
        var proof = new CredentialRequest.Proof("jwt", jwt);
        ECKey result = ProofValidator.validate(proof, ISSUER_URL, C_NONCE);
        assertNotNull(result);
        assertEquals(walletKey.toPublicJWK().toJSONString(), result.toJSONString());
    }

    @Test
    void validate_nullExpectedNonce_skipsNonceCheck() throws Exception {
        String jwt = createValidProofJwt(walletKey, ISSUER_URL, "any-nonce");
        var proof = new CredentialRequest.Proof("jwt", jwt);
        ECKey result = ProofValidator.validate(proof, ISSUER_URL, null);
        assertNotNull(result);
    }

    // --- Helpers ---

    private String createValidProofJwt(ECKey key, String audience, String nonce) throws Exception {
        return createProofJwt(key, audience, nonce, "openid4vci-proof+jwt", JWSAlgorithm.ES256);
    }

    private String createProofJwt(ECKey key, String audience, String nonce,
                                   String typ, JWSAlgorithm alg) throws Exception {
        var claims = new JWTClaimsSet.Builder()
                .audience(List.of(audience))
                .claim("nonce", nonce)
                .issueTime(new Date())
                .build();
        var header = new JWSHeader.Builder(alg)
                .type(new JOSEObjectType(typ))
                .jwk(key.toPublicJWK())
                .build();
        var jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }

    private JWTClaimsSet proofClaims(String audience, String nonce) {
        return new JWTClaimsSet.Builder()
                .audience(List.of(audience))
                .claim("nonce", nonce)
                .issueTime(new Date())
                .build();
    }
}
