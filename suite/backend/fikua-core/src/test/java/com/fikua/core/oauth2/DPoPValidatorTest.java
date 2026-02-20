package com.fikua.core.oauth2;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class DPoPValidatorTest {

    /** Well beyond the 5-minute MAX_AGE_SECONDS window. */
    private static final long TEN_MINUTES_MS = 600_000;

    private Set<String> seenJtis;
    private DPoPValidator validator;
    private ECKey walletKey;

    @BeforeEach
    void setUp() throws Exception {
        seenJtis = new HashSet<>();
        validator = new DPoPValidator(seenJtis::add);
        walletKey = new ECKeyGenerator(Curve.P_256).keyID("wallet-1").generate();
    }

    // --- Missing / blank header ---

    @Test
    void validate_nullHeader_throws() {
        var ex = assertThrows(OAuthErrorException.class,
                () -> validator.validate(null, "POST", "https://issuer.example.com/token", null));
        assertTrue(ex.error().errorDescription().contains("Missing DPoP"));
    }

    @Test
    void validate_blankHeader_throws() {
        var ex = assertThrows(OAuthErrorException.class,
                () -> validator.validate("   ", "POST", "https://issuer.example.com/token", null));
        assertTrue(ex.error().errorDescription().contains("Missing DPoP"));
    }

    // --- typ header ---

    @Test
    void validate_wrongTyp_throws() throws Exception {
        String jwt = createDPoPProof(walletKey, "POST", "https://issuer.example.com/token",
                null, "jwt", null).serialize();
        var ex = assertThrows(OAuthErrorException.class,
                () -> validator.validate(jwt, "POST", "https://issuer.example.com/token", null));
        assertTrue(ex.error().errorDescription().contains("typ"));
    }

    // --- jwk header ---

    @Test
    void validate_missingJwk_throws() throws Exception {
        // Build JWT without jwk in header
        var claims = baseClaims("POST", "https://issuer.example.com/token", null);
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dpop+jwt"))
                .build(); // no jwk
        var jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(walletKey));

        var ex = assertThrows(OAuthErrorException.class,
                () -> validator.validate(jwt.serialize(), "POST", "https://issuer.example.com/token", null));
        assertTrue(ex.error().errorDescription().contains("jwk"));
    }

    // --- alg ---

    @Test
    void validate_wrongAlg_throws() throws Exception {
        // Sign a valid DPoP proof with ES256, then tamper the header to say ES384
        String validJwt = createValidDPoPProof("POST", "https://issuer.example.com/token", null);
        // Replace ES256 alg in header with ES384 by re-encoding the header
        String[] parts = validJwt.split("\\.");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        String tamperedHeader = headerJson.replace("ES256", "ES384");
        String tamperedHeaderB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(tamperedHeader.getBytes(StandardCharsets.UTF_8));
        String tamperedJwt = tamperedHeaderB64 + "." + parts[1] + "." + parts[2];

        var ex = assertThrows(OAuthErrorException.class,
                () -> validator.validate(tamperedJwt, "POST", "https://issuer.example.com/token", null));
        assertTrue(ex.error().errorDescription().contains("ES256"));
    }

    // --- Private key leak ---

    @Test
    void validate_privateKeyInJwk_throws() throws Exception {
        // Sign a valid DPoP proof, then tamper header to include the private key
        String validJwt = createValidDPoPProof("POST", "https://issuer.example.com/token", null);
        String[] parts = validJwt.split("\\.");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        // Replace public JWK with full (private) JWK in the header
        String publicJwkJson = walletKey.toPublicJWK().toJSONString();
        String privateJwkJson = walletKey.toJSONString();
        String tamperedHeader = headerJson.replace(publicJwkJson, privateJwkJson);
        String tamperedHeaderB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(tamperedHeader.getBytes(StandardCharsets.UTF_8));
        String tamperedJwt = tamperedHeaderB64 + "." + parts[1] + "." + parts[2];

        var ex = assertThrows(OAuthErrorException.class,
                () -> validator.validate(tamperedJwt, "POST", "https://issuer.example.com/token", null));
        assertTrue(ex.error().errorDescription().contains("public key"));
    }

    // --- Signature ---

    @Test
    void validate_invalidSignature_throws() throws Exception {
        // Sign with one key, put a different public key in header
        ECKey otherKey = new ECKeyGenerator(Curve.P_256).generate();
        var claims = baseClaims("POST", "https://issuer.example.com/token", null);
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dpop+jwt"))
                .jwk(otherKey.toPublicJWK()) // different key
                .build();
        var jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(walletKey)); // signed with walletKey

        var ex = assertThrows(OAuthErrorException.class,
                () -> validator.validate(jwt.serialize(), "POST", "https://issuer.example.com/token", null));
        assertTrue(ex.error().errorDescription().contains("signature"));
    }

    // --- htm / htu mismatch ---

    @Test
    void validate_htmMismatch_throws() throws Exception {
        String jwt = createValidDPoPProof("POST", "https://issuer.example.com/token", null);
        var ex = assertThrows(OAuthErrorException.class,
                () -> validator.validate(jwt, "GET", "https://issuer.example.com/token", null));
        assertTrue(ex.error().errorDescription().contains("htm"));
    }

    @Test
    void validate_htuMismatch_throws() throws Exception {
        String jwt = createValidDPoPProof("POST", "https://issuer.example.com/token", null);
        var ex = assertThrows(OAuthErrorException.class,
                () -> validator.validate(jwt, "POST", "https://other.example.com/token", null));
        assertTrue(ex.error().errorDescription().contains("htu"));
    }

    // --- iat expired ---

    @Test
    void validate_expiredIat_throws() throws Exception {
        var claims = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .claim("htm", "POST")
                .claim("htu", "https://issuer.example.com/token")
                .issueTime(new Date(System.currentTimeMillis() - TEN_MINUTES_MS))
                .build();
        String jwt = signDPoPProof(walletKey, claims);

        var ex = assertThrows(OAuthErrorException.class,
                () -> validator.validate(jwt, "POST", "https://issuer.example.com/token", null));
        assertTrue(ex.error().errorDescription().contains("expired"));
    }

    @Test
    void validate_futureIat_throws() throws Exception {
        var claims = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .claim("htm", "POST")
                .claim("htu", "https://issuer.example.com/token")
                .issueTime(new Date(System.currentTimeMillis() + TEN_MINUTES_MS)) // 10 min in future
                .build();
        String jwt = signDPoPProof(walletKey, claims);

        var ex = assertThrows(OAuthErrorException.class,
                () -> validator.validate(jwt, "POST", "https://issuer.example.com/token", null));
        assertTrue(ex.error().errorDescription().contains("expired"));
    }

    @Test
    void validate_iatWithinWindow_succeeds() throws Exception {
        // 4 minutes ago — within the 5-minute window
        var claims = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .claim("htm", "POST")
                .claim("htu", "https://issuer.example.com/token")
                .issueTime(new Date(System.currentTimeMillis() - 240_000))
                .build();
        String jwt = signDPoPProof(walletKey, claims);

        ECKey result = validator.validate(jwt, "POST", "https://issuer.example.com/token", null);
        assertNotNull(result);
    }

    // --- JTI replay ---

    @Test
    void validate_jtiReplay_throws() throws Exception {
        String jwt = createValidDPoPProof("POST", "https://issuer.example.com/token", null);
        // First call succeeds
        validator.validate(jwt, "POST", "https://issuer.example.com/token", null);
        // Second call with same JTI fails
        var ex = assertThrows(OAuthErrorException.class,
                () -> validator.validate(jwt, "POST", "https://issuer.example.com/token", null));
        assertTrue(ex.error().errorDescription().contains("jti") || ex.error().errorDescription().contains("replay"));
    }

    // --- ath ---

    @Test
    void validate_athMismatch_throws() throws Exception {
        String jwt = createDPoPProof(walletKey, "POST", "https://issuer.example.com/credential",
                "wrong-hash", "dpop+jwt", null).serialize();
        var ex = assertThrows(OAuthErrorException.class,
                () -> validator.validate(jwt, "POST", "https://issuer.example.com/credential", "correct-hash"));
        assertTrue(ex.error().errorDescription().contains("ath"));
    }

    @Test
    void validate_athMissing_whenExpected_throws() throws Exception {
        // No ath claim in proof, but we expect one
        String jwt = createValidDPoPProof("POST", "https://issuer.example.com/credential", null);
        var ex = assertThrows(OAuthErrorException.class,
                () -> validator.validate(jwt, "POST", "https://issuer.example.com/credential", "expected-hash"));
        assertTrue(ex.error().errorDescription().contains("ath"));
    }

    // --- Valid proof ---

    @Test
    void validate_validProof_returnsPublicKey() throws Exception {
        String jwt = createValidDPoPProof("POST", "https://issuer.example.com/token", null);
        ECKey result = validator.validate(jwt, "POST", "https://issuer.example.com/token", null);
        assertNotNull(result);
        assertFalse(result.isPrivate());
        assertEquals(walletKey.toPublicJWK().toJSONString(), result.toJSONString());
    }

    @Test
    void validate_validProofWithAth_returnsPublicKey() throws Exception {
        String ath = "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo";
        String jwt = createDPoPProof(walletKey, "POST", "https://issuer.example.com/credential",
                ath, "dpop+jwt", null).serialize();
        ECKey result = validator.validate(jwt, "POST", "https://issuer.example.com/credential", ath);
        assertNotNull(result);
    }

    // --- Helpers ---

    private String createValidDPoPProof(String htm, String htu, String ath) throws Exception {
        return createDPoPProof(walletKey, htm, htu, ath, "dpop+jwt", null).serialize();
    }

    private SignedJWT createDPoPProof(ECKey key, String htm, String htu,
                                      String ath, String typ, JWSAlgorithm algOverride) throws Exception {
        var claimsBuilder = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .claim("htm", htm)
                .claim("htu", htu)
                .issueTime(new Date());
        if (ath != null) {
            claimsBuilder.claim("ath", ath);
        }

        JWSAlgorithm alg = algOverride != null ? algOverride : JWSAlgorithm.ES256;
        var header = new JWSHeader.Builder(alg)
                .type(new JOSEObjectType(typ))
                .jwk(key.toPublicJWK())
                .build();

        var jwt = new SignedJWT(header, claimsBuilder.build());
        jwt.sign(new ECDSASigner(key));
        return jwt;
    }

    private JWTClaimsSet baseClaims(String htm, String htu, String ath) {
        var builder = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .claim("htm", htm)
                .claim("htu", htu)
                .issueTime(new Date());
        if (ath != null) {
            builder.claim("ath", ath);
        }
        return builder.build();
    }

    private String signDPoPProof(ECKey key, JWTClaimsSet claims) throws Exception {
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dpop+jwt"))
                .jwk(key.toPublicJWK())
                .build();
        var jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }
}
