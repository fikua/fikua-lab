package com.fikua.core.sdjwt;

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
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SdJwtVerifierTest {

    private ECKey issuerKey;

    @BeforeEach
    void setUp() throws Exception {
        issuerKey = new ECKeyGenerator(Curve.P_256).keyID("issuer-1").generate();
    }

    @Test
    void verify_validSdJwt_returnsResolvedClaims() throws Exception {
        Disclosure d1 = Disclosure.create("given_name", "Alice");
        Disclosure d2 = Disclosure.create("family_name", "Smith");

        String issuerJwt = createIssuerJwt(issuerKey, List.of(d1, d2), null);
        SdJwt sdJwt = new SdJwt(issuerJwt, List.of(d1, d2), null);

        Map<String, Object> claims = SdJwtVerifier.verify(sdJwt, issuerKey);
        assertEquals("Alice", claims.get("given_name"));
        assertEquals("Smith", claims.get("family_name"));
        assertFalse(claims.containsKey("_sd"), "_sd should be removed");
        assertFalse(claims.containsKey("_sd_alg"), "_sd_alg should be removed");
    }

    @Test
    void verify_preservesPlainClaims() throws Exception {
        String issuerJwt = createIssuerJwt(issuerKey, List.of(), null);
        SdJwt sdJwt = new SdJwt(issuerJwt, List.of(), null);

        Map<String, Object> claims = SdJwtVerifier.verify(sdJwt, issuerKey);
        assertEquals("https://issuer.example.com", claims.get("iss"));
    }

    @Test
    void verify_wrongKey_throws() throws Exception {
        ECKey wrongKey = new ECKeyGenerator(Curve.P_256).generate();
        String issuerJwt = createIssuerJwt(issuerKey, List.of(), null);
        SdJwt sdJwt = new SdJwt(issuerJwt, List.of(), null);

        assertThrows(RuntimeException.class,
                () -> SdJwtVerifier.verify(sdJwt, wrongKey));
    }

    @Test
    void verify_expiredCredential_throws() throws Exception {
        Date expired = new Date(System.currentTimeMillis() - 60_000); // 1 min ago
        String issuerJwt = createIssuerJwt(issuerKey, List.of(), expired);
        SdJwt sdJwt = new SdJwt(issuerJwt, List.of(), null);

        assertThrows(RuntimeException.class,
                () -> SdJwtVerifier.verify(sdJwt, issuerKey));
    }

    @Test
    void verify_noExpiry_succeeds() throws Exception {
        // JWT with no exp claim — should not throw
        String issuerJwt = createIssuerJwt(issuerKey, List.of(), null);
        SdJwt sdJwt = new SdJwt(issuerJwt, List.of(), null);

        Map<String, Object> claims = SdJwtVerifier.verify(sdJwt, issuerKey);
        assertNotNull(claims);
    }

    // --- Helpers ---

    private String createIssuerJwt(ECKey key, List<Disclosure> disclosures, Date exp) throws Exception {
        var claimsBuilder = new JWTClaimsSet.Builder()
                .issuer("https://issuer.example.com")
                .issueTime(new Date())
                .claim("_sd_alg", "sha-256");

        if (exp != null) {
            claimsBuilder.expirationTime(exp);
        }

        if (!disclosures.isEmpty()) {
            List<String> sdDigests = disclosures.stream()
                    .map(Disclosure::digest)
                    .toList();
            claimsBuilder.claim("_sd", sdDigests);
        }

        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(key.getKeyID())
                .build();

        var jwt = new SignedJWT(header, claimsBuilder.build());
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }
}
