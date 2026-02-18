package com.fikua.core.sdjwt;

import com.fikua.core.crypto.EcKeyManager;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SdJwtBuilderTest {

    private static final EcKeyManager ISSUER_KEY = EcKeyManager.generate();

    @Test
    void build_typHeader_isDcSdJwt() throws Exception {
        SdJwt sdJwt = new SdJwtBuilder(ISSUER_KEY)
                .vct("eu.europa.ec.eudi.pid.1")
                .issuer("https://issuer.lab.fikua.com")
                .build();

        // Parse the issuer-signed JWT (first part before ~)
        String serialized = sdJwt.serialize();
        String jwtPart = serialized.split("~")[0];
        SignedJWT jwt = SignedJWT.parse(jwtPart);

        assertEquals("dc+sd-jwt", jwt.getHeader().getType().toString(),
                "SD-JWT VC typ header must be dc+sd-jwt (not vc+sd-jwt)");
    }

    @Test
    void build_withSelectiveClaims_hasDisclosures() throws Exception {
        SdJwt sdJwt = new SdJwtBuilder(ISSUER_KEY)
                .vct("eu.europa.ec.eudi.pid.1")
                .issuer("https://issuer.lab.fikua.com")
                .selectiveClaim("given_name", "Jan")
                .selectiveClaim("family_name", "Kowalski")
                .build();

        String serialized = sdJwt.serialize();
        // SD-JWT format: jwt~disclosure1~disclosure2~
        String[] parts = serialized.split("~", -1);
        // At least: jwt + 2 disclosures + empty trailing (key binding holder)
        assertTrue(parts.length >= 3, "Should have JWT + at least 2 disclosures");
    }

    @Test
    void build_hasRequiredClaims() throws Exception {
        SdJwt sdJwt = new SdJwtBuilder(ISSUER_KEY)
                .vct("eu.europa.ec.eudi.pid.1")
                .issuer("https://issuer.lab.fikua.com")
                .subject("urn:fikua:pid:test")
                .selectiveClaim("given_name", "Jan")
                .build();

        String jwtPart = sdJwt.serialize().split("~")[0];
        SignedJWT jwt = SignedJWT.parse(jwtPart);
        var claims = jwt.getJWTClaimsSet();

        assertEquals("eu.europa.ec.eudi.pid.1", claims.getStringClaim("vct"));
        assertEquals("https://issuer.lab.fikua.com", claims.getIssuer());
        assertEquals("urn:fikua:pid:test", claims.getSubject());
        assertNotNull(claims.getIssueTime(), "iat must be present");
        assertNotNull(claims.getExpirationTime(), "exp must be present");
        assertEquals("sha-256", claims.getStringClaim("_sd_alg"));
    }
}
