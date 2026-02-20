package com.fikua.core.sdjwt;

import com.fikua.core.crypto.SigningKey;
import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;

import java.time.Instant;
import java.util.*;

/**
 * Builds SD-JWT VCs (Selective Disclosure JWT Verifiable Credentials).
 * Creates the issuer-signed JWT with selective disclosures per SD-JWT spec.
 */
public class SdJwtBuilder {

    private final SigningKey issuerKey;
    private final Map<String, Object> plainClaims = new LinkedHashMap<>();
    private final Map<String, Object> selectiveClaims = new LinkedHashMap<>();
    private String vct;
    private String issuer;
    private String subject;
    private long validitySeconds = 86400 * 365; // 1 year default
    private ECKey holderKey;
    private List<Base64> x5cChain;

    public SdJwtBuilder(SigningKey issuerKey) {
        this.issuerKey = issuerKey;
    }

    public SdJwtBuilder vct(String vct) {
        this.vct = vct;
        return this;
    }

    public SdJwtBuilder issuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    public SdJwtBuilder subject(String subject) {
        this.subject = subject;
        return this;
    }

    public SdJwtBuilder validitySeconds(long seconds) {
        this.validitySeconds = seconds;
        return this;
    }

    /** Add a claim that will be in plaintext (not selectively disclosable). */
    public SdJwtBuilder plainClaim(String name, Object value) {
        plainClaims.put(name, value);
        return this;
    }

    /** Add a claim that will be selectively disclosable. */
    public SdJwtBuilder selectiveClaim(String name, Object value) {
        selectiveClaims.put(name, value);
        return this;
    }

    /** Set the holder/wallet public key for key binding (cnf claim). */
    public SdJwtBuilder holderKey(ECKey holderKey) {
        this.holderKey = holderKey;
        return this;
    }

    /** Set x5c certificate chain for the JWS header. */
    public SdJwtBuilder x5cChain(List<Base64> x5cChain) {
        this.x5cChain = x5cChain;
        return this;
    }

    /** Build the SD-JWT VC. */
    public SdJwt build() {
        // Create disclosures
        List<Disclosure> disclosures = new ArrayList<>();
        List<String> sdDigests = new ArrayList<>();

        for (var entry : selectiveClaims.entrySet()) {
            Disclosure disclosure = Disclosure.create(entry.getKey(), entry.getValue());
            disclosures.add(disclosure);
            sdDigests.add(disclosure.digest());
        }

        // Build JWT claims
        Instant now = Instant.now();
        var claimsBuilder = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(validitySeconds)));

        if (subject != null) {
            claimsBuilder.subject(subject);
        }

        // vct (Verifiable Credential Type)
        if (vct != null) {
            claimsBuilder.claim("vct", vct);
        }

        // _sd_alg
        claimsBuilder.claim("_sd_alg", "sha-256");

        // _sd array (digests of disclosures)
        if (!sdDigests.isEmpty()) {
            claimsBuilder.claim("_sd", sdDigests);
        }

        // Plain claims
        for (var entry : plainClaims.entrySet()) {
            claimsBuilder.claim(entry.getKey(), entry.getValue());
        }

        // cnf (confirmation) with holder key
        if (holderKey != null) {
            Map<String, Object> cnf = Map.of("jwk", holderKey.toPublicJWK().toJSONObject());
            claimsBuilder.claim("cnf", cnf);
        }

        // Build JWS header
        var headerBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dc+sd-jwt"))
                .keyID(issuerKey.kid());

        if (x5cChain != null && !x5cChain.isEmpty()) {
            headerBuilder.x509CertChain(x5cChain);
        }

        // Sign
        String jwt = issuerKey.signJwt(headerBuilder.build(), claimsBuilder.build());

        return new SdJwt(jwt, disclosures, null);
    }
}
