package com.fikua.core.crypto;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;

import java.security.interfaces.ECPublicKey;
import java.util.List;

/**
 * Abstraction for cryptographic signing operations.
 * Implemented by EcKeyManager (P-256/ES256).
 * Lives in core so domain objects (SdJwtBuilder, DPoPValidator) can depend on it.
 */
public interface SigningKey {

    /** Get key ID (typically SHA-256 thumbprint). */
    String kid();

    /** Get JWK Set containing only the public key. */
    JWKSet jwkSet();

    /** Sign a JWS object. Returns the serialized compact form. */
    String sign(JWSHeader header, Payload payload);

    /** Sign a JWT (JWS with JSON claims payload). Returns the serialized compact form. */
    String signJwt(JWSHeader header, JWTClaimsSet claims);

    /** Verify a JWS signature using this key's public key. */
    boolean verify(String serializedJws);

    /** Verify a signed JWT and return the claims if valid, null otherwise. */
    JWTClaimsSet verifyJwt(String serializedJwt);

    /** Get the EC public key as java.security type. */
    ECPublicKey toPublicKey();

    /** Get the x5c certificate chain (empty list if no certificates). */
    List<Base64> x5cChain();
}
