package com.fikua.core.crypto;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.*;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.List;
import java.util.Map;

/**
 * EC P-256 key management for signing and verification.
 * Wraps nimbus-jose-jwt ECKey operations.
 */
public final class EcKeyManager implements SigningKey {

    private final ECKey ecKey;

    private EcKeyManager(ECKey ecKey) {
        this.ecKey = ecKey;
    }

    /** Generate a new EC P-256 key pair with SHA-256 thumbprint as kid. */
    public static EcKeyManager generate() {
        try {
            ECKey key = new ECKeyGenerator(Curve.P_256)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.ES256)
                    .generate();
            String kid = key.computeThumbprint("SHA-256").toString();
            return new EcKeyManager(new ECKey.Builder(key).keyID(kid).build());
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to generate EC key", e);
        }
    }

    /** Load from PEM private key + X.509 certificate. Includes x5c chain. */
    public static EcKeyManager fromPem(PrivateKey privateKey, X509Certificate cert) {
        try {
            ECPublicKey pubKey = (ECPublicKey) cert.getPublicKey();
            List<Base64> x5c = X509CertUtil.buildX5cChain(cert);

            ECKey ecKey = new ECKey.Builder(Curve.P_256, pubKey)
                    .privateKey(privateKey)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.ES256)
                    .x509CertChain(x5c)
                    .build();

            String kid = ecKey.computeThumbprint("SHA-256").toString();
            return new EcKeyManager(new ECKey.Builder(ecKey).keyID(kid).build());
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to build ECKey from PEM", e);
        }
    }

    /** Load from an existing nimbus ECKey. */
    public static EcKeyManager from(ECKey ecKey) {
        return new EcKeyManager(ecKey);
    }

    /** Parse from JWK JSON string. */
    public static EcKeyManager parse(String jwkJson) {
        try {
            return new EcKeyManager(ECKey.parse(jwkJson));
        } catch (ParseException e) {
            throw new RuntimeException("Failed to parse ECKey", e);
        }
    }

    /** Get the full ECKey (with private key if available). */
    public ECKey ecKey() {
        return ecKey;
    }

    /** Get public-only ECKey. */
    public ECKey publicKey() {
        return ecKey.toPublicJWK();
    }

    /** Get key ID (SHA-256 thumbprint). */
    public String kid() {
        return ecKey.getKeyID();
    }

    /** Get JWK Set containing only the public key. */
    public JWKSet jwkSet() {
        return new JWKSet(ecKey.toPublicJWK());
    }

    /** Sign a JWS object with ES256. */
    public String sign(JWSHeader header, Payload payload) {
        try {
            JWSObject jws = new JWSObject(header, payload);
            jws.sign(new ECDSASigner(ecKey));
            return jws.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to sign JWS", e);
        }
    }

    /** Sign a JWT (JWS with JSON claims payload). */
    public String signJwt(JWSHeader header, JWTClaimsSet claims) {
        try {
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new ECDSASigner(ecKey));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to sign JWT", e);
        }
    }

    /** Verify a JWS signature using this key's public key. */
    public boolean verify(String serializedJws) {
        try {
            JWSObject jws = JWSObject.parse(serializedJws);
            return jws.verify(new ECDSAVerifier(ecKey.toPublicJWK()));
        } catch (ParseException | JOSEException e) {
            return false;
        }
    }

    /** Verify a signed JWT and return the claims if valid. */
    public JWTClaimsSet verifyJwt(String serializedJwt) {
        try {
            SignedJWT jwt = SignedJWT.parse(serializedJwt);
            if (jwt.verify(new ECDSAVerifier(ecKey.toPublicJWK()))) {
                return jwt.getJWTClaimsSet();
            }
            return null;
        } catch (ParseException | JOSEException e) {
            return null;
        }
    }

    /** Get the EC public key as java.security type. */
    public ECPublicKey toPublicKey() {
        try {
            return ecKey.toECPublicKey();
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to export public key", e);
        }
    }

    /** Get the x5c certificate chain (empty list if no certificates). */
    @Override
    public List<Base64> x5cChain() {
        List<Base64> chain = ecKey.getX509CertChain();
        return chain != null ? chain : List.of();
    }

    /** Sign raw bytes with ECDSA-SHA256 in P1363 format (r || s, 64 bytes for P-256). */
    @Override
    public byte[] signRawBytes(byte[] data) {
        try {
            java.security.Signature sig = java.security.Signature.getInstance("SHA256withECDSAinP1363Format");
            sig.initSign(ecKey.toECPrivateKey());
            sig.update(data);
            return sig.sign();
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign raw bytes with ECDSA", e);
        }
    }

    /** Get the EC private key as java.security type. */
    public ECPrivateKey toPrivateKey() {
        try {
            return ecKey.toECPrivateKey();
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to export private key", e);
        }
    }
}
