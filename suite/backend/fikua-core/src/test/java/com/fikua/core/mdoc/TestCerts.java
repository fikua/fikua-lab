package com.fikua.core.mdoc;

import com.fikua.core.crypto.EcKeyManager;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

/**
 * Test-only helper that mints real P-256 X.509 certificates so mdoc
 * verification tests have a genuine COSE x5chain to parse and validate.
 * Mirrors the issuer's {@code PemKeyLoader.generateWithCaSignedCert} pattern.
 */
final class TestCerts {

    private TestCerts() {}

    /** A self-signed root CA: its key pair, certificate, and a signing manager. */
    record Ca(KeyPair keyPair, X509Certificate cert) {}

    /** An EcKeyManager whose x5c is [leaf] (leaf signed by the CA), plus the CA cert. */
    record IssuerChain(EcKeyManager key, X509Certificate leaf, X509Certificate ca) {}

    static KeyPair generateEcKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate EC key pair", e);
        }
    }

    /** Create a self-signed CA certificate (basicConstraints CA=true). */
    static Ca selfSignedCa(String cn) {
        try {
            KeyPair caKp = generateEcKeyPair();
            X500Name subject = new X500Name("CN=" + cn + ", O=Fikua Lab Test, C=ES");
            Date notBefore = new Date(System.currentTimeMillis() - 60_000);
            Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(caKp.getPrivate());
            X509CertificateHolder holder = new JcaX509v3CertificateBuilder(
                    subject, BigInteger.valueOf(1), notBefore, notAfter, subject, caKp.getPublic())
                    .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                    .build(signer);
            X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
            return new Ca(caKp, cert);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create self-signed CA", e);
        }
    }

    /**
     * Create a leaf (issuer) cert signed by the given CA and return an
     * EcKeyManager carrying it (x5c = [leaf]). The CA root is the trust anchor,
     * excluded from x5c — mirroring HAIP 6.1.1.
     */
    static IssuerChain issuerSignedBy(Ca ca, String cn) {
        try {
            KeyPair leafKp = generateEcKeyPair();
            X500Name issuer = new X500Name(ca.cert().getSubjectX500Principal().getName());
            X500Name subject = new X500Name("CN=" + cn + ", O=Fikua Lab Test, C=ES");
            Date notBefore = new Date(System.currentTimeMillis() - 60_000);
            Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(ca.keyPair().getPrivate());
            X509CertificateHolder holder = new JcaX509v3CertificateBuilder(
                    issuer, BigInteger.valueOf(2), notBefore, notAfter, subject, leafKp.getPublic())
                    .build(signer);
            X509Certificate leaf = new JcaX509CertificateConverter().getCertificate(holder);
            EcKeyManager key = EcKeyManager.fromPem(leafKp.getPrivate(), leaf);
            return new IssuerChain(key, leaf, ca.cert());
        } catch (Exception e) {
            throw new RuntimeException("Failed to create CA-signed issuer cert", e);
        }
    }

    /** Convenience: a one-cert self-signed issuer (acts as its own root). */
    static IssuerChain selfSignedIssuer(String cn) {
        Ca ca = selfSignedCa(cn);
        EcKeyManager key = EcKeyManager.fromPem(ca.keyPair().getPrivate(), ca.cert());
        return new IssuerChain(key, ca.cert(), ca.cert());
    }
}
