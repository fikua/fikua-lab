package com.fikua.core.crypto;

import com.nimbusds.jose.util.Base64;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * X.509 certificate utilities for loading PEM files and building x5c chains.
 */
public final class X509CertUtil {

    private X509CertUtil() {}

    /** Load an X.509 certificate from a PEM file. */
    public static X509Certificate loadCertificate(Path pemPath) {
        try (InputStream is = Files.newInputStream(pemPath)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(is);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load certificate from " + pemPath, e);
        }
    }

    /** Load a private key from a PEM file (PKCS#8 or EC). */
    public static PrivateKey loadPrivateKey(Path pemPath) {
        try (PEMParser parser = new PEMParser(Files.newBufferedReader(pemPath))) {
            Object obj = parser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            if (obj instanceof PrivateKeyInfo pki) {
                return converter.getPrivateKey(pki);
            }
            throw new RuntimeException("Unsupported PEM object: " + obj.getClass().getName());
        } catch (IOException e) {
            throw new RuntimeException("Failed to load private key from " + pemPath, e);
        }
    }

    /**
     * Build x5c chain as List<Base64> for JOSE headers.
     * Per HAIP: leaf certificate first, trust anchor (root CA) excluded.
     *
     * @param certs ordered from leaf to intermediate(s). Root CA must NOT be included.
     */
    public static List<Base64> buildX5cChain(X509Certificate... certs) {
        List<Base64> chain = new ArrayList<>();
        for (X509Certificate cert : certs) {
            try {
                chain.add(Base64.encode(cert.getEncoded()));
            } catch (CertificateEncodingException e) {
                throw new RuntimeException("Failed to encode certificate", e);
            }
        }
        return chain;
    }

    /**
     * Compute SHA-256 hash of DER-encoded certificate, base64url-encoded.
     * Used for x509_hash client_id prefix in OID4VP.
     */
    public static String certThumbprint(X509Certificate cert) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(cert.getEncoded());
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute cert thumbprint", e);
        }
    }
}
