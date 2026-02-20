package com.fikua.core.crypto;

import com.nimbusds.jose.util.Base64;

import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Pure X.509 certificate utilities (no I/O).
 * Transforms in-memory certificate objects — does not read files.
 */
public final class X509CertUtil {

    private X509CertUtil() {}

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
