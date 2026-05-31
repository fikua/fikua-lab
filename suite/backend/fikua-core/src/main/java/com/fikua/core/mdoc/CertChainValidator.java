package com.fikua.core.mdoc;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Validates an X.509 certificate chain extracted from an mdoc COSE x5chain.
 *
 * <p>The OIDF conformance suite issues the mdoc with its own ephemeral CA and
 * ships the chain in the COSE {@code x5chain} (label 33), so there is usually no
 * externally pinned issuer anchor. This validator therefore checks
 * <em>chain integrity</em> — each certificate is signed by the next, every
 * certificate is within its validity window, and non-leaf certificates assert
 * the CA basic constraint — anchored either on a caller-supplied trust anchor or,
 * when none is given, on the chain's own self-signed root.
 *
 * <p>The {@code trustAnchor} parameter is the pluggable seam for a future pinned
 * IACA: pass a root and the chain must terminate at (or be signed by) it.
 */
public final class CertChainValidator {

    private CertChainValidator() {}

    /** Thrown when the chain fails any integrity or trust check. */
    public static final class ChainException extends Exception {
        public ChainException(String message) {
            super(message);
        }

        public ChainException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Validate the chain (leaf first). If {@code trustAnchor} is non-null, the
     * chain must chain up to it; otherwise the chain's own last certificate is
     * treated as the (self-signed) anchor.
     *
     * @param chain       certificates leaf → intermediate(s) → [root], leaf first
     * @param trustAnchor optional pinned anchor; null ⇒ anchor on the chain's root
     */
    public static void validate(List<X509Certificate> chain, X509Certificate trustAnchor)
            throws ChainException {
        if (chain == null || chain.isEmpty()) {
            throw new ChainException("Empty certificate chain");
        }

        // Every certificate must currently be within its validity window.
        for (X509Certificate cert : chain) {
            try {
                cert.checkValidity();
            } catch (Exception e) {
                throw new ChainException("Certificate not valid (expired or not yet valid): "
                        + cert.getSubjectX500Principal(), e);
            }
        }

        // Each certificate must be signed by the next one in the chain. Non-leaf
        // certificates must be CAs (basicConstraints pathLen >= 0).
        for (int i = 0; i < chain.size() - 1; i++) {
            X509Certificate subject = chain.get(i);
            X509Certificate issuer = chain.get(i + 1);
            requireCa(issuer);
            verifySignedBy(subject, issuer);
        }

        X509Certificate top = chain.get(chain.size() - 1);

        if (trustAnchor != null) {
            // The top of the supplied chain must be signed by (or equal to) the anchor.
            if (!top.equals(trustAnchor)) {
                requireCa(trustAnchor);
                verifySignedBy(top, trustAnchor);
            }
        } else {
            // No pinned anchor: the chain's root must be self-signed (its own anchor).
            verifySignedBy(top, top);
        }
    }

    private static void requireCa(X509Certificate cert) throws ChainException {
        if (cert.getBasicConstraints() < 0) {
            throw new ChainException("Issuer certificate is not a CA: " + cert.getSubjectX500Principal());
        }
    }

    private static void verifySignedBy(X509Certificate subject, X509Certificate issuer)
            throws ChainException {
        try {
            subject.verify(issuer.getPublicKey());
        } catch (Exception e) {
            throw new ChainException("Certificate " + subject.getSubjectX500Principal()
                    + " is not signed by " + issuer.getSubjectX500Principal(), e);
        }
    }
}
