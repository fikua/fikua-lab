package com.fikua.core.profile;

import com.fikua.core.profile.enums.*;

/**
 * Factory methods for well-known profile configurations
 * matching OIDF conformance test scenarios.
 */
public final class ProfilePresets {

    private ProfilePresets() {}

    /**
     * Plain issuer profile: supports both pre-authorized_code and authorization_code.
     * No DPoP, no PAR, no PKCE, no client attestation.
     * Grant type is selected per-issuance via the UI.
     */
    public static ProfileConfig plainIssuer() {
        return new ProfileConfig(
                null,  // Grant type decided per-issuance
                null,  // No sender constraining
                null,  // No client auth
                CredentialFormat.SD_JWT_VC,
                VciProfile.PLAIN,
                CredentialOfferVariant.BY_REFERENCE,
                IssuanceMode.IMMEDIATE,
                CredentialResponseEncryption.PLAIN,
                null,  // No PAR
                null,  // No PKCE
                null,  // No client ID prefix (issuer role)
                null,  // No response mode (issuer role)
                null,  // No query language (issuer role)
                "unsigned",
                "simple"
        );
    }

    /**
     * HAIP issuer profile: authorization code, DPoP, PAR, PKCE S256, client attestation.
     * Maps to OIDF test #1 (Final/HAIP).
     */
    public static ProfileConfig haipIssuer() {
        return new ProfileConfig(
                GrantType.AUTHORIZATION_CODE,
                SenderConstraining.DPOP,
                ClientAuthType.CLIENT_ATTESTATION,
                CredentialFormat.SD_JWT_VC,
                VciProfile.HAIP,
                CredentialOfferVariant.BY_REFERENCE,
                IssuanceMode.IMMEDIATE,
                CredentialResponseEncryption.PLAIN,
                true,   // PAR required
                "S256", // PKCE required
                null,
                null,
                null,
                "unsigned",
                "simple"
        );
    }

    /**
     * Plain verifier profile: SD-JWT VC, x509_san_dns, signed request_uri, direct_post.
     * Maps to OIDF test #6 with plain_vp profile.
     */
    public static ProfileConfig plainVerifier() {
        return new ProfileConfig(
                null, null, null,
                CredentialFormat.SD_JWT_VC,
                null, null, null, null, null, null,
                ClientIdPrefix.X509_SAN_DNS,
                ResponseMode.DIRECT_POST,
                null,
                "request_uri_signed",
                null
        );
    }

    /**
     * HAIP verifier profile: SD-JWT VC, x509_hash, JAR, direct_post.jwt, DCQL.
     * Maps to OIDF test #5 (Final/HAIP).
     */
    public static ProfileConfig haipVerifier() {
        return new ProfileConfig(
                null, null, null,
                CredentialFormat.SD_JWT_VC,
                null, null, null, null, null, null,
                ClientIdPrefix.X509_HASH,
                ResponseMode.DIRECT_POST_JWT,
                QueryLanguage.DCQL,
                "request_uri_signed",
                null
        );
    }

    /**
     * HAIP verifier profile for ISO mdoc (mso_mdoc): x509_hash, JAR,
     * direct_post.jwt, DCQL. Same as {@link #haipVerifier()} but requests the
     * mso_mdoc credential format. Maps to the OIDF iso_mdl verifier variant.
     */
    public static ProfileConfig haipMdocVerifier() {
        return new ProfileConfig(
                null, null, null,
                CredentialFormat.MDOC,
                null, null, null, null, null, null,
                ClientIdPrefix.X509_HASH,
                ResponseMode.DIRECT_POST_JWT,
                QueryLanguage.DCQL,
                "request_uri_signed",
                null
        );
    }
}
