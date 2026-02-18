package com.fikua.core.profile;

import com.fikua.core.profile.enums.*;

/**
 * Factory methods for well-known profile configurations
 * matching OIDF conformance test scenarios.
 */
public final class ProfilePresets {

    private ProfilePresets() {}

    /**
     * Simplest issuer profile: pre-authorized code, SD-JWT VC, no DPoP, no client auth.
     * Maps to OIDF test #2 with pre_authorization_code.
     */
    public static ProfileConfig plainPreAuthIssuer() {
        return new ProfileConfig(
                GrantType.PRE_AUTHORIZATION_CODE,
                null,  // No sender constraining for pre-auth
                null,  // No client auth for pre-auth
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
}
