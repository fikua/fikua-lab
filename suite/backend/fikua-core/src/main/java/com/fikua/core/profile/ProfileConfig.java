package com.fikua.core.profile;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fikua.core.profile.enums.*;

/**
 * Complete profile configuration for an OIDF conformance test scenario.
 * Nullable fields mean "not applicable" for the selected profile
 * (e.g. senderConstraining is null for pre_authorization_code).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ProfileConfig(
        // Issuance parameters
        GrantType grantType,
        SenderConstraining senderConstraining,
        ClientAuthType clientAuth,
        CredentialFormat credentialFormat,
        VciProfile vciProfile,
        CredentialOfferVariant credentialOffer,
        IssuanceMode issuanceMode,
        CredentialResponseEncryption credentialResponseEnc,
        Boolean par,
        String pkce,

        // Presentation parameters
        ClientIdPrefix clientIdPrefix,
        ResponseMode responseMode,
        QueryLanguage queryLanguage,

        // Common
        String requestMethod,
        String authRequestType
) {
    /** Returns true if this profile requires DPoP sender constraining. */
    @JsonIgnore
    public boolean requiresDPoP() {
        return senderConstraining == SenderConstraining.DPOP;
    }

    /** Returns true if this profile requires PAR. */
    @JsonIgnore
    public boolean requiresPar() {
        return Boolean.TRUE.equals(par);
    }

    /** Returns true if this profile requires PKCE. */
    @JsonIgnore
    public boolean requiresPkce() {
        return pkce != null;
    }

    /** Returns true if this is a HAIP profile. */
    @JsonIgnore
    public boolean isHaip() {
        return vciProfile == VciProfile.HAIP;
    }

    /** Returns true if this profile requires attestation-based client authentication. */
    @JsonIgnore
    public boolean requiresClientAttestation() {
        return clientAuth == ClientAuthType.CLIENT_ATTESTATION;
    }
}
