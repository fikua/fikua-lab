package com.fikua.core.oauth2;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * OAuth2 error response per RFC 6749 Section 5.2.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record OAuthError(
        @JsonProperty("error") String error,
        @JsonProperty("error_description") String errorDescription
) {

    public static final String INVALID_REQUEST = "invalid_request";
    public static final String INVALID_GRANT = "invalid_grant";
    public static final String INVALID_CLIENT = "invalid_client";
    public static final String UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";
    public static final String INVALID_TOKEN = "invalid_token";
    public static final String UNSUPPORTED_CREDENTIAL_TYPE = "unsupported_credential_type";
    public static final String UNSUPPORTED_CREDENTIAL_FORMAT = "unsupported_credential_format";

    /** OID4VCI 1.0 Final §8.3.1 — proof is missing, invalid, or does not contain c_nonce. */
    public static final String INVALID_OR_MISSING_PROOF = "invalid_or_missing_proof";

    /** OID4VCI 1.0 Final §8.3.1 — c_nonce in proof is invalid/expired. Wallet should request a new nonce. */
    public static final String INVALID_NONCE = "invalid_nonce";

    public static OAuthError invalidRequest(String description) {
        return new OAuthError(INVALID_REQUEST, description);
    }

    public static OAuthError invalidGrant(String description) {
        return new OAuthError(INVALID_GRANT, description);
    }

    public static OAuthError invalidProof(String description) {
        return new OAuthError(INVALID_OR_MISSING_PROOF, description);
    }

    public static OAuthError invalidToken(String description) {
        return new OAuthError(INVALID_TOKEN, description);
    }

    public static OAuthError invalidNonce(String description) {
        return new OAuthError(INVALID_NONCE, description);
    }

    public static OAuthError invalidClient(String description) {
        return new OAuthError(INVALID_CLIENT, description);
    }

    public static OAuthError unsupportedGrantType(String description) {
        return new OAuthError(UNSUPPORTED_GRANT_TYPE, description);
    }

    public static OAuthError unsupportedCredentialFormat(String description) {
        return new OAuthError(UNSUPPORTED_CREDENTIAL_FORMAT, description);
    }
}
