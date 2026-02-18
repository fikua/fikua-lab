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
    public static final String INVALID_PROOF = "invalid_proof";
    public static final String UNSUPPORTED_CREDENTIAL_TYPE = "unsupported_credential_type";
    public static final String UNSUPPORTED_CREDENTIAL_FORMAT = "unsupported_credential_format";

    public static OAuthError invalidRequest(String description) {
        return new OAuthError(INVALID_REQUEST, description);
    }

    public static OAuthError invalidGrant(String description) {
        return new OAuthError(INVALID_GRANT, description);
    }

    public static OAuthError invalidProof(String description) {
        return new OAuthError(INVALID_PROOF, description);
    }
}
