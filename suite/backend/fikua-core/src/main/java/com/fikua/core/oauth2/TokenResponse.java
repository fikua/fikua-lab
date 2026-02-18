package com.fikua.core.oauth2;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * OAuth2 token response per RFC 6749 + OID4VCI extensions.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record TokenResponse(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("token_type") String tokenType,
        @JsonProperty("expires_in") int expiresIn,
        @JsonProperty("c_nonce") String cNonce,
        @JsonProperty("c_nonce_expires_in") Integer cNonceExpiresIn,
        @JsonProperty("authorization_details") Object authorizationDetails
) {

    public static TokenResponse bearer(String accessToken, String cNonce) {
        return new TokenResponse(accessToken, "Bearer", 86400, cNonce, 86400, null);
    }

    public static TokenResponse dpop(String accessToken, String cNonce) {
        return new TokenResponse(accessToken, "DPoP", 86400, cNonce, 86400, null);
    }
}
