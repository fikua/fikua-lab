package com.fikua.core.oauth2;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * OAuth2 token response per RFC 6749 §5.1.
 *
 * OID4VCI 1.0 Final: c_nonce is no longer in the token response.
 * The wallet must call the Nonce Endpoint (§7) to obtain a c_nonce.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record TokenResponse(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("token_type") String tokenType,
        @JsonProperty("expires_in") int expiresIn,
        @JsonProperty("scope") String scope,
        @JsonProperty("authorization_details") Object authorizationDetails
) {

    public static TokenResponse bearer(String accessToken) {
        return new TokenResponse(accessToken, "Bearer", 86400, null, null);
    }

    public static TokenResponse dpop(String accessToken) {
        return new TokenResponse(accessToken, "DPoP", 86400, null, null);
    }
}
