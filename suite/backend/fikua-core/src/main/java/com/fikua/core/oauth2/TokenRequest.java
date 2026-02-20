package com.fikua.core.oauth2;

import java.util.Map;

/**
 * Parsed OAuth2 token request from form-urlencoded body.
 */
public record TokenRequest(
        String grantType,
        String code,
        String redirectUri,
        String codeVerifier,
        String preAuthorizedCode,
        String txCode,
        String authorizationDetails
) {

    /** Parse from form parameters map. */
    public static TokenRequest fromParams(Map<String, String> params) {
        return new TokenRequest(
                params.get("grant_type"),
                params.get("code"),
                params.get("redirect_uri"),
                params.get("code_verifier"),
                params.get("pre-authorized_code"),
                params.get("tx_code"),
                params.get("authorization_details")
        );
    }

    public boolean isPreAuthorizedCode() {
        return "urn:ietf:params:oauth:grant-type:pre-authorized_code".equals(grantType);
    }

    public boolean isAuthorizationCode() {
        return "authorization_code".equals(grantType);
    }
}
