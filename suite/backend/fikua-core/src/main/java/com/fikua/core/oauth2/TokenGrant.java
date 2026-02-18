package com.fikua.core.oauth2;

/**
 * Sealed interface representing OAuth2 token grant types supported by OID4VCI.
 */
public sealed interface TokenGrant {

    /** Pre-authorized code grant (simplest flow, no user interaction). */
    record PreAuthorizedCode(
            String preAuthorizedCode,
            String txCode
    ) implements TokenGrant {}

    /** Authorization code grant (standard OAuth2 flow with PAR/PKCE). */
    record AuthorizationCode(
            String code,
            String redirectUri,
            String codeVerifier
    ) implements TokenGrant {}
}
