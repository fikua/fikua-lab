package com.fikua.core.oauth2;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class TokenRequestTest {

    @Test
    void fromParams_parsesPreAuthorizedCode() {
        var params = Map.of(
                "grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code", "code-123",
                "tx_code", "123456"
        );
        TokenRequest tr = TokenRequest.fromParams(params);
        assertEquals("urn:ietf:params:oauth:grant-type:pre-authorized_code", tr.grantType());
        assertEquals("code-123", tr.preAuthorizedCode());
        assertEquals("123456", tr.txCode());
        assertTrue(tr.isPreAuthorizedCode());
        assertFalse(tr.isAuthorizationCode());
    }

    @Test
    void fromParams_parsesAuthorizationCode() {
        var params = Map.of(
                "grant_type", "authorization_code",
                "code", "auth-code-789",
                "redirect_uri", "https://wallet.example.com/callback",
                "code_verifier", "verifier-xyz"
        );
        TokenRequest tr = TokenRequest.fromParams(params);
        assertTrue(tr.isAuthorizationCode());
        assertFalse(tr.isPreAuthorizedCode());
        assertEquals("auth-code-789", tr.code());
        assertEquals("https://wallet.example.com/callback", tr.redirectUri());
        assertEquals("verifier-xyz", tr.codeVerifier());
    }

    @Test
    void fromParams_missingFields_areNull() {
        var params = Map.of("grant_type", "authorization_code");
        TokenRequest tr = TokenRequest.fromParams(params);
        assertNull(tr.code());
        assertNull(tr.redirectUri());
        assertNull(tr.codeVerifier());
        assertNull(tr.preAuthorizedCode());
        assertNull(tr.txCode());
    }

    @Test
    void isPreAuthorizedCode_wrongGrantType_returnsFalse() {
        var tr = new TokenRequest("client_credentials", null, null, null, null, null);
        assertFalse(tr.isPreAuthorizedCode());
        assertFalse(tr.isAuthorizationCode());
    }

    @Test
    void isAuthorizationCode_exactMatch() {
        var tr = new TokenRequest("authorization_code", null, null, null, null, null);
        assertTrue(tr.isAuthorizationCode());
    }
}
