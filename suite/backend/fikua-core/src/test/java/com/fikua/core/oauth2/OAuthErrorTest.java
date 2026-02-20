package com.fikua.core.oauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class OAuthErrorTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void serialize_usesSnakeCase() throws Exception {
        var error = new OAuthError("invalid_request", "test description");
        String json = MAPPER.writeValueAsString(error);

        assertTrue(json.contains("\"error\""));
        assertTrue(json.contains("\"error_description\""));
        assertFalse(json.contains("errorDescription"));
    }

    @Test
    void serialize_nullDescription_omitted() throws Exception {
        var error = new OAuthError("invalid_request", null);
        JsonNode json = MAPPER.valueToTree(error);

        assertEquals("invalid_request", json.get("error").asText());
        assertNull(json.get("error_description"));
    }

    @Test
    void invalidRequest_hasCorrectCode() {
        assertEquals("invalid_request", OAuthError.invalidRequest("x").error());
    }

    @Test
    void invalidGrant_hasCorrectCode() {
        assertEquals("invalid_grant", OAuthError.invalidGrant("x").error());
    }

    @Test
    void invalidProof_hasCorrectCode() {
        assertEquals("invalid_proof", OAuthError.invalidProof("x").error());
    }

    @Test
    void invalidToken_hasCorrectCode() {
        assertEquals("invalid_token", OAuthError.invalidToken("x").error());
    }

    @Test
    void invalidClient_hasCorrectCode() {
        assertEquals("invalid_client", OAuthError.invalidClient("x").error());
    }

    @Test
    void unsupportedGrantType_hasCorrectCode() {
        assertEquals("unsupported_grant_type", OAuthError.unsupportedGrantType("x").error());
    }

    @Test
    void unsupportedCredentialFormat_hasCorrectCode() {
        assertEquals("unsupported_credential_format", OAuthError.unsupportedCredentialFormat("x").error());
    }
}
