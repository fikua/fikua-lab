package com.fikua.core.oid4vci;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CredentialResponseTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void success_hasCorrectFields() {
        var cr = CredentialResponse.success("eyJ...", "new-nonce");
        assertEquals("eyJ...", cr.credential());
        assertEquals("new-nonce", cr.cNonce());
        assertEquals(86400, cr.cNonceExpiresIn());
    }

    @Test
    void serialize_usesSnakeCaseFields() throws Exception {
        var cr = CredentialResponse.success("cred-data", "nonce-123");
        JsonNode json = MAPPER.valueToTree(cr);

        assertEquals("cred-data", json.get("credential").asText());
        assertEquals("nonce-123", json.get("c_nonce").asText());
        assertEquals(86400, json.get("c_nonce_expires_in").asInt());
    }

    @Test
    void serialize_nullCredential_omitted() throws Exception {
        var cr = new CredentialResponse(null, "nonce", 300);
        JsonNode json = MAPPER.valueToTree(cr);

        assertNull(json.get("credential"));
        assertEquals("nonce", json.get("c_nonce").asText());
    }

    @Test
    void serialize_nullNonce_omitted() throws Exception {
        var cr = new CredentialResponse("cred", null, null);
        JsonNode json = MAPPER.valueToTree(cr);

        assertEquals("cred", json.get("credential").asText());
        assertNull(json.get("c_nonce"));
        assertNull(json.get("c_nonce_expires_in"));
    }
}
