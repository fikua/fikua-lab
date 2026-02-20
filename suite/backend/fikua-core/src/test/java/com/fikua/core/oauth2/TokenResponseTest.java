package com.fikua.core.oauth2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TokenResponseTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void bearer_hasCorrectTokenType() {
        var tr = TokenResponse.bearer("tok-123");
        assertEquals("Bearer", tr.tokenType());
        assertEquals("tok-123", tr.accessToken());
    }

    @Test
    void dpop_hasCorrectTokenType() {
        var tr = TokenResponse.dpop("tok-456");
        assertEquals("DPoP", tr.tokenType());
    }

    @Test
    void serialize_usesSnakeCaseFields() throws Exception {
        var tr = TokenResponse.bearer("tok");
        JsonNode json = MAPPER.valueToTree(tr);

        assertEquals("tok", json.get("access_token").asText());
        assertEquals("Bearer", json.get("token_type").asText());
        assertEquals(86400, json.get("expires_in").asInt());
    }

    @Test
    void serialize_noCNonce_inTokenResponse() throws Exception {
        // OID4VCI 1.0 Final: c_nonce is NOT in token response (moved to Nonce Endpoint §7)
        var tr = TokenResponse.bearer("tok");
        JsonNode json = MAPPER.valueToTree(tr);

        assertNull(json.get("c_nonce"), "c_nonce must NOT be in token response");
        assertNull(json.get("c_nonce_expires_in"), "c_nonce_expires_in must NOT be in token response");
    }

    @Test
    void serialize_nullAuthorizationDetails_omitted() throws Exception {
        var tr = TokenResponse.bearer("tok");
        JsonNode json = MAPPER.valueToTree(tr);

        assertNull(json.get("authorization_details"));
    }
}
