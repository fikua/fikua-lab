package com.fikua.core.oid4vci;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AuthServerMetadataTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String BASE_URL = "https://issuer.lab.fikua.com";

    @Test
    void forPreAuthProfile_returnsCorrectFields() throws Exception {
        var metadata = AuthServerMetadata.forPreAuthProfile(BASE_URL);
        JsonNode json = MAPPER.valueToTree(metadata);

        assertEquals(BASE_URL, json.get("issuer").asText());
        assertEquals(BASE_URL + "/oid4vci/v1/token", json.get("token_endpoint").asText());
        assertEquals(BASE_URL + "/oid4vci/v1/jwks", json.get("jwks_uri").asText());
        assertTrue(json.get("pre-authorized_grant_anonymous_access_supported").asBoolean());

        // Pre-auth profile should NOT have authorization_endpoint or PAR (omitted by @JsonInclude(NON_NULL))
        assertNull(json.get("authorization_endpoint"));
        assertNull(json.get("pushed_authorization_request_endpoint"));
    }

    @Test
    void forHaipProfile_returnsCorrectFields() throws Exception {
        var metadata = AuthServerMetadata.forHaipProfile(BASE_URL);
        JsonNode json = MAPPER.valueToTree(metadata);

        assertEquals(BASE_URL, json.get("issuer").asText());
        assertEquals(BASE_URL + "/oid4vci/v1/token", json.get("token_endpoint").asText());
        assertEquals(BASE_URL + "/oid4vci/v1/authorize", json.get("authorization_endpoint").asText());
        assertEquals(BASE_URL + "/oid4vci/v1/par", json.get("pushed_authorization_request_endpoint").asText());
        assertEquals("S256", json.get("code_challenge_methods_supported").get(0).asText());
        assertEquals("attest_jwt_client_auth", json.get("token_endpoint_auth_methods_supported").get(0).asText());
        assertEquals("ES256", json.get("dpop_signing_alg_values_supported").get(0).asText());
    }

    @Test
    void noProfile_containsNoCredentialNonceEndpoint() throws Exception {
        // credential_nonce_endpoint belongs in Credential Issuer Metadata, NOT in AS Metadata
        var preAuth = AuthServerMetadata.forPreAuthProfile(BASE_URL);
        var haip = AuthServerMetadata.forHaipProfile(BASE_URL);

        String preAuthJson = MAPPER.writeValueAsString(preAuth);
        String haipJson = MAPPER.writeValueAsString(haip);

        assertFalse(preAuthJson.contains("credential_nonce_endpoint"),
                "AS metadata must NOT contain credential_nonce_endpoint");
        assertFalse(haipJson.contains("credential_nonce_endpoint"),
                "AS metadata must NOT contain credential_nonce_endpoint");
    }
}
