package com.fikua.core.oid4vci;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CredentialRequestTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void deserialize_withCredentialConfigurationId() throws Exception {
        String json = """
                {
                  "credential_configuration_id": "eu.europa.ec.eudi.pid.1",
                  "proof": {
                    "proof_type": "jwt",
                    "jwt": "eyJ..."
                  }
                }
                """;

        CredentialRequest request = MAPPER.readValue(json, CredentialRequest.class);

        assertEquals("eu.europa.ec.eudi.pid.1", request.credentialConfigurationId());
        assertNull(request.format(), "format should be null when credential_configuration_id is used");
        assertNotNull(request.proof());
        assertEquals("jwt", request.proof().proofType());
    }

    @Test
    void deserialize_withFormat_backwardsCompatible() throws Exception {
        String json = """
                {
                  "format": "dc+sd-jwt",
                  "proof": {
                    "proof_type": "jwt",
                    "jwt": "eyJ..."
                  }
                }
                """;

        CredentialRequest request = MAPPER.readValue(json, CredentialRequest.class);

        assertEquals("dc+sd-jwt", request.format());
        assertNull(request.credentialConfigurationId());
    }

    @Test
    void deserialize_withBothFields() throws Exception {
        String json = """
                {
                  "credential_configuration_id": "eu.europa.ec.eudi.pid.1",
                  "format": "dc+sd-jwt",
                  "proof": {
                    "proof_type": "jwt",
                    "jwt": "eyJ..."
                  }
                }
                """;

        CredentialRequest request = MAPPER.readValue(json, CredentialRequest.class);

        assertEquals("eu.europa.ec.eudi.pid.1", request.credentialConfigurationId());
        assertEquals("dc+sd-jwt", request.format());
    }

    @Test
    void serialize_credentialConfigurationId_usesSnakeCase() throws Exception {
        CredentialRequest request = new CredentialRequest(
                null, "eu.europa.ec.eudi.pid.1", null, null, null
        );

        String json = MAPPER.writeValueAsString(request);
        assertTrue(json.contains("\"credential_configuration_id\""),
                "JSON must use snake_case: credential_configuration_id");
        assertFalse(json.contains("credentialConfigurationId"),
                "JSON must not use camelCase");
    }
}
