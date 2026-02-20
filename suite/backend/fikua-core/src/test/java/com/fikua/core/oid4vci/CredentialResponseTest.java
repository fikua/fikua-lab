package com.fikua.core.oid4vci;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CredentialResponseTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void success_hasCredentialsArray() {
        var cr = CredentialResponse.success("eyJ...");
        assertNotNull(cr.credentials());
        assertEquals(1, cr.credentials().size());
        assertEquals("eyJ...", cr.credentials().getFirst().get("credential"));
    }

    @Test
    void success_noCNonceInResponse() throws Exception {
        var cr = CredentialResponse.success("cred-data");
        JsonNode json = MAPPER.valueToTree(cr);

        assertNull(json.get("c_nonce"), "c_nonce must not appear in OID4VCI 1.0 Final credential response");
        assertNull(json.get("c_nonce_expires_in"), "c_nonce_expires_in must not appear in OID4VCI 1.0 Final credential response");
    }

    @Test
    void success_noSingularCredentialKey() throws Exception {
        var cr = CredentialResponse.success("cred-data");
        JsonNode json = MAPPER.valueToTree(cr);

        assertNull(json.get("credential"), "singular 'credential' key must not appear at top level");
        assertTrue(json.has("credentials"), "'credentials' (plural) must be present");
    }

    @Test
    void serialize_credentialsArrayFormat() throws Exception {
        var cr = CredentialResponse.success("eyJhbGciOiJFUzI1NiJ9...");
        JsonNode json = MAPPER.valueToTree(cr);

        assertTrue(json.get("credentials").isArray());
        assertEquals(1, json.get("credentials").size());
        assertEquals("eyJhbGciOiJFUzI1NiJ9...", json.get("credentials").get(0).get("credential").asText());
    }

    @Test
    void serialize_nullFieldsOmitted() throws Exception {
        var cr = CredentialResponse.success("cred");
        JsonNode json = MAPPER.valueToTree(cr);

        assertNull(json.get("transaction_id"));
        assertNull(json.get("notification_id"));
        // Only "credentials" should be present
        assertEquals(1, json.size(), "Only 'credentials' key should be present");
    }

    @Test
    void deferred_hasTransactionIdOnly() throws Exception {
        var cr = CredentialResponse.deferred("tx-123");
        JsonNode json = MAPPER.valueToTree(cr);

        assertNull(json.get("credentials"));
        assertEquals("tx-123", json.get("transaction_id").asText());
        assertEquals(1, json.size());
    }

    @Test
    void serialize_onlyAllowedKeys() throws Exception {
        var cr = CredentialResponse.success("cred");
        JsonNode json = MAPPER.valueToTree(cr);

        var allowedKeys = java.util.Set.of("credentials", "transaction_id", "notification_id");
        var fields = json.fieldNames();
        while (fields.hasNext()) {
            String key = fields.next();
            assertTrue(allowedKeys.contains(key),
                    "Unexpected key in credential response: " + key);
        }
    }
}
