package com.fikua.core.oid4vci;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CredentialOfferTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void preAuthorized_hasCorrectStructure() throws Exception {
        var offer = CredentialOffer.preAuthorized(
                "https://issuer.example.com", "eu.europa.ec.eudi.pid_jwt_vc_json",
                "pre-auth-code-123", false);

        JsonNode json = MAPPER.valueToTree(offer);
        assertEquals("https://issuer.example.com", json.get("credential_issuer").asText());
        assertEquals("eu.europa.ec.eudi.pid_jwt_vc_json",
                json.get("credential_configuration_ids").get(0).asText());
    }

    @Test
    void preAuthorized_containsGrantWithPreAuthCode() throws Exception {
        var offer = CredentialOffer.preAuthorized(
                "https://issuer.example.com", "pid", "code-abc", false);

        JsonNode json = MAPPER.valueToTree(offer);
        JsonNode grant = json.get("grants")
                .get("urn:ietf:params:oauth:grant-type:pre-authorized_code");
        assertNotNull(grant);
        assertEquals("code-abc", grant.get("pre-authorized_code").asText());
        assertNull(grant.get("tx_code"));
    }

    @Test
    void preAuthorized_withTxCode_includesTxCodeObject() throws Exception {
        var offer = CredentialOffer.preAuthorized(
                "https://issuer.example.com", "pid", "code-abc", true);

        JsonNode json = MAPPER.valueToTree(offer);
        JsonNode grant = json.get("grants")
                .get("urn:ietf:params:oauth:grant-type:pre-authorized_code");
        JsonNode txCode = grant.get("tx_code");
        assertNotNull(txCode);
        assertEquals("numeric", txCode.get("input_mode").asText());
        assertEquals(6, txCode.get("length").asInt());
    }

    @Test
    void authorizationCode_hasCorrectStructure() throws Exception {
        var offer = CredentialOffer.authorizationCode(
                "https://issuer.example.com", "pid", "state-123");

        JsonNode json = MAPPER.valueToTree(offer);
        assertEquals("https://issuer.example.com", json.get("credential_issuer").asText());

        JsonNode grant = json.get("grants").get("authorization_code");
        assertNotNull(grant);
        assertEquals("state-123", grant.get("issuer_state").asText());
        // M3: authorization_server in grant object per OID4VCI 1.0 Final §4.1.1
        assertEquals("https://issuer.example.com", grant.get("authorization_server").asText());
    }

    @Test
    void authorizationCode_nullIssuerState_omitsField() throws Exception {
        var offer = CredentialOffer.authorizationCode(
                "https://issuer.example.com", "pid", null);

        JsonNode json = MAPPER.valueToTree(offer);
        JsonNode grant = json.get("grants").get("authorization_code");
        assertNotNull(grant);
        assertNull(grant.get("issuer_state"));
    }

    @Test
    void serialize_nullGrants_omitted() throws Exception {
        var offer = new CredentialOffer("https://issuer.example.com",
                java.util.List.of("pid"), null);
        JsonNode json = MAPPER.valueToTree(offer);
        assertNull(json.get("grants"));
    }
}
