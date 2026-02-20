package com.fikua.core.oid4vci;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class CredentialIssuerMetadataTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String BASE_URL = "https://issuer.lab.fikua.com";
    private static final String API_PREFIX = "/oid4vci/v1";
    private static final String CREDENTIAL_CONFIG_ID = "eu.europa.ec.eudi.pid_dc+sd-jwt";

    @Test
    void build_returnsCorrectTopLevelFields() throws Exception {
        var metadata = buildMetadata(false);
        JsonNode json = MAPPER.valueToTree(metadata);

        assertEquals(BASE_URL, json.get("credential_issuer").asText());
        assertEquals(BASE_URL + "/oid4vci/v1/credential", json.get("credential_endpoint").asText());
        assertEquals(BASE_URL + "/oid4vci/v1/nonce", json.get("nonce_endpoint").asText());
        assertEquals(BASE_URL + "/oid4vci/v1/notification", json.get("notification_endpoint").asText());
        assertNotNull(json.get("credential_configurations_supported"));
        assertNotNull(json.get("display"));
    }

    @Test
    void build_credentialConfig_usesDcSdJwtFormat() throws Exception {
        var metadata = buildMetadata(false);
        JsonNode json = MAPPER.valueToTree(metadata);

        JsonNode configs = json.get("credential_configurations_supported");
        assertNotNull(configs.get(CREDENTIAL_CONFIG_ID), "Config key should be " + CREDENTIAL_CONFIG_ID);

        JsonNode config = configs.get(CREDENTIAL_CONFIG_ID);
        assertEquals("dc+sd-jwt", config.get("format").asText());
        assertEquals("eu.europa.ec.eudi.pid_dc+sd-jwt", config.get("scope").asText());
    }

    @Test
    void build_credentialConfig_hasCorrectCryptoFields() throws Exception {
        var metadata = buildMetadata(false);
        JsonNode config = MAPPER.valueToTree(metadata)
                .get("credential_configurations_supported")
                .get(CREDENTIAL_CONFIG_ID);

        assertEquals("jwk", config.get("cryptographic_binding_methods_supported").get(0).asText());
        assertEquals("ES256", config.get("credential_signing_alg_values_supported").get(0).asText());
        assertEquals("eu.europa.ec.eudi.pid.1", config.get("vct").asText());

        // proof_types_supported
        JsonNode proofTypes = config.get("proof_types_supported");
        assertNotNull(proofTypes.get("jwt"));
        assertEquals("ES256", proofTypes.get("jwt").get("proof_signing_alg_values_supported").get(0).asText());
    }

    @Test
    void build_credentialMetadata_hasClaimsWithPathFormat() throws Exception {
        var metadata = buildMetadata(false);
        JsonNode config = MAPPER.valueToTree(metadata)
                .get("credential_configurations_supported")
                .get(CREDENTIAL_CONFIG_ID);

        // Claims should be inside credential_metadata, not at top level
        assertNull(config.get("claims"), "claims should NOT be at config top level");
        assertNull(config.get("display"), "display should NOT be at config top level");

        JsonNode credentialMetadata = config.get("credential_metadata");
        assertNotNull(credentialMetadata, "credential_metadata should exist");

        // Display inside credential_metadata
        JsonNode display = credentialMetadata.get("display");
        assertNotNull(display);
        assertEquals("EUDI PID", display.get(0).get("name").asText());

        // Claims array with path format
        JsonNode claims = credentialMetadata.get("claims");
        assertNotNull(claims);
        assertTrue(claims.isArray());
        assertEquals(5, claims.size());

        // Verify first claim has path array
        JsonNode firstClaim = claims.get(0);
        assertTrue(firstClaim.get("path").isArray());
        assertEquals("given_name", firstClaim.get("path").get(0).asText());
        assertEquals("Given Name", firstClaim.get("display").get(0).get("name").asText());
    }

    @Test
    void build_withHaip_includesCredentialResponseEncryption() throws Exception {
        var metadata = buildMetadata(true);
        JsonNode json = MAPPER.valueToTree(metadata);

        JsonNode encryption = json.get("credential_response_encryption");
        assertNotNull(encryption, "HAIP profile must include credential_response_encryption");

        // alg_values_supported: ECDH-ES (HAIP required)
        JsonNode algs = encryption.get("alg_values_supported");
        assertNotNull(algs);
        assertEquals("ECDH-ES", algs.get(0).asText());

        // enc_values_supported: A128GCM, A256GCM
        JsonNode encs = encryption.get("enc_values_supported");
        assertNotNull(encs);
        assertEquals(2, encs.size());
        assertEquals("A128GCM", encs.get(0).asText());
        assertEquals("A256GCM", encs.get(1).asText());

        // encryption_required: false
        assertFalse(encryption.get("encryption_required").asBoolean());
    }

    @Test
    void build_withoutHaip_omitsCredentialResponseEncryption() throws Exception {
        var metadata = buildMetadata(false);
        JsonNode json = MAPPER.valueToTree(metadata);

        assertNull(json.get("credential_response_encryption"),
                "Non-HAIP must NOT include credential_response_encryption");
    }

    @Test
    void build_noOldFormatFields_present() throws Exception {
        var metadata = buildMetadata(false);
        String json = MAPPER.writeValueAsString(metadata);

        // Must NOT contain old vc+sd-jwt references
        assertFalse(json.contains("vc+sd-jwt"), "JSON must not contain vc+sd-jwt");
        // Must contain new dc+sd-jwt references
        assertTrue(json.contains("dc+sd-jwt"), "JSON must contain dc+sd-jwt");
    }

    /** Build test metadata with the PID credential configuration. */
    private CredentialIssuerMetadata buildMetadata(boolean haip) {
        return CredentialIssuerMetadata.build(
                BASE_URL,
                BASE_URL + API_PREFIX + "/credential",
                BASE_URL + API_PREFIX + "/nonce",
                BASE_URL + API_PREFIX + "/notification",
                buildPidCredentialConfigurations(),
                List.of(Map.<String, Object>of("name", "Fikua Lab Issuer", "locale", "en")),
                haip
        );
    }

    private Map<String, Object> buildPidCredentialConfigurations() {
        var credConfig = new LinkedHashMap<String, Object>();
        credConfig.put("format", "dc+sd-jwt");
        credConfig.put("scope", "eu.europa.ec.eudi.pid_dc+sd-jwt");
        credConfig.put("cryptographic_binding_methods_supported", List.of("jwk"));
        credConfig.put("credential_signing_alg_values_supported", List.of("ES256"));
        credConfig.put("proof_types_supported", Map.of(
                "jwt", Map.of("proof_signing_alg_values_supported", List.of("ES256"))
        ));
        credConfig.put("vct", "eu.europa.ec.eudi.pid.1");

        var claims = List.of(
                Map.of("path", List.of("given_name"), "display", List.of(Map.of("name", "Given Name", "locale", "en"))),
                Map.of("path", List.of("family_name"), "display", List.of(Map.of("name", "Surname", "locale", "en"))),
                Map.of("path", List.of("birth_date"), "display", List.of(Map.of("name", "Date of Birth", "locale", "en"))),
                Map.of("path", List.of("issuing_authority"), "display", List.of(Map.of("name", "Issuing Authority", "locale", "en"))),
                Map.of("path", List.of("issuing_country"), "display", List.of(Map.of("name", "Issuing Country", "locale", "en")))
        );

        var credentialMetadata = new LinkedHashMap<String, Object>();
        credentialMetadata.put("display", List.of(Map.of(
                "name", "EUDI PID",
                "locale", "en",
                "description", "EU Digital Identity Personal Identification Data"
        )));
        credentialMetadata.put("claims", claims);
        credConfig.put("credential_metadata", credentialMetadata);

        return Map.of(CREDENTIAL_CONFIG_ID, credConfig);
    }
}
