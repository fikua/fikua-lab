package com.fikua.core.oid4vci;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fikua.core.profile.ProfilePresets;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CredentialIssuerMetadataTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String BASE_URL = "https://issuer.lab.fikua.com";

    @Test
    void build_withPreAuthProfile_returnsCorrectTopLevelFields() throws Exception {
        var metadata = CredentialIssuerMetadata.build(BASE_URL, ProfilePresets.plainPreAuthIssuer());
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
        var metadata = CredentialIssuerMetadata.build(BASE_URL, ProfilePresets.plainPreAuthIssuer());
        JsonNode json = MAPPER.valueToTree(metadata);

        String configKey = "eu.europa.ec.eudi.pid_dc+sd-jwt";
        JsonNode configs = json.get("credential_configurations_supported");
        assertNotNull(configs.get(configKey), "Config key should be " + configKey);

        JsonNode config = configs.get(configKey);
        assertEquals("dc+sd-jwt", config.get("format").asText());
        assertEquals("eu.europa.ec.eudi.pid_dc+sd-jwt", config.get("scope").asText());
    }

    @Test
    void build_credentialConfig_hasCorrectCryptoFields() throws Exception {
        var metadata = CredentialIssuerMetadata.build(BASE_URL, ProfilePresets.plainPreAuthIssuer());
        JsonNode config = MAPPER.valueToTree(metadata)
                .get("credential_configurations_supported")
                .get("eu.europa.ec.eudi.pid_dc+sd-jwt");

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
        var metadata = CredentialIssuerMetadata.build(BASE_URL, ProfilePresets.plainPreAuthIssuer());
        JsonNode config = MAPPER.valueToTree(metadata)
                .get("credential_configurations_supported")
                .get("eu.europa.ec.eudi.pid_dc+sd-jwt");

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
    void build_withHaipProfile_includesCredentialResponseEncryption() throws Exception {
        var metadata = CredentialIssuerMetadata.build(BASE_URL, ProfilePresets.haipIssuer());
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
    void build_withPreAuthProfile_omitsCredentialResponseEncryption() throws Exception {
        var metadata = CredentialIssuerMetadata.build(BASE_URL, ProfilePresets.plainPreAuthIssuer());
        JsonNode json = MAPPER.valueToTree(metadata);

        assertNull(json.get("credential_response_encryption"),
                "Pre-auth profile must NOT include credential_response_encryption");
    }

    @Test
    void build_noOldFormatFields_present() throws Exception {
        var metadata = CredentialIssuerMetadata.build(BASE_URL, ProfilePresets.plainPreAuthIssuer());
        String json = MAPPER.writeValueAsString(metadata);

        // Must NOT contain old vc+sd-jwt references
        assertFalse(json.contains("vc+sd-jwt"), "JSON must not contain vc+sd-jwt");
        // Must contain new dc+sd-jwt references
        assertTrue(json.contains("dc+sd-jwt"), "JSON must contain dc+sd-jwt");
    }
}
