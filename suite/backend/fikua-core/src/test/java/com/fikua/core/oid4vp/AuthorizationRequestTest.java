package com.fikua.core.oid4vp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AuthorizationRequestTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void constants_haveCorrectValues() {
        assertEquals("vp_token", AuthorizationRequest.RESPONSE_TYPE_VP_TOKEN);
        assertEquals("oauth-authz-req+jwt", AuthorizationRequest.JAR_TYPE);
    }

    @Test
    void fullRequest_serializesCorrectly() throws Exception {
        var dcql = new DcqlQuery(List.of(
                new CredentialQuery("pid", "dc+sd-jwt",
                        new CredentialQuery.CredentialMeta(List.of("eu.europa.ec.eudi.pid.1")),
                        List.of(new ClaimQuery(List.of("given_name"), null, true)))
        ));

        var request = new AuthorizationRequest(
                "vp_token",
                "x509_san_dns:verifier.lab.fikua.com",
                "direct_post",
                "https://verifier.lab.fikua.com/oid4vp/v1/response",
                "n-0S6_WzA2Mj",
                "af0ifjsldkj",
                dcql,
                null,
                Map.of("vp_formats_supported", Map.of("dc+sd-jwt", Map.of())),
                "https://self-issued.me/v2",
                "x509_san_dns:verifier.lab.fikua.com",
                1709000000L,
                1709000300L
        );

        JsonNode json = MAPPER.valueToTree(request);
        assertEquals("vp_token", json.get("response_type").asText());
        assertEquals("x509_san_dns:verifier.lab.fikua.com", json.get("client_id").asText());
        assertEquals("direct_post", json.get("response_mode").asText());
        assertEquals("https://verifier.lab.fikua.com/oid4vp/v1/response", json.get("response_uri").asText());
        assertEquals("n-0S6_WzA2Mj", json.get("nonce").asText());
        assertEquals("af0ifjsldkj", json.get("state").asText());
        assertNotNull(json.get("dcql_query"));
        assertNull(json.get("scope"));
        assertEquals("https://self-issued.me/v2", json.get("aud").asText());
        assertEquals(1709000000L, json.get("iat").asLong());
        assertEquals(1709000300L, json.get("exp").asLong());
    }

    @Test
    void nullOptionalFields_omitted() throws Exception {
        var request = new AuthorizationRequest(
                "vp_token",
                "x509_san_dns:verifier.example.com",
                "direct_post",
                "https://verifier.example.com/response",
                "nonce123",
                "state456",
                null, null, null, null, null, null, null
        );

        JsonNode json = MAPPER.valueToTree(request);
        assertEquals("vp_token", json.get("response_type").asText());
        assertNull(json.get("dcql_query"));
        assertNull(json.get("scope"));
        assertNull(json.get("client_metadata"));
        assertNull(json.get("aud"));
        assertNull(json.get("iss"));
        assertNull(json.get("iat"));
        assertNull(json.get("exp"));
    }

    @Test
    void roundTrip_deserializesCorrectly() throws Exception {
        var original = new AuthorizationRequest(
                "vp_token",
                "x509_hash:abc123",
                "direct_post.jwt",
                "https://verifier.example.com/response",
                "nonce-xyz",
                "state-abc",
                new DcqlQuery(List.of(
                        new CredentialQuery("cred1", "dc+sd-jwt", null, null)
                )),
                null, null,
                "https://self-issued.me/v2",
                "x509_hash:abc123",
                1700000000L,
                1700000300L
        );

        String jsonStr = MAPPER.writeValueAsString(original);
        AuthorizationRequest deserialized = MAPPER.readValue(jsonStr, AuthorizationRequest.class);

        assertEquals("vp_token", deserialized.responseType());
        assertEquals("x509_hash:abc123", deserialized.clientId());
        assertEquals("direct_post.jwt", deserialized.responseMode());
        assertEquals("nonce-xyz", deserialized.nonce());
        assertEquals(1, deserialized.dcqlQuery().credentials().size());
    }

    @Test
    void verificationResult_success() throws Exception {
        var result = VerificationResult.success(Map.of("given_name", "Oriol", "family_name", "Canades"));

        JsonNode json = MAPPER.valueToTree(result);
        assertEquals("success", json.get("status").asText());
        assertEquals("Oriol", json.get("claims").get("given_name").asText());
        assertNull(json.get("error"));
        assertNull(json.get("error_description"));
    }

    @Test
    void verificationResult_error() throws Exception {
        var result = VerificationResult.error("invalid_request", "VP Token validation failed");

        JsonNode json = MAPPER.valueToTree(result);
        assertEquals("error", json.get("status").asText());
        assertNull(json.get("claims"));
        assertEquals("invalid_request", json.get("error").asText());
        assertEquals("VP Token validation failed", json.get("error_description").asText());
    }
}
