package com.fikua.core.oid4vp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DcqlQueryTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void eudiPidQuery_hasCorrectStructure() throws Exception {
        var query = new DcqlQuery(List.of(
                new CredentialQuery(
                        "identity_credential",
                        DcqlQuery.FORMAT_DC_SD_JWT,
                        CredentialQuery.CredentialMeta.sdJwt(List.of("eu.europa.ec.eudi.pid.1")),
                        List.of(
                                new ClaimQuery(List.of("given_name"), null, true),
                                new ClaimQuery(List.of("family_name"), null, true),
                                new ClaimQuery(List.of("birth_date"), null, null)
                        )
                )
        ));

        JsonNode json = MAPPER.valueToTree(query);
        JsonNode cred = json.get("credentials").get(0);
        assertEquals("identity_credential", cred.get("id").asText());
        assertEquals("dc+sd-jwt", cred.get("format").asText());
        assertEquals("eu.europa.ec.eudi.pid.1", cred.get("meta").get("vct_values").get(0).asText());

        JsonNode claims = cred.get("claims");
        assertEquals(3, claims.size());
        assertEquals("given_name", claims.get(0).get("path").get(0).asText());
        assertTrue(claims.get(0).get("essential").asBoolean());
        assertNull(claims.get(2).get("essential"));
    }

    @Test
    void nullOptionalFields_omitted() throws Exception {
        var query = new DcqlQuery(List.of(
                new CredentialQuery("cred1", "dc+sd-jwt", null, null)
        ));

        JsonNode json = MAPPER.valueToTree(query);
        JsonNode cred = json.get("credentials").get(0);
        assertNull(cred.get("meta"));
        assertNull(cred.get("claims"));
    }

    @Test
    void claimQuery_withValues_serializesCorrectly() throws Exception {
        var claim = new ClaimQuery(List.of("nationality"), List.of("ES", "EU"), true);

        JsonNode json = MAPPER.valueToTree(claim);
        assertEquals("nationality", json.get("path").get(0).asText());
        assertEquals(2, json.get("values").size());
        assertEquals("ES", json.get("values").get(0).asText());
        assertTrue(json.get("essential").asBoolean());
    }

    @Test
    void roundTrip_deserializesCorrectly() throws Exception {
        var original = new DcqlQuery(List.of(
                new CredentialQuery(
                        "pid",
                        "dc+sd-jwt",
                        CredentialQuery.CredentialMeta.sdJwt(List.of("eu.europa.ec.eudi.pid.1")),
                        List.of(new ClaimQuery(List.of("given_name"), null, null))
                )
        ));

        String jsonStr = MAPPER.writeValueAsString(original);
        DcqlQuery deserialized = MAPPER.readValue(jsonStr, DcqlQuery.class);

        assertEquals(1, deserialized.credentials().size());
        assertEquals("pid", deserialized.credentials().getFirst().id());
        assertEquals("dc+sd-jwt", deserialized.credentials().getFirst().format());
        assertEquals("eu.europa.ec.eudi.pid.1",
                deserialized.credentials().getFirst().meta().vctValues().getFirst());
        assertEquals("given_name",
                deserialized.credentials().getFirst().claims().getFirst().path().getFirst());
    }

    @Test
    void formatConstants_haveCorrectValues() {
        assertEquals("dc+sd-jwt", DcqlQuery.FORMAT_DC_SD_JWT);
        assertEquals("mso_mdoc", DcqlQuery.FORMAT_MSO_MDOC);
    }
}
