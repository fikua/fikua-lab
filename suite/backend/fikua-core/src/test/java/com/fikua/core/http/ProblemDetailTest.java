package com.fikua.core.http;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ProblemDetailTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void notFound_hasCorrectFields() {
        var pd = ProblemDetail.notFound("/foo");
        assertEquals("about:blank", pd.type());
        assertEquals(404, pd.status());
        assertEquals("Not Found", pd.title());
        assertEquals("/foo", pd.instance());
    }

    @Test
    void methodNotAllowed_hasCorrectFields() {
        var pd = ProblemDetail.methodNotAllowed("/bar");
        assertEquals(405, pd.status());
        assertEquals("Method Not Allowed", pd.title());
    }

    @Test
    void internalError_hasCorrectFields() {
        var pd = ProblemDetail.internalError("/baz");
        assertEquals(500, pd.status());
        assertEquals("Internal Server Error", pd.title());
    }

    @Test
    void badRequest_preservesDetail() {
        var pd = ProblemDetail.badRequest("missing field X", "/api/test");
        assertEquals(400, pd.status());
        assertEquals("Bad Request", pd.title());
        assertEquals("missing field X", pd.detail());
    }

    @Test
    void serialize_usesCorrectFieldNames() throws Exception {
        var pd = ProblemDetail.notFound("/test");
        JsonNode json = MAPPER.valueToTree(pd);

        assertEquals("about:blank", json.get("type").asText());
        assertEquals(404, json.get("status").asInt());
        assertEquals("Not Found", json.get("title").asText());
        assertNotNull(json.get("detail"));
        assertEquals("/test", json.get("instance").asText());
    }

    @Test
    void serialize_nullInstance_omitted() throws Exception {
        var pd = ProblemDetail.of(400, "Bad Request", "test", null);
        JsonNode json = MAPPER.valueToTree(pd);

        assertNull(json.get("instance"));
    }

    @Test
    void CONTENT_TYPE_isApplicationProblemJson() {
        assertEquals("application/problem+json", ProblemDetail.CONTENT_TYPE);
    }
}
