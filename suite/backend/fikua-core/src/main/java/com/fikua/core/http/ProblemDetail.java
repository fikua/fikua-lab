package com.fikua.core.http;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * RFC 9457 Problem Details for HTTP APIs.
 * Used for non-protocol errors (admin endpoints, 404, 500).
 * Protocol endpoints (OID4VCI, OAuth2) use OAuthError instead.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ProblemDetail(
        @JsonProperty("type") String type,
        @JsonProperty("status") int status,
        @JsonProperty("title") String title,
        @JsonProperty("detail") String detail,
        @JsonProperty("instance") String instance
) {

    public static final String CONTENT_TYPE = "application/problem+json";

    public static ProblemDetail of(int status, String title, String detail, String instance) {
        return new ProblemDetail("about:blank", status, title, detail, instance);
    }

    public static ProblemDetail notFound(String instance) {
        return of(404, "Not Found", "The requested resource was not found", instance);
    }

    public static ProblemDetail methodNotAllowed(String instance) {
        return of(405, "Method Not Allowed", "HTTP method not allowed for this endpoint", instance);
    }

    public static ProblemDetail internalError(String instance) {
        return of(500, "Internal Server Error", "An unexpected error occurred", instance);
    }

    public static ProblemDetail badRequest(String detail, String instance) {
        return of(400, "Bad Request", detail, instance);
    }
}
