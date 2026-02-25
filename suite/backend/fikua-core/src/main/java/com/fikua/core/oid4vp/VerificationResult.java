package com.fikua.core.oid4vp;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * Result of a VP Token verification.
 * Contains either verified claims (success) or error details (failure).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record VerificationResult(
        @JsonProperty("status") String status,
        @JsonProperty("claims") Map<String, Object> claims,
        @JsonProperty("error") String error,
        @JsonProperty("error_description") String errorDescription
) {

    public static final String STATUS_SUCCESS = "success";
    public static final String STATUS_ERROR = "error";

    public static VerificationResult success(Map<String, Object> claims) {
        return new VerificationResult(STATUS_SUCCESS, claims, null, null);
    }

    public static VerificationResult error(String error, String description) {
        return new VerificationResult(STATUS_ERROR, null, error, description);
    }
}
