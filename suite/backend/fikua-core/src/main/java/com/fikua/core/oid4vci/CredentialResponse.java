package com.fikua.core.oid4vci;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

/**
 * OID4VCI 1.0 Final Credential Response per Section 8.3.
 *
 * Uses "credentials" (plural array of objects) instead of draft "credential" (singular string).
 * c_nonce is no longer in the credential response — it is obtained from the Nonce Endpoint (Section 7).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialResponse(
        @JsonProperty("credentials") List<Map<String, String>> credentials,
        @JsonProperty("transaction_id") String transactionId,
        @JsonProperty("notification_id") String notificationId
) {

    /**
     * Successful immediate credential response.
     * Wraps the credential string in the OID4VCI 1.0 Final format:
     * {@code {"credentials": [{"credential": "eyJ..."}]}}
     */
    public static CredentialResponse success(String credential) {
        return new CredentialResponse(
                List.of(Map.of("credential", credential)),
                null,
                null
        );
    }

    /**
     * Deferred credential response (transaction_id only).
     */
    public static CredentialResponse deferred(String transactionId) {
        return new CredentialResponse(null, transactionId, null);
    }
}
