package com.fikua.core.oid4vci;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * OID4VCI Credential Response per Section 7.3.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialResponse(
        @JsonProperty("credential") String credential,
        @JsonProperty("c_nonce") String cNonce,
        @JsonProperty("c_nonce_expires_in") Integer cNonceExpiresIn
) {

    public static CredentialResponse success(String credential, String newNonce) {
        return new CredentialResponse(credential, newNonce, 86400);
    }
}
