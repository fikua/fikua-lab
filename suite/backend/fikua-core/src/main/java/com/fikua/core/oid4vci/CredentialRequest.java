package com.fikua.core.oid4vci;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * OID4VCI Credential Request per Section 7.2.
 * Sent by wallet to issuer's credential endpoint.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CredentialRequest(
        @JsonProperty("format") String format,
        @JsonProperty("credential_identifier") String credentialIdentifier,
        @JsonProperty("proof") Proof proof,
        @JsonProperty("credential_response_encryption") Map<String, Object> credentialResponseEncryption
) {

    /**
     * Proof of possession of the key material.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Proof(
            @JsonProperty("proof_type") String proofType,
            @JsonProperty("jwt") String jwt
    ) {}
}
