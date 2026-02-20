package com.fikua.core.oid4vci;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

/**
 * OID4VCI Credential Request per Section 7.2.
 * Supports both singular "proof" (draft) and plural "proofs" (OID4VCI 1.0 Final §7.2.2).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CredentialRequest(
        @JsonProperty("format") String format,
        @JsonProperty("credential_configuration_id") String credentialConfigurationId,
        @JsonProperty("credential_identifier") String credentialIdentifier,
        @JsonProperty("proof") Proof proof,
        @JsonProperty("proofs") Map<String, List<String>> proofs,
        @JsonProperty("credential_response_encryption") Map<String, Object> credentialResponseEncryption
) {

    /**
     * Extract the first JWT proof string from either "proof" (singular) or "proofs" (plural).
     * OID4VCI 1.0 Final §7.2: "proofs": {"jwt": ["eyJ..."]}
     * Draft format: "proof": {"proof_type": "jwt", "jwt": "eyJ..."}
     *
     * @return the JWT string, or null if no proof is present
     */
    public String extractProofJwt() {
        // OID4VCI 1.0 Final: proofs.jwt[0]
        if (proofs != null) {
            List<String> jwtList = proofs.get("jwt");
            if (jwtList != null && !jwtList.isEmpty()) {
                return jwtList.getFirst();
            }
        }
        // Draft fallback: proof.jwt
        if (proof != null && "jwt".equals(proof.proofType())) {
            return proof.jwt();
        }
        return null;
    }

    /**
     * Proof of possession of the key material (singular, draft format).
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Proof(
            @JsonProperty("proof_type") String proofType,
            @JsonProperty("jwt") String jwt
    ) {}
}
