package com.fikua.core.oid4vci;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

/**
 * OID4VCI Credential Offer per Section 4.1.
 * Sent by issuer to wallet to initiate credential issuance.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialOffer(
        @JsonProperty("credential_issuer") String credentialIssuer,
        @JsonProperty("credential_configuration_ids") List<String> credentialConfigurationIds,
        @JsonProperty("grants") Map<String, Object> grants
) {

    /** Create a pre-authorized code offer. */
    public static CredentialOffer preAuthorized(String issuerUrl, String configId,
                                                 String preAuthCode, boolean txCodeRequired) {
        var grant = new java.util.LinkedHashMap<String, Object>();
        grant.put("pre-authorized_code", preAuthCode);
        if (txCodeRequired) {
            grant.put("tx_code", Map.of(
                    "input_mode", "numeric",
                    "length", 6,
                    "description", "Enter the transaction code"
            ));
        }

        return new CredentialOffer(
                issuerUrl,
                List.of(configId),
                Map.of("urn:ietf:params:oauth:grant-type:pre-authorized_code", grant)
        );
    }

    /** Create an authorization code offer (OID4VCI 1.0 Final §4.1.1). */
    public static CredentialOffer authorizationCode(String issuerUrl, String configId,
                                                     String issuerState) {
        var grant = new java.util.LinkedHashMap<String, Object>();
        if (issuerState != null) {
            grant.put("issuer_state", issuerState);
        }
        // M3: authorization_server in grant object per OID4VCI 1.0 Final §4.1.1
        grant.put("authorization_server", issuerUrl);

        return new CredentialOffer(
                issuerUrl,
                List.of(configId),
                Map.of("authorization_code", grant)
        );
    }
}
