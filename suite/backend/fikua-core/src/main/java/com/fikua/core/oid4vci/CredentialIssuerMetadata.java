package com.fikua.core.oid4vci;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.*;

/**
 * OID4VCI 1.0 Final Credential Issuer Metadata per §10.2.
 * Served at /.well-known/openid-credential-issuer.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialIssuerMetadata(
        @JsonProperty("credential_issuer") String credentialIssuer,
        @JsonProperty("authorization_servers") List<String> authorizationServers,
        @JsonProperty("credential_endpoint") String credentialEndpoint,
        @JsonProperty("nonce_endpoint") String nonceEndpoint,
        @JsonProperty("notification_endpoint") String notificationEndpoint,
        @JsonProperty("credential_response_encryption") Map<String, Object> credentialResponseEncryption,
        @JsonProperty("batch_credential_issuance") Map<String, Object> batchCredentialIssuance,
        @JsonProperty("signed_metadata") String signedMetadata,
        @JsonProperty("credential_configurations_supported") Map<String, Object> credentialConfigurationsSupported,
        @JsonProperty("display") List<Map<String, Object>> display
) {

    /**
     * Build metadata from explicit endpoint URLs, credential configurations, and display.
     */
    public static CredentialIssuerMetadata build(String credentialIssuer,
                                                  String credentialEndpoint,
                                                  String nonceEndpoint,
                                                  String notificationEndpoint,
                                                  Map<String, Object> credentialConfigurations,
                                                  List<Map<String, Object>> display,
                                                  boolean haip) {
        Map<String, Object> responseEncryption = null;
        if (haip) {
            responseEncryption = Map.of(
                    "alg_values_supported", List.of("ECDH-ES"),
                    "enc_values_supported", List.of("A128GCM", "A256GCM"),
                    "encryption_required", false
            );
        }

        // OID4VCI 1.0 Final §10.2: authorization_servers when AS = issuer
        List<String> authServers = List.of(credentialIssuer);

        // OID4VCI 1.0 Final §10.2: batch_credential_issuance (supports proofs plural)
        Map<String, Object> batch = Map.of("batch_size", 1);

        return new CredentialIssuerMetadata(
                credentialIssuer,
                authServers,
                credentialEndpoint,
                nonceEndpoint,
                notificationEndpoint,
                responseEncryption,
                batch,
                null, // signed_metadata: optional, not yet implemented
                credentialConfigurations,
                display
        );
    }
}
