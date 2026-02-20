package com.fikua.core.oid4vci;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.*;

/**
 * OID4VCI Credential Issuer Metadata per Section 11.2.
 * Served at /.well-known/openid-credential-issuer.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialIssuerMetadata(
        @JsonProperty("credential_issuer") String credentialIssuer,
        @JsonProperty("credential_endpoint") String credentialEndpoint,
        @JsonProperty("nonce_endpoint") String nonceEndpoint,
        @JsonProperty("notification_endpoint") String notificationEndpoint,
        @JsonProperty("credential_response_encryption") Map<String, Object> credentialResponseEncryption,
        @JsonProperty("credential_configurations_supported") Map<String, Object> credentialConfigurationsSupported,
        @JsonProperty("display") List<Map<String, Object>> display
) {

    /**
     * Build metadata from explicit endpoint URLs, credential configurations, and display.
     *
     * @param credentialIssuer         the issuer identifier (base URL)
     * @param credentialEndpoint       full URL of the credential endpoint
     * @param nonceEndpoint            full URL of the nonce endpoint
     * @param notificationEndpoint     full URL of the notification endpoint (nullable)
     * @param credentialConfigurations map of credential config ID → config object
     * @param display                  issuer display info
     * @param haip                     whether to include credential_response_encryption (HAIP)
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

        return new CredentialIssuerMetadata(
                credentialIssuer,
                credentialEndpoint,
                nonceEndpoint,
                notificationEndpoint,
                responseEncryption,
                credentialConfigurations,
                display
        );
    }
}
