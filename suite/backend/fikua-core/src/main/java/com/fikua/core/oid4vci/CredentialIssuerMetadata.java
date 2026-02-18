package com.fikua.core.oid4vci;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fikua.core.profile.ProfileConfig;
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

    /** Build metadata from base URL and profile config. */
    public static CredentialIssuerMetadata build(String baseUrl, ProfileConfig config) {
        String configId = "eu.europa.ec.eudi.pid_dc+sd-jwt";

        var credConfig = new LinkedHashMap<String, Object>();
        credConfig.put("format", "dc+sd-jwt");
        credConfig.put("scope", "eu.europa.ec.eudi.pid_dc+sd-jwt");
        credConfig.put("cryptographic_binding_methods_supported", List.of("jwk"));
        credConfig.put("credential_signing_alg_values_supported", List.of("ES256"));
        credConfig.put("proof_types_supported", Map.of(
                "jwt", Map.of("proof_signing_alg_values_supported", List.of("ES256"))
        ));
        credConfig.put("vct", "eu.europa.ec.eudi.pid.1");

        // Claims array with path (OID4VCI 1.0 Final)
        var claims = List.of(
                Map.of("path", List.of("given_name"), "display", List.of(Map.of("name", "Given Name", "locale", "en"))),
                Map.of("path", List.of("family_name"), "display", List.of(Map.of("name", "Surname", "locale", "en"))),
                Map.of("path", List.of("birth_date"), "display", List.of(Map.of("name", "Date of Birth", "locale", "en"))),
                Map.of("path", List.of("issuing_authority"), "display", List.of(Map.of("name", "Issuing Authority", "locale", "en"))),
                Map.of("path", List.of("issuing_country"), "display", List.of(Map.of("name", "Issuing Country", "locale", "en")))
        );

        // Credential metadata wrapper (OID4VCI 1.0 Final)
        var credentialMetadata = new LinkedHashMap<String, Object>();
        credentialMetadata.put("display", List.of(Map.of(
                "name", "EUDI PID",
                "locale", "en",
                "description", "EU Digital Identity Personal Identification Data"
        )));
        credentialMetadata.put("claims", claims);

        credConfig.put("credential_metadata", credentialMetadata);

        var display = List.of(Map.<String, Object>of(
                "name", "Fikua Lab Issuer",
                "locale", "en"
        ));

        // credential_response_encryption: advertise supported algorithms (HAIP)
        Map<String, Object> responseEncryption = null;
        if (config != null && config.isHaip()) {
            responseEncryption = Map.of(
                    "alg_values_supported", List.of("ECDH-ES"),
                    "enc_values_supported", List.of("A128GCM", "A256GCM"),
                    "encryption_required", false
            );
        }

        String apiPrefix = "/oid4vci/v1";

        return new CredentialIssuerMetadata(
                baseUrl,
                baseUrl + apiPrefix + "/credential",
                baseUrl + apiPrefix + "/nonce",
                baseUrl + apiPrefix + "/notification",
                responseEncryption,
                Map.of(configId, credConfig),
                display
        );
    }
}
