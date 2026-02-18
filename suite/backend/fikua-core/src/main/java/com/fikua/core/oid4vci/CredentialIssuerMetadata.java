package com.fikua.core.oid4vci;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fikua.core.profile.ProfileConfig;
import com.fikua.core.profile.enums.CredentialFormat;

import java.util.*;

/**
 * OID4VCI Credential Issuer Metadata per Section 11.2.
 * Served at /.well-known/openid-credential-issuer.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialIssuerMetadata(
        @JsonProperty("credential_issuer") String credentialIssuer,
        @JsonProperty("credential_endpoint") String credentialEndpoint,
        @JsonProperty("credential_configurations_supported") Map<String, Object> credentialConfigurationsSupported,
        @JsonProperty("display") List<Map<String, Object>> display
) {

    /** Build metadata from base URL and profile config. */
    public static CredentialIssuerMetadata build(String baseUrl, ProfileConfig config) {
        String configId = "eu.europa.ec.eudi.pid_vc+sd-jwt";

        var credConfig = new LinkedHashMap<String, Object>();
        credConfig.put("format", "vc+sd-jwt");
        credConfig.put("scope", "eu.europa.ec.eudi.pid_vc+sd-jwt");
        credConfig.put("cryptographic_binding_methods_supported", List.of("jwk"));
        credConfig.put("credential_signing_alg_values_supported", List.of("ES256"));
        credConfig.put("proof_types_supported", Map.of(
                "jwt", Map.of("proof_signing_alg_values_supported", List.of("ES256"))
        ));
        credConfig.put("vct", "eu.europa.ec.eudi.pid.1");

        // Claims for EUDI PID
        var claims = new LinkedHashMap<String, Object>();
        claims.put("given_name", Map.of());
        claims.put("family_name", Map.of());
        claims.put("birth_date", Map.of());
        claims.put("issuing_authority", Map.of());
        claims.put("issuing_country", Map.of());
        credConfig.put("claims", claims);

        // Display
        credConfig.put("display", List.of(Map.of(
                "name", "EUDI PID",
                "locale", "en",
                "description", "EU Digital Identity Personal Identification Data"
        )));

        var display = List.of(Map.<String, Object>of(
                "name", "Fikua Lab Issuer",
                "locale", "en"
        ));

        String apiPrefix = "/oid4vci/v1";

        return new CredentialIssuerMetadata(
                baseUrl,
                baseUrl + apiPrefix + "/credential",
                Map.of(configId, credConfig),
                display
        );
    }
}
