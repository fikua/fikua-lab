package com.fikua.core.oid4vci;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.*;

/**
 * OAuth2 Authorization Server Metadata per RFC 8414 + OID4VCI extensions.
 * Served at /.well-known/oauth-authorization-server.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuthServerMetadata(
        @JsonProperty("issuer") String issuer,
        @JsonProperty("token_endpoint") String tokenEndpoint,
        @JsonProperty("authorization_endpoint") String authorizationEndpoint,
        @JsonProperty("pushed_authorization_request_endpoint") String parEndpoint,
        @JsonProperty("jwks_uri") String jwksUri,
        @JsonProperty("response_types_supported") List<String> responseTypesSupported,
        @JsonProperty("grant_types_supported") List<String> grantTypesSupported,
        @JsonProperty("code_challenge_methods_supported") List<String> codeChallengeMethodsSupported,
        @JsonProperty("token_endpoint_auth_methods_supported") List<String> tokenEndpointAuthMethodsSupported,
        @JsonProperty("dpop_signing_alg_values_supported") List<String> dpopSigningAlgValues,
        @JsonProperty("client_attestation_signing_alg_values_supported") List<String> clientAttestationSigningAlgValues,
        @JsonProperty("client_attestation_pop_signing_alg_values_supported") List<String> clientAttestationPopSigningAlgValues,
        @JsonProperty("pre-authorized_grant_anonymous_access_supported") Boolean preAuthAnonymousAccess
) {

    /** Build metadata for pre-authorized code profile. */
    public static AuthServerMetadata forPreAuthProfile(String issuer, String tokenEndpoint, String jwksUri) {
        return new AuthServerMetadata(
                issuer,
                tokenEndpoint,
                null, // no authorization endpoint for pre-auth
                null, // no PAR
                jwksUri,
                List.of("none"),
                List.of("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
                null, // no PKCE
                List.of("none"),
                null, // no DPoP
                null, // no client attestation
                null,
                true
        );
    }

    /** Build metadata for authorization_code (HAIP) profile. */
    public static AuthServerMetadata forHaipProfile(String issuer, String tokenEndpoint,
                                                     String authorizationEndpoint, String parEndpoint,
                                                     String jwksUri) {
        return new AuthServerMetadata(
                issuer,
                tokenEndpoint,
                authorizationEndpoint,
                parEndpoint,
                jwksUri,
                List.of("code"),
                List.of("authorization_code"),
                List.of("S256"),
                List.of("attest_jwt_client_auth"),
                List.of("ES256"),
                List.of("ES256"),
                List.of("ES256"),
                null
        );
    }
}
