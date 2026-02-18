package com.fikua.core.oid4vci;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fikua.core.profile.ProfileConfig;

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
        @JsonProperty("pre-authorized_grant_anonymous_access_supported") Boolean preAuthAnonymousAccess
) {

    private static final String API_PREFIX = "/oid4vci/v1";

    /** Build metadata for pre-authorized code profile. */
    public static AuthServerMetadata forPreAuthProfile(String baseUrl) {
        return new AuthServerMetadata(
                baseUrl,
                baseUrl + API_PREFIX + "/token",
                null, // no authorization endpoint for pre-auth
                null, // no PAR
                baseUrl + API_PREFIX + "/jwks",
                List.of("none"),
                List.of("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
                null, // no PKCE
                List.of("none"),
                null, // no DPoP
                true
        );
    }

    /** Build metadata for authorization_code (HAIP) profile. */
    public static AuthServerMetadata forHaipProfile(String baseUrl) {
        return new AuthServerMetadata(
                baseUrl,
                baseUrl + API_PREFIX + "/token",
                baseUrl + API_PREFIX + "/authorize",
                baseUrl + API_PREFIX + "/par",
                baseUrl + API_PREFIX + "/jwks",
                List.of("code"),
                List.of("authorization_code"),
                List.of("S256"),
                List.of("attest_jwt_client_auth"),
                List.of("ES256"),
                null
        );
    }

    /** Build metadata based on profile config. */
    public static AuthServerMetadata fromProfile(String baseUrl, ProfileConfig config) {
        if (config.isHaip()) {
            return forHaipProfile(baseUrl);
        }
        return forPreAuthProfile(baseUrl);
    }
}
