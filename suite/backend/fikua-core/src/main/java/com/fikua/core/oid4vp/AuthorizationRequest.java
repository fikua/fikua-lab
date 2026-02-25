package com.fikua.core.oid4vp;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * OID4VP Authorization Request — the payload of a signed Request Object (JAR).
 * Contains all parameters needed to request a Verifiable Presentation from a Wallet.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5">OID4VP §5</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public record AuthorizationRequest(
        @JsonProperty("response_type") String responseType,
        @JsonProperty("client_id") String clientId,
        @JsonProperty("response_mode") String responseMode,
        @JsonProperty("response_uri") String responseUri,
        @JsonProperty("nonce") String nonce,
        @JsonProperty("state") String state,
        @JsonProperty("dcql_query") DcqlQuery dcqlQuery,
        @JsonProperty("scope") String scope,
        @JsonProperty("client_metadata") Map<String, Object> clientMetadata,
        @JsonProperty("aud") String aud,
        @JsonProperty("iss") String iss,
        @JsonProperty("iat") Long iat,
        @JsonProperty("exp") Long exp
) {

    /** The only valid response_type for OID4VP (§5.2). */
    public static final String RESPONSE_TYPE_VP_TOKEN = "vp_token";

    /** JOSE typ header value for signed Authorization Request Objects (JAR, RFC 9101). */
    public static final String JAR_TYPE = "oauth-authz-req+jwt";
}
