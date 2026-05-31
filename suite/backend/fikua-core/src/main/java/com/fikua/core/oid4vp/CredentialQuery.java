package com.fikua.core.oid4vp;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * A single credential query within a DCQL query.
 * Specifies the credential format, metadata filters, and requested claims.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">OID4VP §6.1</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialQuery(
        @JsonProperty("id") String id,
        @JsonProperty("format") String format,
        @JsonProperty("meta") CredentialMeta meta,
        @JsonProperty("claims") List<ClaimQuery> claims
) {

    /**
     * Format-specific metadata for filtering credentials. SD-JWT VC uses
     * {@code vct_values}; ISO mdoc (mso_mdoc) uses {@code doctype_value}
     * (a single docType string, OID4VP §6.1). Only the field relevant to the
     * credential format is serialized (the other stays null).
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record CredentialMeta(
            @JsonProperty("vct_values") List<String> vctValues,
            @JsonProperty("doctype_value") String doctypeValue
    ) {
        /** SD-JWT VC metadata: filter by accepted vct values. */
        public static CredentialMeta sdJwt(List<String> vctValues) {
            return new CredentialMeta(vctValues, null);
        }

        /** mso_mdoc metadata: filter by docType. */
        public static CredentialMeta mdoc(String docType) {
            return new CredentialMeta(null, docType);
        }
    }
}
