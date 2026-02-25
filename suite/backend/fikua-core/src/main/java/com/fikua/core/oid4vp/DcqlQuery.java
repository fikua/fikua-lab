package com.fikua.core.oid4vp;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Digital Credentials Query Language (DCQL) query.
 * Top-level object containing one or more credential queries.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6">OID4VP §6</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record DcqlQuery(
        @JsonProperty("credentials") List<CredentialQuery> credentials
) {

    /** Credential format identifier for SD-JWT VC (OID4VP Appendix B.3). */
    public static final String FORMAT_DC_SD_JWT = "dc+sd-jwt";

    /** Credential format identifier for ISO mdoc (OID4VP Appendix B.2). */
    public static final String FORMAT_MSO_MDOC = "mso_mdoc";
}
