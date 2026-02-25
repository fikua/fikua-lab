package com.fikua.core.oid4vp;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * A single claim query within a DCQL credential query.
 * Specifies which claim is requested and optional constraints.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.3">OID4VP §6.3</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ClaimQuery(
        @JsonProperty("path") List<String> path,
        @JsonProperty("values") List<String> values,
        @JsonProperty("essential") Boolean essential
) {}
