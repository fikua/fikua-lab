package com.fikua.core.mdoc;

/**
 * Represents a complete mso_mdoc Document (ISO 18013-5), ready for serialization.
 * The CBOR bytes can be base64url-encoded for the OID4VCI credential response.
 */
public record MdocDocument(byte[] cborBytes) {

    /** Serialize to base64url string (no padding) for OID4VCI credential response. */
    public String toBase64Url() {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(cborBytes);
    }
}
