package com.fikua.core.mdoc;

/**
 * Represents the IssuerSigned CBOR structure (ISO 18013-5 §8.3.2.1.2.2).
 * Contains issuerAuth (COSE_Sign1) and nameSpaces with IssuerSignedItems.
 * Per OID4VCI A.2.4, the credential response is the base64url-encoded IssuerSigned.
 */
public record MdocDocument(byte[] cborBytes) {

    /** Serialize to base64url string (no padding) for OID4VCI credential response. */
    public String toBase64Url() {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(cborBytes);
    }
}
