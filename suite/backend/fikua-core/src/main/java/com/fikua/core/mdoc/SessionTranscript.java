package com.fikua.core.mdoc;

import com.upokecenter.cbor.CBORObject;

import java.security.MessageDigest;

/**
 * Builds the OID4VP {@code SessionTranscript} and {@code DeviceAuthentication}
 * CBOR structures that bind an mdoc {@code DeviceResponse} to a presentation
 * request, per OID4VP 1.0 FINAL §B.2.6 and ISO/IEC 18013-5 §9.1.5.
 *
 * <p>For the redirect / {@code direct_post(.jwt)} flow (NOT the Digital
 * Credentials API), the FINAL spec defines:
 *
 * <pre>
 * SessionTranscript        = [ null, null, OpenID4VPHandover ]
 * OpenID4VPHandover        = [ "OpenID4VPHandover", sha256(OpenID4VPHandoverInfoBytes) ]
 * OpenID4VPHandoverInfo    = [ clientId (tstr), nonce (tstr), jwkThumbprint (bstr), responseUri (tstr) ]
 * </pre>
 *
 * Where {@code jwkThumbprint} is the RFC 7638 SHA-256 thumbprint (raw bytes) of
 * the verifier's response-encryption public key when the response is encrypted
 * (it is {@code null} for an unencrypted response). There is no
 * {@code mdocGeneratedNonce} in OID4VP 1.0 FINAL — that was an ISO 18013-7
 * draft concept and is not used here.
 *
 * <p>The device signature covers {@code DeviceAuthenticationBytes}:
 *
 * <pre>
 * DeviceAuthentication      = [ "DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes ]
 * DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
 * </pre>
 */
public final class SessionTranscript {

    private static final String HANDOVER_TYPE = "OpenID4VPHandover";
    private static final int TAG_ENCODED_CBOR = 24;

    private SessionTranscript() {}

    /**
     * Build the encoded {@code SessionTranscript} for the OID4VP redirect /
     * direct_post(.jwt) flow.
     *
     * @param clientId      the full {@code client_id} request parameter, including
     *                      any Client Identifier Prefix (e.g. {@code x509_hash:…})
     * @param nonce         the request {@code nonce}
     * @param jwkThumbprint raw 32-byte RFC 7638 SHA-256 thumbprint of the
     *                      response-encryption key, or {@code null} if the
     *                      response is not encrypted
     * @param responseUri   the {@code response_uri} (or {@code redirect_uri})
     * @return CBOR-encoded {@code [null, null, OpenID4VPHandover]}
     */
    public static byte[] openid4vpHandover(String clientId, String nonce,
                                           byte[] jwkThumbprint, String responseUri) {
        CBORObject handoverInfo = CBORObject.NewArray();
        handoverInfo.Add(CBORObject.FromObject(clientId));
        handoverInfo.Add(CBORObject.FromObject(nonce));
        handoverInfo.Add(jwkThumbprint != null
                ? CBORObject.FromObject(jwkThumbprint)
                : CBORObject.Null);
        handoverInfo.Add(CBORObject.FromObject(responseUri));

        byte[] handoverInfoHash = sha256(handoverInfo.EncodeToBytes());

        CBORObject handover = CBORObject.NewArray();
        handover.Add(CBORObject.FromObject(HANDOVER_TYPE));
        handover.Add(CBORObject.FromObject(handoverInfoHash));

        CBORObject sessionTranscript = CBORObject.NewArray();
        sessionTranscript.Add(CBORObject.Null);   // DeviceEngagementBytes
        sessionTranscript.Add(CBORObject.Null);   // EReaderKeyBytes
        sessionTranscript.Add(handover);

        return sessionTranscript.EncodeToBytes();
    }

    /**
     * Build {@code DeviceAuthenticationBytes} — the detached payload the device
     * signature covers.
     *
     * @param sessionTranscript       CBOR-encoded SessionTranscript (from {@link #openid4vpHandover})
     * @param docType                 the document type
     * @param deviceNameSpacesBytes   the verbatim {@code deviceSigned.nameSpaces}
     *                                bytes (already a {@code #6.24(bstr .cbor …)})
     * @return CBOR-encoded {@code #6.24(bstr .cbor DeviceAuthentication)}
     */
    public static byte[] deviceAuthenticationBytes(byte[] sessionTranscript, String docType,
                                                   byte[] deviceNameSpacesBytes) {
        CBORObject deviceAuth = CBORObject.NewArray();
        deviceAuth.Add(CBORObject.FromObject("DeviceAuthentication"));
        deviceAuth.Add(CBORObject.DecodeFromBytes(sessionTranscript));
        deviceAuth.Add(CBORObject.FromObject(docType));
        deviceAuth.Add(CBORObject.DecodeFromBytes(deviceNameSpacesBytes));

        // Wrap in tag 24: DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
        byte[] deviceAuthBytes = deviceAuth.EncodeToBytes();
        return CBORObject.FromObject(deviceAuthBytes).WithTag(TAG_ENCODED_CBOR).EncodeToBytes();
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}
