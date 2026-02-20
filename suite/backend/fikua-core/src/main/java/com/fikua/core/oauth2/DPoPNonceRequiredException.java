package com.fikua.core.oauth2;

/**
 * Thrown when a DPoP proof is missing a valid server nonce (RFC 9449 §8).
 * The server must respond with 401 and a DPoP-Nonce header containing a fresh nonce.
 */
public class DPoPNonceRequiredException extends OAuthErrorException {

    public DPoPNonceRequiredException() {
        super(401, new OAuthError(DPoPValidator.USE_DPOP_NONCE, "DPoP nonce required"));
    }
}
