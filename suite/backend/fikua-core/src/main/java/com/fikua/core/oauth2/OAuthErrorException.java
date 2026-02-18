package com.fikua.core.oauth2;

/**
 * Exception carrying an OAuth2 error response with HTTP status.
 */
public class OAuthErrorException extends RuntimeException {

    private final int httpStatus;
    private final OAuthError error;

    public OAuthErrorException(int httpStatus, OAuthError error) {
        super(error.error() + ": " + error.errorDescription());
        this.httpStatus = httpStatus;
        this.error = error;
    }

    public int httpStatus() {
        return httpStatus;
    }

    public OAuthError error() {
        return error;
    }

    public static OAuthErrorException badRequest(String errorCode, String description) {
        return new OAuthErrorException(400, new OAuthError(errorCode, description));
    }

    public static OAuthErrorException unauthorized(String errorCode, String description) {
        return new OAuthErrorException(401, new OAuthError(errorCode, description));
    }
}
