package com.fikua.core.profile.enums;

import com.fasterxml.jackson.annotation.JsonValue;

public enum ResponseMode {
    DIRECT_POST("direct_post"),
    DIRECT_POST_JWT("direct_post_jwt"),
    DC_API("dc_api"),
    DC_API_JWT("dc_api_jwt");

    private final String value;

    ResponseMode(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }

    /** Protocol value as used in OID4VP messages. */
    public String protocolValue() {
        return switch (this) {
            case DIRECT_POST -> "direct_post";
            case DIRECT_POST_JWT -> "direct_post.jwt";
            case DC_API -> "dc_api";
            case DC_API_JWT -> "dc_api.jwt";
        };
    }
}
