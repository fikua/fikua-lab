package com.fikua.core.profile.enums;

import com.fasterxml.jackson.annotation.JsonValue;

public enum GrantType {
    AUTHORIZATION_CODE("authorization_code"),
    PRE_AUTHORIZATION_CODE("pre_authorization_code");

    private final String value;

    GrantType(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }

    public String oauthGrantType() {
        return switch (this) {
            case AUTHORIZATION_CODE -> "authorization_code";
            case PRE_AUTHORIZATION_CODE -> "urn:ietf:params:oauth:grant-type:pre-authorized_code";
        };
    }
}
