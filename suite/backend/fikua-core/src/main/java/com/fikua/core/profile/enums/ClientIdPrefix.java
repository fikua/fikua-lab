package com.fikua.core.profile.enums;

import com.fasterxml.jackson.annotation.JsonValue;

public enum ClientIdPrefix {
    X509_SAN_DNS("x509_san_dns"),
    X509_HASH("x509_hash"),
    PRE_REGISTERED("pre_registered"),
    REDIRECT_URI("redirect_uri"),
    WEB_ORIGIN("web_origin");

    private final String value;

    ClientIdPrefix(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }
}
