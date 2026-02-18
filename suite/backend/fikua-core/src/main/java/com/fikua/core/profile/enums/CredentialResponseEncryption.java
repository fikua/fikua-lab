package com.fikua.core.profile.enums;

import com.fasterxml.jackson.annotation.JsonValue;

public enum CredentialResponseEncryption {
    PLAIN("plain"),
    ENCRYPTED("encrypted");

    private final String value;

    CredentialResponseEncryption(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }
}
