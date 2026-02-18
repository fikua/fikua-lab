package com.fikua.core.profile.enums;

import com.fasterxml.jackson.annotation.JsonValue;

public enum ClientAuthType {
    MTLS("mtls"),
    PRIVATE_KEY_JWT("private_key_jwt"),
    CLIENT_ATTESTATION("client_attestation");

    private final String value;

    ClientAuthType(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }
}
