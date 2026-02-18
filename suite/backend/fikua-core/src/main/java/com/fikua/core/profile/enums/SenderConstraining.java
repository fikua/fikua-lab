package com.fikua.core.profile.enums;

import com.fasterxml.jackson.annotation.JsonValue;

public enum SenderConstraining {
    DPOP("dpop"),
    MTLS("mtls");

    private final String value;

    SenderConstraining(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }
}
