package com.fikua.core.profile.enums;

import com.fasterxml.jackson.annotation.JsonValue;

public enum IssuanceMode {
    IMMEDIATE("immediate"),
    DEFERRED("deferred");

    private final String value;

    IssuanceMode(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }
}
