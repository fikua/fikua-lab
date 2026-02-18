package com.fikua.core.profile.enums;

import com.fasterxml.jackson.annotation.JsonValue;

public enum VciProfile {
    PLAIN("plain"),
    HAIP("haip");

    private final String value;

    VciProfile(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }
}
