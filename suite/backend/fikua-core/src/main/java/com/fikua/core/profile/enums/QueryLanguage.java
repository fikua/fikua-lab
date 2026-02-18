package com.fikua.core.profile.enums;

import com.fasterxml.jackson.annotation.JsonValue;

public enum QueryLanguage {
    PRESENTATION_EXCHANGE("presentation_exchange"),
    DCQL("dcql");

    private final String value;

    QueryLanguage(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }
}
