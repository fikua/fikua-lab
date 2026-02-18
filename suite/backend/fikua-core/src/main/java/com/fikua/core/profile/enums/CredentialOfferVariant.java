package com.fikua.core.profile.enums;

import com.fasterxml.jackson.annotation.JsonValue;

public enum CredentialOfferVariant {
    BY_VALUE("by_value"),
    BY_REFERENCE("by_reference");

    private final String value;

    CredentialOfferVariant(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }
}
