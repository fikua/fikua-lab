package com.fikua.core.profile.enums;

import com.fasterxml.jackson.annotation.JsonValue;

public enum CredentialFormat {
    SD_JWT_VC("sd_jwt_vc", "dc+sd-jwt"),
    MDOC("mdoc", "mso_mdoc");

    private final String value;
    private final String oid4vciFormat;

    CredentialFormat(String value, String oid4vciFormat) {
        this.value = value;
        this.oid4vciFormat = oid4vciFormat;
    }

    @JsonValue
    public String value() {
        return value;
    }

    /** Format identifier as used in OID4VCI protocol messages. */
    public String oid4vciFormat() {
        return oid4vciFormat;
    }
}
