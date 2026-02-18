package com.fikua.core.sdjwt;

import java.util.List;

/**
 * Represents a complete SD-JWT: issuer JWT + disclosures + optional key binding JWT.
 * Serialized format: <issuer-jwt>~<disclosure1>~<disclosure2>~...~<kb-jwt>
 */
public record SdJwt(
        String issuerJwt,
        List<Disclosure> disclosures,
        String keyBindingJwt
) {

    /** Serialize to the SD-JWT combined format. */
    public String serialize() {
        var sb = new StringBuilder(issuerJwt);
        for (Disclosure d : disclosures) {
            sb.append('~').append(d.encoded());
        }
        sb.append('~');
        if (keyBindingJwt != null) {
            sb.append(keyBindingJwt);
        }
        return sb.toString();
    }

    /** Parse from combined SD-JWT format string. */
    public static SdJwt parse(String combined) {
        String[] parts = combined.split("~", -1);
        if (parts.length < 2) {
            throw new IllegalArgumentException("Invalid SD-JWT format");
        }

        String jwt = parts[0];
        String kbJwt = parts[parts.length - 1].isEmpty() ? null : parts[parts.length - 1];

        int disclosureEnd = kbJwt != null ? parts.length - 1 : parts.length;
        List<Disclosure> disclosures = new java.util.ArrayList<>();
        for (int i = 1; i < disclosureEnd; i++) {
            if (!parts[i].isEmpty()) {
                disclosures.add(Disclosure.parse(parts[i]));
            }
        }

        return new SdJwt(jwt, disclosures, kbJwt);
    }
}
