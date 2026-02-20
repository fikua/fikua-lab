package com.fikua.core.sdjwt;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class DisclosureTest {

    // --- create ---

    @Test
    void create_returnsNonNullDisclosure() {
        Disclosure d = Disclosure.create("given_name", "Alice");
        assertNotNull(d);
        assertNotNull(d.salt());
        assertEquals("given_name", d.claimName());
        assertEquals("Alice", d.claimValue());
        assertNotNull(d.encoded());
    }

    @Test
    void create_encodedIsBase64url() {
        Disclosure d = Disclosure.create("family_name", "Smith");
        assertFalse(d.encoded().contains("="), "must not contain padding");
        assertFalse(d.encoded().contains("+"), "must not contain +");
        assertFalse(d.encoded().contains("/"), "must not contain /");
    }

    @Test
    void create_differentSaltEachTime() {
        Disclosure d1 = Disclosure.create("age", 30);
        Disclosure d2 = Disclosure.create("age", 30);
        assertNotEquals(d1.salt(), d2.salt());
        assertNotEquals(d1.encoded(), d2.encoded());
    }

    // --- digest ---

    @Test
    void digest_isBase64url() {
        Disclosure d = Disclosure.create("given_name", "Alice");
        String digest = d.digest();
        assertNotNull(digest);
        assertFalse(digest.contains("="), "must not contain padding");
        assertFalse(digest.contains("+"), "must not contain +");
        assertFalse(digest.contains("/"), "must not contain /");
    }

    @Test
    void digest_isDeterministic() {
        Disclosure d = Disclosure.create("given_name", "Alice");
        assertEquals(d.digest(), d.digest());
    }

    @Test
    void digest_isDifferentForDifferentDisclosures() {
        Disclosure d1 = Disclosure.create("given_name", "Alice");
        Disclosure d2 = Disclosure.create("given_name", "Bob");
        assertNotEquals(d1.digest(), d2.digest());
    }

    // --- parse round-trip ---

    @Test
    void parse_roundTrip_preservesClaim() {
        Disclosure original = Disclosure.create("email", "alice@example.com");
        Disclosure parsed = Disclosure.parse(original.encoded());

        assertEquals(original.salt(), parsed.salt());
        assertEquals(original.claimName(), parsed.claimName());
        assertEquals(original.claimValue(), parsed.claimValue());
        assertEquals(original.encoded(), parsed.encoded());
    }

    // --- parse errors ---

    @Test
    void parse_wrongElementCount_throws() {
        // Create a 2-element array
        String json = "[\"salt\",\"name\"]";
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));
        assertThrows(RuntimeException.class, () -> Disclosure.parse(encoded));
    }

    @Test
    void parse_invalidBase64_throws() {
        assertThrows(RuntimeException.class, () -> Disclosure.parse("!!!not-base64!!!"));
    }

    // --- edge cases ---

    @Test
    void create_withObjectValue_roundTrips() {
        var address = java.util.Map.of("street", "123 Main St", "city", "Berlin");
        Disclosure d = Disclosure.create("address", address);
        Disclosure parsed = Disclosure.parse(d.encoded());
        assertEquals("address", parsed.claimName());
        assertEquals(address, parsed.claimValue());
    }

    @Test
    void create_withNumericValue_roundTrips() {
        Disclosure d = Disclosure.create("age", 42);
        Disclosure parsed = Disclosure.parse(d.encoded());
        assertEquals("age", parsed.claimName());
        assertEquals(42, parsed.claimValue());
    }

    @Test
    void create_withSpecialCharacters_roundTrips() {
        Disclosure d = Disclosure.create("name", "José García-López");
        Disclosure parsed = Disclosure.parse(d.encoded());
        assertEquals("José García-López", parsed.claimValue());
    }
}
