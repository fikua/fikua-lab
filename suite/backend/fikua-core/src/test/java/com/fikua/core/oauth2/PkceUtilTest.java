package com.fikua.core.oauth2;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PkceUtilTest {

    @Test
    void generateCodeVerifier_returnsNonNull() {
        assertNotNull(PkceUtil.generateCodeVerifier());
        assertFalse(PkceUtil.generateCodeVerifier().isBlank());
    }

    @Test
    void generateCodeVerifier_hasCorrectLength() {
        // 32 bytes → 43 base64url chars (without padding)
        String verifier = PkceUtil.generateCodeVerifier();
        assertEquals(43, verifier.length());
    }

    @Test
    void generateCodeVerifier_isDifferentEachTime() {
        String v1 = PkceUtil.generateCodeVerifier();
        String v2 = PkceUtil.generateCodeVerifier();
        assertNotEquals(v1, v2);
    }

    @Test
    void computeS256Challenge_isBase64url() {
        String challenge = PkceUtil.computeS256Challenge("test-verifier");
        assertFalse(challenge.contains("="), "must not contain padding");
        assertFalse(challenge.contains("+"), "must not contain +");
        assertFalse(challenge.contains("/"), "must not contain /");
    }

    @Test
    void computeS256Challenge_isDeterministic() {
        String c1 = PkceUtil.computeS256Challenge("same-input");
        String c2 = PkceUtil.computeS256Challenge("same-input");
        assertEquals(c1, c2);
    }

    @Test
    void computeS256Challenge_rfc7636TestVector() {
        // RFC 7636 Appendix B test vector
        String verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        String expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assertEquals(expected, PkceUtil.computeS256Challenge(verifier));
    }

    @Test
    void verifyS256_correctVerifier_returnsTrue() {
        String verifier = PkceUtil.generateCodeVerifier();
        String challenge = PkceUtil.computeS256Challenge(verifier);
        assertTrue(PkceUtil.verifyS256(verifier, challenge));
    }

    @Test
    void verifyS256_wrongVerifier_returnsFalse() {
        String challenge = PkceUtil.computeS256Challenge("correct-verifier");
        assertFalse(PkceUtil.verifyS256("wrong-verifier", challenge));
    }

    @Test
    void verifyS256_emptyVerifier_returnsFalse() {
        String challenge = PkceUtil.computeS256Challenge("something");
        assertFalse(PkceUtil.verifyS256("", challenge));
    }
}
