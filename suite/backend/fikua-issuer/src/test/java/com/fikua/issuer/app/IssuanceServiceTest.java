package com.fikua.issuer.app;

import com.fikua.core.oauth2.DPoPValidator;
import com.fikua.core.oauth2.OAuthErrorException;
import com.fikua.core.profile.ProfileConfig;
import com.fikua.core.profile.enums.*;
import com.fikua.issuer.app.port.IssuanceStore;
import com.fikua.issuer.app.port.IssuanceStore.IssuanceRecord;
import com.fikua.issuer.app.port.ProfileStore;
import com.fikua.issuer.app.port.SessionStore.SessionData;
import com.fikua.issuer.infra.InMemorySessionStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for IssuanceService — wallet-initiated flow with identification portal.
 */
class IssuanceServiceTest {

    private InMemorySessionStore sessionStore;
    private StubIssuanceStore issuanceStore;
    private IssuanceService service;

    private static final String IDENTIFY_BASE_URL = "https://identify.lab.fikua.com";
    private static final String ISSUER_BASE_URL = "https://issuer.lab.fikua.com";

    private static final ProfileConfig HAIP_CONFIG = new ProfileConfig(
            GrantType.AUTHORIZATION_CODE,
            SenderConstraining.DPOP,
            ClientAuthType.CLIENT_ATTESTATION,
            CredentialFormat.SD_JWT_VC,
            VciProfile.HAIP,
            CredentialOfferVariant.BY_VALUE,
            IssuanceMode.IMMEDIATE,
            null, true, "S256",
            null, null, null, null, null
    );

    @BeforeEach
    void setUp() {
        sessionStore = new InMemorySessionStore();
        issuanceStore = new StubIssuanceStore();

        ProfileStore profileStore = () -> new ProfileStore.ActiveProfile("test", HAIP_CONFIG);
        DPoPValidator dpopValidator = new DPoPValidator(jti -> true);

        service = new IssuanceService(
                null, // issuerKey not needed for authorize tests
                sessionStore,
                issuanceStore,
                profileStore,
                dpopValidator,
                ISSUER_BASE_URL,
                IDENTIFY_BASE_URL
        );
    }

    @Test
    void handleAuthorize_walletInitiated_redirectsToIdentificationPortal() {
        // Given: wallet-initiated flow — no issuer_state, no credential offer
        Map<String, String> parParams = Map.of(
                "client_id", "https://wallet.test.fikua.com",
                "redirect_uri", "https://wallet.test.fikua.com/callback",
                "scope", "eu.europa.ec.eudi.pid.1",
                "state", "abc123",
                "response_type", "code",
                "code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method", "S256"
        );
        String requestUri = "urn:ietf:params:oauth:request_uri:test123";
        sessionStore.storeParRequest(requestUri, parParams);

        // When: authorize without issuer_state (wallet-initiated)
        var result = service.handleAuthorize(
                requestUri, null, null, null, null, null, HAIP_CONFIG
        );

        // Then: redirects to identification portal (no code yet)
        assertNotNull(result.identifyRedirect(), "Wallet-initiated must redirect to identification portal");
        assertTrue(result.identifyRedirect().startsWith(IDENTIFY_BASE_URL + "?session="),
                "Redirect URL must point to identify portal with session token");
        assertNull(result.code(), "No auth code should be issued before identification");
        assertNull(result.redirectUri(), "No wallet redirect before identification");

        // Then: no issuance record created yet (will be created after identification)
        assertEquals(0, issuanceStore.records.size(),
                "No issuance record should be created before identification");
    }

    @Test
    void handleAuthorize_issuerInitiated_returnsCodeImmediately() {
        // Given: issuer-initiated flow — issuer_state links to existing issuance record
        String existingRecordId = "existing-record-123";
        String issuerState = sessionStore.randomToken(16);
        sessionStore.storeIssuerState(issuerState, Map.of("issuanceRecordId", existingRecordId));

        Map<String, String> parParams = Map.of(
                "client_id", "https://wallet.test.fikua.com",
                "redirect_uri", "https://wallet.test.fikua.com/callback",
                "scope", "eu.europa.ec.eudi.pid.1",
                "state", "xyz789",
                "response_type", "code",
                "code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method", "S256",
                "issuer_state", issuerState
        );
        String requestUri = "urn:ietf:params:oauth:request_uri:test456";
        sessionStore.storeParRequest(requestUri, parParams);

        // When: authorize with issuer_state (issuer-initiated)
        var result = service.handleAuthorize(
                requestUri, null, null, null, null, null, HAIP_CONFIG
        );

        // Then: code issued immediately (no identification redirect)
        assertNotNull(result.code(), "Auth code must be issued for issuer-initiated flow");
        assertNull(result.identifyRedirect(), "No identification redirect for issuer-initiated flow");

        // Then: auth code session contains the existing issuanceRecordId
        SessionData session = sessionStore.consumeAuthCode(result.code());
        assertNotNull(session);
        assertEquals(existingRecordId, session.metadata().get("issuanceRecordId"));
    }

    @Test
    void completeIdentification_withValidSession_createsRecordAndReturnsCode() {
        // Given: pending authorization from wallet-initiated flow
        Map<String, String> parParams = Map.of(
                "client_id", "https://wallet.test.fikua.com",
                "redirect_uri", "https://wallet.test.fikua.com/callback",
                "scope", "eu.europa.ec.eudi.pid.1",
                "state", "abc123",
                "response_type", "code",
                "code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method", "S256"
        );
        String requestUri = "urn:ietf:params:oauth:request_uri:test789";
        sessionStore.storeParRequest(requestUri, parParams);

        var authorizeResult = service.handleAuthorize(
                requestUri, null, null, null, null, null, HAIP_CONFIG
        );
        // Extract session token from identify redirect URL
        String sessionToken = authorizeResult.identifyRedirect()
                .substring(authorizeResult.identifyRedirect().indexOf("session=") + "session=".length());

        // When: identification completes with real credential data
        String credentialData = "{\"given_name\":\"Maria\",\"family_name\":\"Garcia\",\"birth_date\":\"1985-03-15\"}";
        var result = service.completeIdentification(sessionToken, credentialData, "x509_cert", "CN=Maria Garcia");

        // Then: auth code issued with redirect to wallet
        assertNotNull(result.code(), "Auth code must be issued after identification");
        assertEquals("https://wallet.test.fikua.com/callback", result.redirectUri());
        assertEquals("abc123", result.state());
        assertNull(result.identifyRedirect(), "No further identification redirect");

        // Then: IssuanceRecord created with real data from identification
        assertEquals(1, issuanceStore.records.size(), "One issuance record must be created");
        IssuanceRecord record = issuanceStore.records.values().iterator().next();
        assertEquals("eu.europa.ec.eudi.pid.1", record.credentialType());
        assertEquals("x509_cert", record.sourceType());
        assertEquals("CN=Maria Garcia", record.sourceRef());
        assertTrue(record.credentialData().contains("Maria"), "Credential data must contain real identification data");

        // Then: auth code session contains issuanceRecordId
        SessionData session = sessionStore.consumeAuthCode(result.code());
        assertNotNull(session);
        assertEquals(record.id(), session.metadata().get("issuanceRecordId"));
    }

    @Test
    void completeIdentification_withInvalidSession_throwsError() {
        // When/Then: completing with invalid session token throws error
        var ex = assertThrows(OAuthErrorException.class, () ->
                service.completeIdentification("invalid-token", "{}", "x509_cert", null)
        );
        assertTrue(ex.getMessage().contains("Invalid or expired identification session"));
    }

    @Test
    void completeIdentification_resolvesCredentialConfigIdFromScope() {
        // Given: PAR with scope eu.europa.ec.eudi.pid.1
        Map<String, String> parParams = Map.of(
                "client_id", "https://wallet.test.fikua.com",
                "redirect_uri", "https://wallet.test.fikua.com/callback",
                "scope", "eu.europa.ec.eudi.pid.1",
                "state", "scope-test",
                "response_type", "code",
                "code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method", "S256"
        );
        String requestUri = "urn:ietf:params:oauth:request_uri:scope-test";
        sessionStore.storeParRequest(requestUri, parParams);

        var authorizeResult = service.handleAuthorize(requestUri, null, null, null, null, null, HAIP_CONFIG);
        String sessionToken = authorizeResult.identifyRedirect()
                .substring(authorizeResult.identifyRedirect().indexOf("session=") + "session=".length());

        // When: complete identification with manual form data
        String credentialData = "{\"given_name\":\"Ana\",\"family_name\":\"Lopez\",\"birth_date\":\"1992-07-20\"}";
        service.completeIdentification(sessionToken, credentialData, "manual_form", "User input");

        // Then: issuance record has credential type derived from scope
        IssuanceRecord record = issuanceStore.records.values().iterator().next();
        assertEquals("eu.europa.ec.eudi.pid.1", record.credentialType(),
                "Credential type must be resolved from scope, not hardcoded");
        assertEquals("manual_form", record.sourceType());
    }

    @Test
    @SuppressWarnings("unchecked")
    void getIdentificationClaims_returnsClaimsForPendingSession() {
        // Given: pending authorization with scope
        Map<String, String> parParams = Map.of(
                "client_id", "https://wallet.test.fikua.com",
                "redirect_uri", "https://wallet.test.fikua.com/callback",
                "scope", "eu.europa.ec.eudi.pid.1",
                "state", "claims-test",
                "response_type", "code",
                "code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method", "S256"
        );
        String requestUri = "urn:ietf:params:oauth:request_uri:claims-test";
        sessionStore.storeParRequest(requestUri, parParams);

        var authorizeResult = service.handleAuthorize(requestUri, null, null, null, null, null, HAIP_CONFIG);
        String sessionToken = authorizeResult.identifyRedirect()
                .substring(authorizeResult.identifyRedirect().indexOf("session=") + "session=".length());

        // When: get claims for the pending session
        var claims = service.getIdentificationClaims(sessionToken);

        // Then: returns credential config id, claims and display
        assertEquals("eu.europa.ec.eudi.pid.1", claims.get("credential_configuration_id"));
        assertNotNull(claims.get("claims"), "Claims must be present");
        assertNotNull(claims.get("display"), "Display must be present");

        var claimsList = (List<Map<String, Object>>) claims.get("claims");
        assertTrue(claimsList.size() >= 3, "Must include at least given_name, family_name, birth_date");

        // Verify claim structure: each has path and display
        var firstClaim = claimsList.get(0);
        assertNotNull(firstClaim.get("path"), "Claim must have path");
        assertNotNull(firstClaim.get("display"), "Claim must have display");
    }

    @Test
    void getIdentificationClaims_withInvalidSession_throwsError() {
        var ex = assertThrows(OAuthErrorException.class, () ->
                service.getIdentificationClaims("invalid-token")
        );
        assertTrue(ex.getMessage().contains("Invalid or expired identification session"));
    }

    // --- Stub IssuanceStore (in-memory, no DB) ---

    static class StubIssuanceStore implements IssuanceStore {
        final ConcurrentHashMap<String, IssuanceRecord> records = new ConcurrentHashMap<>();

        @Override
        public IssuanceRecord create(String credentialType, String credentialData,
                                     String sourceType, String sourceRef) {
            String id = UUID.randomUUID().toString();
            var record = new IssuanceRecord(
                    id, credentialType, credentialData, sourceType, sourceRef,
                    "pending", null, null,
                    Timestamp.from(Instant.now()), Timestamp.from(Instant.now())
            );
            records.put(id, record);
            return record;
        }

        @Override
        public IssuanceRecord findById(String id) {
            return records.get(id);
        }

        @Override
        public void updateStatus(String id, String status) {
            var r = records.get(id);
            if (r != null) {
                records.put(id, new IssuanceRecord(r.id(), r.credentialType(), r.credentialData(),
                        r.sourceType(), r.sourceRef(), status, r.preAuthCode(), r.offerId(),
                        r.createdAt(), Timestamp.from(Instant.now())));
            }
        }

        @Override
        public void updatePreAuthCode(String id, String preAuthCode) {}

        @Override
        public void updateOfferId(String id, String offerId) {}
    }
}
