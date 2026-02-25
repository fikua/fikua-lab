package com.fikua.issuer.infra.http;

import com.fikua.core.oauth2.ClientAttestationValidator;
import com.fikua.core.oauth2.OAuthError;
import com.fikua.core.oauth2.OAuthErrorException;
import com.fikua.core.profile.ProfileConfig;
import com.fikua.issuer.app.IssuanceService;
import io.javalin.Javalin;
import io.javalin.http.Context;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Thin HTTP controller for OID4VCI issuer endpoints.
 * Parses HTTP requests and delegates to IssuanceService.
 */
public class IssuerController {

    private static final Logger log = LoggerFactory.getLogger(IssuerController.class);
    private static final String API_PREFIX = "/oid4vci/v1";

    private final IssuanceService service;
    private final String baseUrl;

    public IssuerController(IssuanceService service, String baseUrl) {
        this.service = service;
        this.baseUrl = baseUrl;
    }

    public void register(Javalin app) {
        // Well-known endpoints (root path, per spec)
        app.get("/.well-known/openid-credential-issuer", this::credentialIssuerMetadata);
        app.get("/.well-known/oauth-authorization-server", this::authServerMetadata);

        // JWKS
        app.get(API_PREFIX + "/jwks", this::jwks);

        // Credential offer
        app.get(API_PREFIX + "/credential-offer", this::credentialOffer);
        app.get(API_PREFIX + "/credential-offer/{id}", this::credentialOfferById);

        // Token endpoint
        app.post(API_PREFIX + "/token", this::token);

        // Nonce endpoint
        app.post(API_PREFIX + "/nonce", this::nonce);

        // Credential endpoint
        app.post(API_PREFIX + "/credential", this::credential);

        // Authorization endpoint (HAIP)
        app.get(API_PREFIX + "/authorize", this::authorize);

        // PAR endpoint (HAIP)
        app.post(API_PREFIX + "/par", this::par);

        // Identification (wallet-initiated)
        app.get(API_PREFIX + "/identify/claims", this::identificationClaims);
        app.post(API_PREFIX + "/identify/complete", this::completeIdentification);

        // Issuance management
        app.get(API_PREFIX + "/issuance", this::listIssuanceRecords);
        app.post(API_PREFIX + "/issuance", this::triggerIssuance);
    }

    private void credentialIssuerMetadata(Context ctx) {
        ProfileConfig config = service.getActiveConfig();
        log.info("GET /.well-known/openid-credential-issuer");
        ctx.json(service.buildCredentialIssuerMetadata(config));
    }

    private void authServerMetadata(Context ctx) {
        ProfileConfig config = service.getActiveConfig();
        log.info("GET /.well-known/oauth-authorization-server — profile={}", config.isHaip() ? "HAIP" : "pre-auth");
        ctx.json(service.buildAuthServerMetadata(config));
    }

    private void jwks(Context ctx) {
        log.info("GET /jwks");
        ctx.contentType("application/json").result(service.jwksJson());
    }

    private void credentialOffer(Context ctx) {
        log.warn("GET /credential-offer — rejected (must use POST /issuance)");
        throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST,
                "Use POST /oid4vci/v1/issuance with credential_data to trigger issuance");
    }

    private void credentialOfferById(Context ctx) {
        String offerId = ctx.pathParam("id");
        String offerJson = service.getCredentialOffer(offerId);
        if (offerJson == null) {
            log.warn("GET /credential-offer/{} — not found", offerId);
            ctx.status(404).json(OAuthError.invalidRequest("Offer not found"));
            return;
        }
        log.info("GET /credential-offer/{} — resolved", offerId);
        ctx.contentType("application/json").result(offerJson);
    }

    private void token(Context ctx) {
        ProfileConfig config = service.getActiveConfig();
        Map<String, String> params = parseFormParams(ctx);
        String dpopHeader = ctx.header("DPoP");
        String attestation = ctx.header(ClientAttestationValidator.HEADER_CLIENT_ATTESTATION);
        String attestationPop = ctx.header(ClientAttestationValidator.HEADER_CLIENT_ATTESTATION_POP);
        log.info("POST /token — grant_type={}, DPoP present: {}", params.get("grant_type"), dpopHeader != null);
        ctx.header("Cache-Control", "no-store");
        var response = service.handleToken(params, config, dpopHeader, attestation, attestationPop);
        log.info("POST /token — response: token_type={}", response.tokenType());
        ctx.json(response);
    }

    private void nonce(Context ctx) {
        String accessToken = extractAccessToken(ctx.header("Authorization"));
        String dpopHeader = ctx.header("DPoP");
        log.info("POST /nonce — accessToken present: {}, DPoP present: {}", accessToken != null, dpopHeader != null);
        ctx.header("Cache-Control", "no-store");
        var response = service.generateNonce(accessToken, dpopHeader);
        log.info("POST /nonce — c_nonce generated");
        ctx.json(response);
    }

    private void credential(Context ctx) {
        ProfileConfig config = service.getActiveConfig();
        String authHeader = ctx.header("Authorization");
        String body = ctx.body();
        log.info("POST /credential — Authorization: {}, DPoP present: {}, body length: {}",
                authHeader != null ? authHeader.substring(0, Math.min(20, authHeader.length())) + "..." : "null",
                ctx.header("DPoP") != null, body != null ? body.length() : 0);
        log.debug("POST /credential — body: {}", body);

        String accessToken = extractAccessToken(authHeader);
        if (accessToken == null) {
            log.warn("POST /credential — rejected: missing access token");
            throw OAuthErrorException.unauthorized(OAuthError.INVALID_TOKEN, "Missing access token");
        }
        // H10: Reject Bearer scheme for DPoP-bound tokens
        if (config.requiresDPoP() && authHeader != null && authHeader.toLowerCase().startsWith("bearer ")) {
            log.warn("POST /credential — rejected: Bearer scheme used for DPoP-bound token");
            throw OAuthErrorException.unauthorized(OAuthError.INVALID_TOKEN,
                    "DPoP-bound tokens must use DPoP authorization scheme, not Bearer");
        }
        String dpopHeader = ctx.header("DPoP");
        ctx.header("Cache-Control", "no-store");
        var response = service.issueCredential(accessToken, body, config, dpopHeader);
        log.info("POST /credential — response: credentials={}, transaction_id={}",
                response.credentials() != null ? response.credentials().size() : "null",
                response.transactionId());
        ctx.json(response);
    }

    private void authorize(Context ctx) {
        ProfileConfig config = service.getActiveConfig();
        log.info("GET /authorize — request_uri={}, client_id={}", ctx.queryParam("request_uri"), ctx.queryParam("client_id"));
        var result = service.handleAuthorize(
                ctx.queryParam("request_uri"),
                ctx.queryParam("client_id"),
                ctx.queryParam("redirect_uri"),
                ctx.queryParam("state"),
                ctx.queryParam("code_challenge"),
                ctx.queryParam("issuer_state"),
                ctx.queryParam("scope"),
                config
        );

        if (result.identifyRedirect() != null) {
            log.info("GET /authorize — wallet-initiated, redirect to identification portal");
            ctx.redirect(result.identifyRedirect());
        } else if (result.redirectUri() != null) {
            String redirect = result.redirectUri() + "?code=" + result.code();
            if (result.state() != null) redirect += "&state=" + result.state();
            redirect += "&iss=" + java.net.URLEncoder.encode(baseUrl, java.nio.charset.StandardCharsets.UTF_8);
            log.info("GET /authorize — redirect to {}", result.redirectUri());
            ctx.redirect(redirect);
        } else {
            log.info("GET /authorize — code issued (no redirect)");
            ctx.json(Map.of("code", result.code()));
        }
    }

    private void identificationClaims(Context ctx) {
        String session = ctx.queryParam("session");
        if (session == null || session.isBlank()) {
            throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST, "Missing session parameter");
        }
        log.info("GET /identify/claims — session={}", session);
        ctx.json(service.getIdentificationClaims(session));
    }

    private static final com.fasterxml.jackson.databind.ObjectMapper MAPPER =
            new com.fasterxml.jackson.databind.ObjectMapper();

    private void completeIdentification(Context ctx) {
        log.info("POST /identify/complete");
        try {
            var body = MAPPER.readTree(ctx.body());
            if (body == null || !body.has("session") || !body.has("credential_data")) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST,
                        "Missing required fields: session, credential_data");
            }
            String session = body.get("session").asText();
            String credentialData = body.get("credential_data").toString();
            String sourceType = body.has("source_type") ? body.get("source_type").asText() : null;
            String sourceRef = body.has("source_ref") ? body.get("source_ref").asText() : null;

            var result = service.completeIdentification(session, credentialData, sourceType, sourceRef);

            // Build wallet callback redirect URL
            String redirect = result.redirectUri() + "?code=" + result.code();
            if (result.state() != null) redirect += "&state=" + result.state();
            redirect += "&iss=" + java.net.URLEncoder.encode(baseUrl, java.nio.charset.StandardCharsets.UTF_8);

            log.info("POST /identify/complete — redirect to wallet callback");
            ctx.json(Map.of("redirect", redirect));
        } catch (OAuthErrorException e) {
            throw e;
        } catch (Exception e) {
            log.error("Identification completion error", e);
            throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST,
                    "Invalid identification request: " + e.getMessage());
        }
    }

    private void par(Context ctx) {
        ProfileConfig config = service.getActiveConfig();
        Map<String, String> params = parseFormParams(ctx);
        String attestation = ctx.header(ClientAttestationValidator.HEADER_CLIENT_ATTESTATION);
        String attestationPop = ctx.header(ClientAttestationValidator.HEADER_CLIENT_ATTESTATION_POP);
        log.info("POST /par — client_id={}, params={}, attestation_header={}, attestation_pop_header={}",
                params.get("client_id"), params.keySet(),
                attestation != null ? "present" : "null",
                attestationPop != null ? "present" : "null");
        var result = service.handlePar(params, config, attestation, attestationPop);
        log.info("POST /par — request_uri={}", result.get("request_uri"));
        ctx.status(201).json(result);
    }

    private void listIssuanceRecords(Context ctx) {
        int page = parseIntParam(ctx.queryParam("page"), 1);
        int size = parseIntParam(ctx.queryParam("size"), 20);
        String sort = ctx.queryParam("sort") != null ? ctx.queryParam("sort") : "created_at";
        String order = ctx.queryParam("order") != null ? ctx.queryParam("order") : "desc";
        log.info("GET /issuance — page={}, size={}, sort={}, order={}", page, size, sort, order);
        ctx.json(service.listIssuanceRecords(page, size, sort, order));
    }

    private void triggerIssuance(Context ctx) {
        ProfileConfig config = service.getActiveConfig();
        log.info("POST /issuance — profile={}", config.isHaip() ? "HAIP" : "pre-auth");
        ctx.json(service.triggerIssuance(ctx.body(), config));
    }

    // --- Helpers ---

    private String extractAccessToken(String authHeader) {
        if (authHeader == null) return null;
        if (authHeader.toLowerCase().startsWith("bearer ")) {
            return authHeader.substring(7).trim();
        }
        if (authHeader.toLowerCase().startsWith("dpop ")) {
            return authHeader.substring(5).trim();
        }
        return null;
    }

    private int parseIntParam(String value, int defaultValue) {
        if (value == null) return defaultValue;
        try { return Integer.parseInt(value); } catch (NumberFormatException e) { return defaultValue; }
    }

    private Map<String, String> parseFormParams(Context ctx) {
        var map = new LinkedHashMap<String, String>();
        for (var entry : ctx.formParamMap().entrySet()) {
            if (!entry.getValue().isEmpty()) {
                map.put(entry.getKey(), entry.getValue().getFirst());
            }
        }
        return map;
    }
}
