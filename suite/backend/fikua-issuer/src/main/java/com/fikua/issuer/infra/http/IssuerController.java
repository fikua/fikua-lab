package com.fikua.issuer.infra.http;

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

        // Issuance trigger
        app.post(API_PREFIX + "/issuance", this::triggerIssuance);
    }

    private void credentialIssuerMetadata(Context ctx) {
        ProfileConfig config = service.getActiveConfig();
        ctx.json(service.buildCredentialIssuerMetadata(config));
    }

    private void authServerMetadata(Context ctx) {
        ProfileConfig config = service.getActiveConfig();
        ctx.json(service.buildAuthServerMetadata(config));
    }

    private void jwks(Context ctx) {
        ctx.contentType("application/json").result(service.jwksJson());
    }

    private void credentialOffer(Context ctx) {
        throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST,
                "Use POST /oid4vci/v1/issuance with credential_data to trigger issuance");
    }

    private void credentialOfferById(Context ctx) {
        String offerId = ctx.pathParam("id");
        String offerJson = service.getCredentialOffer(offerId);
        if (offerJson == null) {
            ctx.status(404).json(OAuthError.invalidRequest("Offer not found"));
            return;
        }
        ctx.contentType("application/json").result(offerJson);
    }

    private void token(Context ctx) {
        ProfileConfig config = service.getActiveConfig();
        Map<String, String> params = parseFormParams(ctx);
        String dpopHeader = ctx.header("DPoP");
        log.info("POST /token — grant_type={}, DPoP present: {}", params.get("grant_type"), dpopHeader != null);
        ctx.header("Cache-Control", "no-store");
        var response = service.handleToken(params, config, dpopHeader);
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
            throw OAuthErrorException.unauthorized(OAuthError.INVALID_TOKEN, "Missing access token");
        }
        // H10: Reject Bearer scheme for DPoP-bound tokens
        if (config.requiresDPoP() && authHeader != null && authHeader.toLowerCase().startsWith("bearer ")) {
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
        var result = service.handleAuthorize(
                ctx.queryParam("request_uri"),
                ctx.queryParam("client_id"),
                ctx.queryParam("redirect_uri"),
                ctx.queryParam("state"),
                ctx.queryParam("code_challenge"),
                ctx.queryParam("issuer_state"),
                config
        );

        if (result.redirectUri() != null) {
            String redirect = result.redirectUri() + "?code=" + result.code();
            if (result.state() != null) redirect += "&state=" + result.state();
            redirect += "&iss=" + java.net.URLEncoder.encode(baseUrl, java.nio.charset.StandardCharsets.UTF_8);
            ctx.redirect(redirect);
        } else {
            ctx.json(Map.of("code", result.code()));
        }
    }

    private void par(Context ctx) {
        ProfileConfig config = service.getActiveConfig();
        Map<String, String> params = parseFormParams(ctx);
        ctx.status(201).json(service.handlePar(params, config));
    }

    private void triggerIssuance(Context ctx) {
        ProfileConfig config = service.getActiveConfig();
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
