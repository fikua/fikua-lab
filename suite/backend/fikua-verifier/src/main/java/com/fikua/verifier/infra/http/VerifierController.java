package com.fikua.verifier.infra.http;

import com.fikua.core.oid4vp.VerificationResult;
import com.fikua.verifier.app.VerificationService;
import com.fikua.verifier.app.port.SessionStore.VerificationSession;
import io.javalin.Javalin;
import io.javalin.http.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Thin HTTP controller for OID4VP verifier endpoints.
 * Parses HTTP requests and delegates to VerificationService.
 */
public class VerifierController {

    private static final Logger log = LoggerFactory.getLogger(VerifierController.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String API_PREFIX = "/oid4vp/v1";

    private final VerificationService service;
    private final String baseUrl;

    public VerifierController(VerificationService service, String baseUrl) {
        this.service = service;
        this.baseUrl = baseUrl;
    }

    /** Register all OID4VP verifier routes on the Javalin app. */
    public void register(Javalin app) {
        // Session management
        app.post(API_PREFIX + "/session", this::createSession);

        // Request Object endpoint (wallet fetches signed Authorization Request).
        // POST supports request_uri_method=post (OID4VP); the wallet may include
        // wallet_metadata / wallet_nonce form params, which we currently ignore.
        app.get(API_PREFIX + "/request/{id}", this::getRequestObject);
        app.post(API_PREFIX + "/request/{id}", this::getRequestObject);

        // Response endpoint (wallet POSTs VP Token via direct_post)
        app.post(API_PREFIX + "/response", this::handleResponse);

        // Result endpoint (frontend polls for verification result)
        app.get(API_PREFIX + "/result/{id}", this::getResult);
    }

    /**
     * POST /oid4vp/v1/session
     * Creates a new verification session and returns the request_uri.
     */
    private void createSession(Context ctx) {
        log.info("POST /oid4vp/v1/session");

        // Parse request body
        String credentialType = "eu.europa.ec.eudi.pid.1"; // default
        List<String> requestedClaims = List.of("given_name", "family_name", "birth_date"); // default
        String format = null; // null ⇒ active profile's credentialFormat decides

        String body = ctx.body();
        if (body != null && !body.isBlank()) {
            try {
                var node = MAPPER.readTree(body);
                if (node.has("credential_type")) {
                    credentialType = node.get("credential_type").asText();
                }
                if (node.has("format")) {
                    format = node.get("format").asText();
                }
                if (node.has("claims") && node.get("claims").isArray()) {
                    requestedClaims = new java.util.ArrayList<>();
                    for (var claim : node.get("claims")) {
                        requestedClaims.add(claim.asText());
                    }
                }
            } catch (Exception e) {
                log.warn("Failed to parse session request body: {}", e.getMessage());
            }
        }

        VerificationSession session = service.createSession(credentialType, requestedClaims, format);
        String requestUri = service.buildRequestUri(session.sessionId());

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("session_id", session.sessionId());
        response.put("request_uri", requestUri);
        response.put("client_id", session.clientId());
        response.put("state", session.state());

        ctx.status(201).json(response);
    }

    /**
     * GET /oid4vp/v1/request/{id}
     * Returns the signed Request Object (JAR JWT) for the wallet.
     */
    private void getRequestObject(Context ctx) {
        String sessionId = ctx.pathParam("id");
        log.info("GET /oid4vp/v1/request/{}", sessionId);

        String requestObject = service.getRequestObject(sessionId);
        if (requestObject == null) {
            ctx.status(404).json(Map.of("error", "invalid_request",
                    "error_description", "Session not found or expired"));
            return;
        }

        // TODO P1: Return as application/oauth-authz-req+jwt when signed JAR is implemented
        // For now, return as JSON (stub)
        ctx.contentType("application/json").result(requestObject);
    }

    /**
     * POST /oid4vp/v1/response
     * Receives the VP Token from the wallet via direct_post.
     */
    private void handleResponse(Context ctx) {
        log.info("POST /oid4vp/v1/response");

        // Parse form params (direct_post uses application/x-www-form-urlencoded)
        String vpToken = ctx.formParam("vp_token");
        String presentationSubmission = ctx.formParam("presentation_submission");
        String state = ctx.formParam("state");
        String response = ctx.formParam("response"); // for direct_post.jwt (JWE)

        VerificationResult result;
        if (response != null && !response.isBlank()) {
            // direct_post.jwt: vp_token and state are inside the encrypted JWE.
            log.info("Received encrypted response (direct_post.jwt), length={}", response.length());
            var outcome = service.handleEncryptedResponse(response);
            result = outcome.result();
            state = outcome.state(); // recover state from the decrypted payload
        } else {
            if (state == null || state.isBlank()) {
                ctx.status(400).json(Map.of("error", "invalid_request",
                        "error_description", "Missing state parameter"));
                return;
            }
            if (vpToken == null || vpToken.isBlank()) {
                ctx.status(400).json(Map.of("error", "invalid_request",
                        "error_description", "Missing vp_token or response parameter"));
                return;
            }
            result = service.handleResponse(state, vpToken, presentationSubmission);
        }

        // Return redirect_uri for same-device flow (OID4VP §8.2)
        VerificationSession session = state != null ? service.getSessionByState(state) : null;
        if (session != null && result.status().equals("success")) {
            ctx.json(Map.of("redirect_uri",
                    baseUrl + API_PREFIX + "/result/" + session.sessionId()));
        } else {
            // Invalid presentation / decryption / unknown state: per OID4VP §8.2
            // the verifier must reject with a 4xx, not a 200 with an error body.
            ctx.status(400).json(result);
        }
    }

    /**
     * GET /oid4vp/v1/result/{id}
     * Returns the verification result for polling.
     */
    private void getResult(Context ctx) {
        String sessionId = ctx.pathParam("id");
        log.info("GET /oid4vp/v1/result/{}", sessionId);

        var result = service.getResult(sessionId);
        if (result == null) {
            ctx.status(404).json(Map.of("error", "not_found",
                    "error_description", "Session not found"));
            return;
        }

        ctx.json(result);
    }
}
