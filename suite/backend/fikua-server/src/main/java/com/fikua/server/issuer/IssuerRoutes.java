package com.fikua.server.issuer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fikua.core.crypto.EcKeyManager;
import com.fikua.core.crypto.JwkUtils;
import com.fikua.core.oauth2.*;
import com.fikua.core.oid4vci.*;
import com.fikua.core.profile.ProfileConfig;
import com.fikua.core.sdjwt.SdJwtBuilder;
import com.fikua.server.db.ProfileRepository;
import com.fikua.server.state.InMemoryStore;
import com.fikua.server.state.InMemoryStore.SessionData;
import com.nimbusds.jose.jwk.ECKey;
import io.javalin.Javalin;
import io.javalin.http.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Map;

/**
 * Issuer HTTP endpoints for OID4VCI conformance testing.
 * All API endpoints use the /oid4vci/v1/ prefix.
 * Well-known endpoints remain at root (per spec).
 */
public class IssuerRoutes {

    private static final Logger log = LoggerFactory.getLogger(IssuerRoutes.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String CREDENTIAL_CONFIG_ID = "eu.europa.ec.eudi.pid_vc+sd-jwt";
    private static final String API_PREFIX = "/oid4vci/v1";

    private final ProfileRepository profileRepo;
    private final EcKeyManager issuerKey;
    private final InMemoryStore store;
    private final DPoPValidator dpopValidator;
    private final String baseUrl;

    public IssuerRoutes(ProfileRepository profileRepo, EcKeyManager issuerKey,
                        InMemoryStore store, String baseUrl) {
        this.profileRepo = profileRepo;
        this.issuerKey = issuerKey;
        this.store = store;
        this.dpopValidator = new DPoPValidator();
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
    }

    /** GET /.well-known/openid-credential-issuer */
    private void credentialIssuerMetadata(Context ctx) {
        ProfileConfig config = getActiveConfig();
        ctx.json(CredentialIssuerMetadata.build(baseUrl, config));
    }

    /** GET /.well-known/oauth-authorization-server */
    private void authServerMetadata(Context ctx) {
        ProfileConfig config = getActiveConfig();
        ctx.json(AuthServerMetadata.fromProfile(baseUrl, config));
    }

    /** GET /jwks */
    private void jwks(Context ctx) {
        ctx.contentType("application/json")
           .result(JwkUtils.jwkSetToJson(issuerKey.jwkSet()));
    }

    /** GET /credential-offer — creates a new offer and returns it or its URI */
    private void credentialOffer(Context ctx) {
        ProfileConfig config = getActiveConfig();

        CredentialOffer offer;
        if (config.isHaip()) {
            String issuerState = InMemoryStore.randomToken(16);
            offer = CredentialOffer.authorizationCode(baseUrl, CREDENTIAL_CONFIG_ID, issuerState);
        } else {
            // Pre-authorized code flow
            SessionData session = new SessionData(
                    InMemoryStore.randomToken(16),
                    null, null, Instant.now(), Map.of()
            );
            String preAuthCode = store.createPreAuthCode(session);
            offer = CredentialOffer.preAuthorized(baseUrl, CREDENTIAL_CONFIG_ID, preAuthCode, false);
        }

        try {
            String offerJson = MAPPER.writeValueAsString(offer);

            // Support credential_offer_uri
            if ("by_reference".equalsIgnoreCase(ctx.queryParam("mode"))) {
                String offerId = store.storeCredentialOffer(offerJson);
                String offerUri = baseUrl + API_PREFIX + "/credential-offer/" + offerId;
                ctx.json(Map.of("credential_offer_uri", offerUri));
            } else {
                ctx.contentType("application/json").result(offerJson);
            }
        } catch (Exception e) {
            ctx.status(500).json(OAuthError.invalidRequest("Failed to create offer"));
        }
    }

    /** GET /credential-offer/{id} — retrieve a stored credential offer */
    private void credentialOfferById(Context ctx) {
        String offerId = ctx.pathParam("id");
        String offerJson = store.getCredentialOffer(offerId);
        if (offerJson == null) {
            ctx.status(404).json(OAuthError.invalidRequest("Offer not found"));
            return;
        }
        ctx.contentType("application/json").result(offerJson);
    }

    /** POST /token */
    private void token(Context ctx) {
        ProfileConfig config = getActiveConfig();
        Map<String, String> params = parseFormParams(ctx);
        TokenRequest request = TokenRequest.fromParams(params);

        log.info("Token request: grant_type={}", request.grantType());

        if (request.isPreAuthorizedCode()) {
            handlePreAuthToken(ctx, request, config);
        } else if (request.isAuthorizationCode()) {
            handleAuthCodeToken(ctx, request, config);
        } else {
            ctx.status(400).json(new OAuthError(OAuthError.UNSUPPORTED_GRANT_TYPE,
                    "Unsupported grant type: " + request.grantType()));
        }
    }

    private void handlePreAuthToken(Context ctx, TokenRequest request, ProfileConfig config) {
        if (request.preAuthorizedCode() == null) {
            ctx.status(400).json(OAuthError.invalidGrant("Missing pre-authorized_code"));
            return;
        }

        SessionData session = store.consumePreAuthCode(request.preAuthorizedCode());
        if (session == null) {
            ctx.status(400).json(OAuthError.invalidGrant("Invalid or expired pre-authorized_code"));
            return;
        }

        // Generate access token and nonce
        String cNonce = store.generateNonce();
        SessionData tokenSession = new SessionData(
                session.sessionId(), cNonce, null, Instant.now(), Map.of()
        );
        String accessToken = store.createAccessToken(tokenSession);
        store.createNonce(session.sessionId());

        ctx.json(TokenResponse.bearer(accessToken, cNonce));
    }

    private void handleAuthCodeToken(Context ctx, TokenRequest request, ProfileConfig config) {
        // Validate DPoP if required
        ECKey dpopKey = null;
        if (config.requiresDPoP()) {
            String dpopHeader = ctx.header("DPoP");
            dpopKey = dpopValidator.validate(dpopHeader, "POST", baseUrl + API_PREFIX + "/token", null);
        }

        // Validate PKCE
        if (config.requiresPkce()) {
            if (request.codeVerifier() == null) {
                ctx.status(400).json(OAuthError.invalidRequest("Missing code_verifier"));
                return;
            }
            // In a full implementation, verify against stored code_challenge
        }

        SessionData session = store.consumeAuthCode(request.code());
        if (session == null) {
            ctx.status(400).json(OAuthError.invalidGrant("Invalid authorization code"));
            return;
        }

        String cNonce = store.generateNonce();
        SessionData tokenSession = new SessionData(
                session.sessionId(), cNonce, dpopKey, Instant.now(), Map.of()
        );
        String accessToken = store.createAccessToken(tokenSession);
        store.createNonce(session.sessionId());

        if (config.requiresDPoP()) {
            ctx.json(TokenResponse.dpop(accessToken, cNonce));
        } else {
            ctx.json(TokenResponse.bearer(accessToken, cNonce));
        }
    }

    /** POST /nonce */
    private void nonce(Context ctx) {
        String nonce = store.generateNonce();
        ctx.json(Map.of("c_nonce", nonce, "c_nonce_expires_in", 86400));
    }

    /** POST /credential */
    private void credential(Context ctx) {
        ProfileConfig config = getActiveConfig();

        // Validate access token
        String authHeader = ctx.header("Authorization");
        String accessToken = extractBearerToken(authHeader);
        if (accessToken == null) {
            ctx.status(401).json(OAuthError.invalidRequest("Missing access token"));
            return;
        }

        SessionData session = store.getAccessTokenSession(accessToken);
        if (session == null) {
            ctx.status(401).json(new OAuthError(OAuthError.INVALID_TOKEN, "Invalid access token"));
            return;
        }

        // Validate DPoP for resource request if required
        if (config.requiresDPoP()) {
            String dpopHeader = ctx.header("DPoP");
            dpopValidator.validate(dpopHeader, "POST", baseUrl + API_PREFIX + "/credential", null);
        }

        try {
            CredentialRequest request = MAPPER.readValue(ctx.body(), CredentialRequest.class);
            log.info("Credential request: format={}", request.format());

            // Validate proof of possession
            ECKey walletKey = ProofValidator.validate(
                    request.proof(), baseUrl, session.cNonce()
            );

            // Build SD-JWT VC (EUDI PID)
            String sdJwt = new SdJwtBuilder(issuerKey)
                    .vct("eu.europa.ec.eudi.pid.1")
                    .issuer(baseUrl)
                    .subject("urn:fikua:pid:" + InMemoryStore.randomToken(8))
                    .selectiveClaim("given_name", "Jan")
                    .selectiveClaim("family_name", "Kowalski")
                    .selectiveClaim("birth_date", "1990-01-15")
                    .plainClaim("issuing_authority", "Fikua Lab")
                    .plainClaim("issuing_country", "EU")
                    .holderKey(walletKey)
                    .build()
                    .serialize();

            // Generate new nonce
            String newNonce = store.generateNonce();

            ctx.json(CredentialResponse.success(sdJwt, newNonce));

        } catch (OAuthErrorException e) {
            ctx.status(e.httpStatus()).json(e.error());
        } catch (Exception e) {
            log.error("Credential issuance error", e);
            ctx.status(400).json(OAuthError.invalidRequest("Invalid credential request: " + e.getMessage()));
        }
    }

    /** GET /oid4vci/v1/authorize — authorization endpoint (HAIP flow) */
    private void authorize(Context ctx) {
        ProfileConfig config = getActiveConfig();
        if (!config.isHaip()) {
            ctx.status(400).json(OAuthError.invalidRequest("Authorization endpoint not available for this profile"));
            return;
        }

        // Extract authorization request params
        String clientId = ctx.queryParam("client_id");
        String redirectUri = ctx.queryParam("redirect_uri");
        String state = ctx.queryParam("state");
        String codeChallenge = ctx.queryParam("code_challenge");
        String requestUri = ctx.queryParam("request_uri");

        // Generate authorization code
        SessionData session = new SessionData(
                InMemoryStore.randomToken(16),
                null, null, Instant.now(),
                Map.of("client_id", clientId != null ? clientId : "",
                       "redirect_uri", redirectUri != null ? redirectUri : "",
                       "code_challenge", codeChallenge != null ? codeChallenge : "")
        );
        String authCode = store.createAuthCode(session);

        // Redirect back to client with authorization code
        if (redirectUri != null) {
            String redirect = redirectUri + "?code=" + authCode;
            if (state != null) redirect += "&state=" + state;
            ctx.redirect(redirect);
        } else {
            ctx.json(Map.of("code", authCode));
        }
    }

    /** POST /oid4vci/v1/par — pushed authorization request (HAIP flow) */
    private void par(Context ctx) {
        ProfileConfig config = getActiveConfig();
        if (!config.isHaip()) {
            ctx.status(400).json(OAuthError.invalidRequest("PAR not available for this profile"));
            return;
        }

        Map<String, String> params = parseFormParams(ctx);
        String requestUri = "urn:ietf:params:oauth:request_uri:" + InMemoryStore.randomToken(16);

        ctx.status(201).json(Map.of(
                "request_uri", requestUri,
                "expires_in", 60
        ));
    }

    // --- Helpers ---

    private ProfileConfig getActiveConfig() {
        var active = profileRepo.findActive();
        if (active == null) {
            throw new RuntimeException("No active profile configured");
        }
        return active.config();
    }

    private String extractBearerToken(String authHeader) {
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
        var map = new java.util.LinkedHashMap<String, String>();
        for (var entry : ctx.formParamMap().entrySet()) {
            if (!entry.getValue().isEmpty()) {
                map.put(entry.getKey(), entry.getValue().getFirst());
            }
        }
        return map;
    }
}
