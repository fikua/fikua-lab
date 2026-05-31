package com.fikua.trustlist.infra.http;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fikua.core.crypto.EcKeyManager;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import io.javalin.Javalin;
import io.javalin.http.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

/**
 * Wallet Provider HTTP routes.
 *
 *   POST /wallet-provider/issue-wia
 *        body: { "client_id": "...", "jwk": { EC P-256 public key } }
 *        -> returns { "wia": "<signed WIA JWT>" }
 *        The WIA is signed by the Wallet Provider's key; the x5c chain lets an
 *        Issuer anchor it to the trusted Wallet Provider CA. cnf.jwk binds the
 *        wallet's proof-of-possession key (the wallet later signs a PoP with it).
 *
 *   GET  /wallet-provider/attestation/status?id=<client_id>
 *        -> mock revocation status for a previously issued WIA.
 */
public class WalletProviderController {

    private static final Logger log = LoggerFactory.getLogger(WalletProviderController.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String PREFIX = "/wallet-provider";
    private static final long WIA_TTL_SECONDS = 24 * 3600; // 24h

    private final EcKeyManager wpKey;
    private final String providerId;

    public WalletProviderController(EcKeyManager wpKey, String baseUrl) {
        this.wpKey = wpKey;
        // baseUrl is the issuer base (e.g. https://lab.fikua.com/issuer); derive
        // the wallet-provider id from its host.
        this.providerId = deriveProviderId(baseUrl);
    }

    public void register(Javalin app) {
        app.post(PREFIX + "/issue-wia", this::issueWia);
        app.get(PREFIX + "/attestation/status", this::status);
        log.info("Wallet Provider routes registered under {}", PREFIX);
    }

    private void issueWia(Context ctx) {
        JsonNode body;
        try {
            body = MAPPER.readTree(ctx.body());
        } catch (Exception e) {
            ctx.status(400).json(Map.of("error", "invalid_json"));
            return;
        }
        String clientId = body.path("client_id").asText(null);
        JsonNode jwkNode = body.get("jwk");
        if (clientId == null || jwkNode == null) {
            ctx.status(400).json(Map.of("error", "missing client_id or jwk"));
            return;
        }

        ECKey holderKey;
        try {
            holderKey = ECKey.parse(jwkNode.toString()); // wallet's PoP public key
        } catch (ParseException e) {
            ctx.status(400).json(Map.of("error", "invalid jwk"));
            return;
        }

        long now = Instant.now().getEpochSecond();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(providerId)            // the Wallet Provider
                .subject(clientId)             // the wallet instance
                .issueTime(new Date(now * 1000))
                .expirationTime(new Date((now + WIA_TTL_SECONDS) * 1000))
                .claim("cnf", Map.of("jwk", holderKey.toJSONObject())) // bind PoP key
                .build();

        // typ=wallet-attestation+jwt, x5c chains to the trusted WP CA.
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("wallet-attestation+jwt"))
                .keyID(wpKey.kid())
                .x509CertChain(wpKey.x5cChain())
                .build();

        String wia = wpKey.signJwt(header, claims);
        log.info("Issued WIA for client_id={}", clientId);
        ctx.json(Map.of("wia", wia, "expires_in", WIA_TTL_SECONDS));
    }

    private void status(Context ctx) {
        String id = ctx.queryParam("id");
        if (id == null || id.isBlank()) {
            ctx.status(400).json(Map.of("error", "missing id"));
            return;
        }
        // Mock: every issued WIA is valid. A real WP tracks revocation state.
        ctx.json(Map.of("id", id, "status", "valid"));
    }

    private static String deriveProviderId(String baseUrl) {
        try {
            java.net.URI u = java.net.URI.create(baseUrl);
            return u.getScheme() + "://" + u.getAuthority() + "/wallet-provider";
        } catch (Exception e) {
            return "https://lab.fikua.com/wallet-provider";
        }
    }
}
