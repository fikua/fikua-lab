package com.fikua.trustlist.infra.http;

import io.javalin.Javalin;
import io.javalin.http.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * HTTP routes for the Trusted List (LOTL mock).
 *
 * All endpoints live under /trustlist and return the static JSON resources
 * verbatim. Content is cached on first read. CORS-friendly: the wallet PWA
 * (a different origin) fetches these, so we set Access-Control-Allow-Origin.
 */
public class TrustListController {

    private static final Logger log = LoggerFactory.getLogger(TrustListController.class);
    private static final String PREFIX = "/trustlist";

    public void register(Javalin app) {
        app.get(PREFIX + "/.well-known/lotl", ctx -> serve(ctx, "lotl.json"));
        app.get(PREFIX + "/issuers", ctx -> serve(ctx, "issuers.json"));
        app.get(PREFIX + "/verifiers", ctx -> serve(ctx, "verifiers.json"));
        app.get(PREFIX + "/wallet-providers", ctx -> serve(ctx, "wallet-providers.json"));
        app.get(PREFIX + "/schemas", ctx -> serve(ctx, "schemas.json"));
        log.info("Trusted List routes registered under {}", PREFIX);
    }

    private void serve(Context ctx, String resourceName) {
        String body = load(resourceName);
        if (body == null) {
            ctx.status(404).json(java.util.Map.of("error", "list_not_found", "list", resourceName));
            return;
        }
        ctx.header("Access-Control-Allow-Origin", "*");
        ctx.header("Cache-Control", "public, max-age=300");
        ctx.contentType("application/json").result(body);
    }

    /** Read a classpath resource under trustlist/. Returns null if absent. */
    private String load(String resourceName) {
        String path = "trustlist/" + resourceName;
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(path)) {
            if (is == null) {
                log.error("Trust list resource not found on classpath: {}", path);
                return null;
            }
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.error("Failed to read trust list resource {}", path, e);
            return null;
        }
    }
}
