package com.fikua.server;

import com.fikua.core.crypto.EcKeyManager;
import com.fikua.core.oauth2.OAuthError;
import com.fikua.core.oauth2.OAuthErrorException;
import com.fikua.server.admin.AdminRoutes;
import com.fikua.server.config.LabConfig;
import com.fikua.core.crypto.X509CertUtil;
import com.fikua.server.db.DatabaseManager;
import com.fikua.server.db.IssuanceRecordRepository;
import com.fikua.server.db.ProfileRepository;
import com.fikua.server.issuer.IssuerRoutes;
import com.fikua.server.state.InMemoryStore;
import io.javalin.Javalin;
import io.javalin.http.staticfiles.Location;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Fikua Lab — OIDF Conformance Testing Platform.
 * Main entry point: boots Javalin server with all routes.
 */
public class FikuaLab {

    private static final Logger log = LoggerFactory.getLogger(FikuaLab.class);

    public static void main(String[] args) {
        log.info("Starting Fikua Lab...");

        // Load configuration
        LabConfig config = LabConfig.load();
        log.info("Base URL: {}", config.baseUrl());
        log.info("Port: {}", config.port());

        // Initialize database
        DatabaseManager db = new DatabaseManager(config);
        db.migrate();

        // Load issuer signing key (PEM if available, otherwise generate)
        EcKeyManager issuerKey;
        var certPath = java.nio.file.Path.of(config.certsDir(), "issuer-cert.pem");
        var keyPath = java.nio.file.Path.of(config.certsDir(), "issuer-key.pem");
        if (java.nio.file.Files.exists(certPath) && java.nio.file.Files.exists(keyPath)) {
            var cert = X509CertUtil.loadCertificate(certPath);
            var privKey = X509CertUtil.loadPrivateKey(keyPath);
            issuerKey = EcKeyManager.fromPem(privKey, cert);
            log.info("Issuer key loaded from PEM, kid={}, subject={}", issuerKey.kid(), cert.getSubjectX500Principal());
        } else {
            issuerKey = EcKeyManager.generate();
            log.warn("No PEM certs at {}, using generated key (kid={}). x5c will be empty.", config.certsDir(), issuerKey.kid());
        }

        // Initialize stores
        InMemoryStore store = new InMemoryStore();
        ProfileRepository profileRepo = new ProfileRepository(db);
        IssuanceRecordRepository issuanceRepo = new IssuanceRecordRepository(db);

        // Create Javalin app
        Javalin app = Javalin.create(javalinConfig -> {
            var frontendDir = new java.io.File(config.frontendDir());
            if (frontendDir.isDirectory()) {
                javalinConfig.staticFiles.add(cfg -> {
                    cfg.directory = config.frontendDir();
                    cfg.hostedPath = "/ui";
                    cfg.location = Location.EXTERNAL;
                });
            } else {
                log.warn("Frontend directory not found: {}, static files disabled", config.frontendDir());
            }
            javalinConfig.http.defaultContentType = "application/json";
        });

        // Global error handling for OAuth errors
        app.exception(OAuthErrorException.class, (e, ctx) -> {
            ctx.status(e.httpStatus()).json(e.error());
        });

        app.exception(Exception.class, (e, ctx) -> {
            log.error("Unhandled error", e);
            ctx.status(500).json(OAuthError.invalidRequest("Internal server error"));
        });

        // Register routes
        new AdminRoutes(profileRepo).register(app);
        new IssuerRoutes(profileRepo, issuanceRepo, issuerKey, store, config.baseUrl()).register(app);

        // Health check
        app.get("/health", ctx -> ctx.json(java.util.Map.of("status", "up")));

        // State reset (for between test runs) — only enabled in dev/test
        if (!"production".equalsIgnoreCase(System.getenv("FIKUA_ENV"))) {
            app.post("/reset", ctx -> {
                store.clear();
                ctx.json(java.util.Map.of("status", "reset"));
            });
        }

        // Start server
        app.start(config.port());
        log.info("Fikua Lab running on port {}", config.port());

        // Shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("Shutting down...");
            app.stop();
            db.close();
        }));
    }
}
