package com.fikua.lab;

import com.fikua.core.http.ProblemDetail;
import com.fikua.core.oauth2.OAuthErrorException;
import com.fikua.issuer.IssuerService;
import com.fikua.lab.admin.AdminRoutes;
import com.fikua.lab.config.LabConfig;
import com.fikua.lab.db.DatabaseManager;
import com.fikua.lab.db.ProfileRepository;
import io.javalin.Javalin;
import io.javalin.http.staticfiles.Location;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Fikua Lab — OIDF Conformance Testing Platform.
 * Orchestrator: reads FIKUA_ROLES env var and starts the requested services.
 */
public class FikuaLab {

    private static final Logger log = LoggerFactory.getLogger(FikuaLab.class);

    public static void main(String[] args) {
        log.info("Starting Fikua Lab...");

        // Parse roles
        Set<String> roles = parseRoles(System.getenv("FIKUA_ROLES"));
        log.info("Active roles: {}", roles);

        // Load configuration
        LabConfig config = LabConfig.load();
        log.info("Base URL: {}", config.baseUrl());
        log.info("Port: {}", config.port());

        // Initialize database
        DatabaseManager db = new DatabaseManager(config);
        db.migrate();

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

        // Global error handling
        app.exception(OAuthErrorException.class, (e, ctx) -> {
            if (e.httpStatus() == 401) {
                ctx.header("WWW-Authenticate", "DPoP error=\"" + e.error().error() + "\"");
            }
            ctx.status(e.httpStatus()).json(e.error());
        });

        app.exception(Exception.class, (e, ctx) -> {
            log.error("Unhandled error on {}", ctx.path(), e);
            ctx.status(500)
               .contentType(ProblemDetail.CONTENT_TYPE)
               .json(ProblemDetail.internalError(ctx.path()));
        });

        app.error(404, ctx -> {
            ctx.contentType(ProblemDetail.CONTENT_TYPE)
               .json(ProblemDetail.notFound(ctx.path()));
        });

        app.error(405, ctx -> {
            ctx.contentType(ProblemDetail.CONTENT_TYPE)
               .json(ProblemDetail.methodNotAllowed(ctx.path()));
        });

        // Admin routes (always available)
        ProfileRepository profileRepo = new ProfileRepository(db);
        new AdminRoutes(profileRepo).register(app);

        // Start services based on roles
        IssuerService issuerService = null;
        if (roles.contains("issuer")) {
            issuerService = new IssuerService();
            issuerService.start(app, db.dataSource(), config.baseUrl(), config.certsDir());
            log.info("Issuer service started");
        }

        // future: if (roles.contains("wallet")) { ... }
        // future: if (roles.contains("verifier")) { ... }

        // Health check
        app.get("/health", ctx -> ctx.json(Map.of("status", "up", "roles", roles)));

        // State reset (dev/test only)
        if (!"production".equalsIgnoreCase(System.getenv("FIKUA_ENV"))) {
            final IssuerService issuer = issuerService;
            app.post("/reset", ctx -> {
                if (issuer != null) issuer.issuanceService().resetState();
                ctx.json(Map.of("status", "reset"));
            });
        }

        // Start server
        app.start(config.port());
        log.info("Fikua Lab running on port {} with roles: {}", config.port(), roles);

        // Shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("Shutting down...");
            app.stop();
            db.close();
        }));
    }

    /** Parse FIKUA_ROLES env var (comma-separated). Defaults to "issuer". */
    static Set<String> parseRoles(String rolesEnv) {
        if (rolesEnv == null || rolesEnv.isBlank()) {
            return Set.of("issuer");
        }
        return Arrays.stream(rolesEnv.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
    }
}
