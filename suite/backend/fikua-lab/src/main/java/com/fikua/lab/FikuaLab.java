package com.fikua.lab;

import com.fikua.core.http.ProblemDetail;
import com.fikua.core.oauth2.DPoPNonceRequiredException;
import com.fikua.core.oauth2.OAuthErrorException;
import com.fikua.issuer.IssuerService;
import com.fikua.issuer.app.port.EmailService;
import com.fikua.issuer.infra.NoOpEmailService;
import com.fikua.issuer.infra.ResendEmailService;
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

        // H6: DPoP-Nonce required — return 401 with DPoP-Nonce header (RFC 9449 §8)
        app.exception(DPoPNonceRequiredException.class, (e, ctx) -> {
            String freshNonce = java.util.UUID.randomUUID().toString();
            ctx.header("DPoP-Nonce", freshNonce);
            ctx.header("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"");
            ctx.status(401).json(e.error());
        });

        app.exception(OAuthErrorException.class, (e, ctx) -> {
            log.warn("OAuth error on {} {}: {} — {}",
                    ctx.method(), ctx.path(), e.error().error(), e.error().errorDescription());
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
            // Email service: use Resend if API key is configured, otherwise NoOp (logs only)
            EmailService emailService;
            if (config.resendApiKey() != null && !config.resendApiKey().isBlank()) {
                emailService = new ResendEmailService(config.resendApiKey(), config.resendFromEmail());
                log.info("Email service: Resend (from: {})", config.resendFromEmail());
            } else {
                emailService = new NoOpEmailService();
                log.info("Email service: NoOp (set FIKUA_RESEND_API_KEY to enable real emails)");
            }

            issuerService = new IssuerService();
            issuerService.start(app, db.dataSource(), config.baseUrl(), config.certsDir(),
                    config.identifyBaseUrl(), emailService, config.walletBaseUrl());
            log.info("Issuer service started");
        }

        // Verifier service
        com.fikua.verifier.VerifierService verifierService = null;
        if (roles.contains("verifier")) {
            verifierService = new com.fikua.verifier.VerifierService();
            verifierService.start(app, db.dataSource(), config.verifierBaseUrl(), config.certsDir());
            log.info("Verifier service started");
        }

        // future: if (roles.contains("wallet")) { ... }

        // Health check
        app.get("/health", ctx -> ctx.json(Map.of("status", "up", "roles", roles)));

        // State reset (dev/test only)
        if (!"production".equalsIgnoreCase(System.getenv("FIKUA_ENV"))) {
            final IssuerService issuer = issuerService;
            final com.fikua.verifier.VerifierService verifier = verifierService;
            app.post("/reset", ctx -> {
                if (issuer != null) issuer.issuanceService().resetState();
                if (verifier != null) verifier.verificationService().resetState();
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
