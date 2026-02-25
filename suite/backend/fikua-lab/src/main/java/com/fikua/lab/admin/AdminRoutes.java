package com.fikua.lab.admin;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fikua.core.profile.ProfileConfig;
import com.fikua.core.profile.ProfilePresets;
import com.fikua.lab.db.ProfileRepository;
import com.fikua.lab.db.ProfileRepository.ProfileRow;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.sse.SseClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

/**
 * Admin API routes for profile management.
 * Serves the admin frontend and provides CRUD + activation endpoints.
 */
public class AdminRoutes {

    private static final Logger log = LoggerFactory.getLogger(AdminRoutes.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final ProfileRepository profileRepo;

    public AdminRoutes(ProfileRepository profileRepo) {
        this.profileRepo = profileRepo;
    }

    public void register(Javalin app) {
        app.get("/admin/profiles", this::listProfiles);
        app.post("/admin/profiles", this::createProfile);
        app.put("/admin/profiles/{id}", this::updateProfile);
        app.delete("/admin/profiles/{id}", this::deleteProfile);
        app.put("/admin/profiles/{id}/activate", this::activateProfile);
        app.get("/admin/presets", this::listPresets);
        app.get("/admin/health", this::health);
        app.get("/admin/logs", this::recentLogs);
        app.sse("/admin/logs/stream", this::logStream);
    }

    private void listProfiles(Context ctx) {
        List<ProfileRow> profiles = profileRepo.findAll();
        ctx.json(profiles.stream().map(this::toMap).toList());
    }

    private void createProfile(Context ctx) throws Exception {
        var body = MAPPER.readTree(ctx.body());
        String name = body.get("name").asText();
        String role = body.get("role").asText();
        ProfileConfig config = MAPPER.treeToValue(body.get("config"), ProfileConfig.class);
        ProfileRow created = profileRepo.create(name, role, config);
        log.info("Profile created: id={}, name={}, role={}", created.id(), name, role);
        ctx.status(201).json(toMap(created));
    }

    private void updateProfile(Context ctx) throws Exception {
        String id = ctx.pathParam("id");
        var body = MAPPER.readTree(ctx.body());
        String name = body.get("name").asText();
        String role = body.get("role").asText();
        ProfileConfig config = MAPPER.treeToValue(body.get("config"), ProfileConfig.class);
        ProfileRow updated = profileRepo.update(id, name, role, config);
        log.info("Profile updated: id={}, name={}, role={}", id, name, role);
        ctx.json(toMap(updated));
    }

    private void deleteProfile(Context ctx) {
        String id = ctx.pathParam("id");
        profileRepo.delete(id);
        log.info("Profile deleted: id={}", id);
        ctx.status(204);
    }

    private void activateProfile(Context ctx) {
        String id = ctx.pathParam("id");
        profileRepo.activate(id);
        log.info("Profile activated: id={}", id);
        ctx.status(200).json(Map.of("status", "activated"));
    }

    private void recentLogs(Context ctx) {
        ctx.json(LogBufferAppender.getRecentLogs());
    }

    private void logStream(SseClient client) {
        client.keepAlive();
        client.onClose(() -> LogBufferAppender.removeClient(client));

        for (var entry : LogBufferAppender.getRecentLogs()) {
            client.sendEvent("log", toLogJson(entry));
        }

        LogBufferAppender.addClient(client);
    }

    private String toLogJson(LogBufferAppender.LogEntry entry) {
        return "{\"timestamp\":\"" + escapeJson(entry.timestamp()) +
                "\",\"level\":\"" + escapeJson(entry.level()) +
                "\",\"source\":\"" + escapeJson(entry.source()) +
                "\",\"message\":\"" + escapeJson(entry.message()) + "\"}";
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private void listPresets(Context ctx) {
        ctx.json(List.of(
                Map.of("name", "Plain Issuer", "role", "issuer", "config", ProfilePresets.plainIssuer()),
                Map.of("name", "HAIP Issuer", "role", "issuer", "config", ProfilePresets.haipIssuer()),
                Map.of("name", "Plain Verifier", "role", "verifier", "config", ProfilePresets.plainVerifier()),
                Map.of("name", "HAIP Verifier", "role", "verifier", "config", ProfilePresets.haipVerifier())
        ));
    }

    private void health(Context ctx) {
        ctx.json(Map.of(
                "status", "up",
                "endpoints", Map.of(
                        "/.well-known/openid-credential-issuer", "up",
                        "/.well-known/oauth-authorization-server", "up",
                        "/token", "up",
                        "/credential", "up",
                        "/nonce", "up",
                        "/jwks", "up"
                )
        ));
    }

    private Map<String, Object> toMap(ProfileRow row) {
        return Map.of(
                "id", row.id(),
                "name", row.name(),
                "role", row.role(),
                "config", row.config(),
                "isActive", row.isActive()
        );
    }
}
