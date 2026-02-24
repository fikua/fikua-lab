package com.fikua.lab.config;

import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * Application configuration loaded from YAML file or environment variables.
 */
public record LabConfig(
        String baseUrl,
        int port,
        String dbUrl,
        String dbUser,
        String dbPassword,
        String certsDir,
        String frontendDir,
        String identifyBaseUrl,
        String resendApiKey,
        String resendFromEmail,
        String walletBaseUrl
) {

    /** Load configuration with env vars taking precedence over YAML defaults. */
    public static LabConfig load() {
        Map<String, Object> yaml = loadYaml();

        return new LabConfig(
                env("FIKUA_BASE_URL", yamlStr(yaml, "base-url", "https://issuer.lab.fikua.com")),
                Integer.parseInt(env("FIKUA_PORT", yamlStr(yaml, "port", "8080"))),
                env("FIKUA_DB_URL", yamlStr(yaml, "db.url", "jdbc:postgresql://localhost:5432/fikua")),
                env("FIKUA_DB_USER", yamlStr(yaml, "db.user", "fikua")),
                env("FIKUA_DB_PASSWORD", yamlStr(yaml, "db.password", "fikua")),
                env("FIKUA_CERTS_DIR", yamlStr(yaml, "certs-dir", "./certs")),
                env("FIKUA_FRONTEND_DIR", yamlStr(yaml, "frontend-dir", "./frontend")),
                env("FIKUA_IDENTIFY_BASE_URL", yamlStr(yaml, "identify-base-url", "https://identify.lab.fikua.com")),
                env("FIKUA_RESEND_API_KEY", yamlStr(yaml, "resend-api-key", "")),
                env("FIKUA_RESEND_FROM_EMAIL", yamlStr(yaml, "resend-from-email", "Fikua Lab <noreply@lab.fikua.com>")),
                env("FIKUA_WALLET_BASE_URL", yamlStr(yaml, "wallet-base-url", "https://wallet.lab.fikua.com"))
        );
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> loadYaml() {
        Path external = Path.of("config.yaml");
        if (Files.exists(external)) {
            try (InputStream is = Files.newInputStream(external)) {
                return new Yaml().load(is);
            } catch (Exception e) {
                // fall through
            }
        }

        try (InputStream is = LabConfig.class.getClassLoader().getResourceAsStream("config.yaml")) {
            if (is != null) {
                return new Yaml().load(is);
            }
        } catch (Exception e) {
            // fall through
        }

        return Map.of();
    }

    @SuppressWarnings("unchecked")
    private static String yamlStr(Map<String, Object> yaml, String dotPath, String defaultVal) {
        String[] parts = dotPath.split("\\.");
        Object current = yaml;
        for (String part : parts) {
            if (current instanceof Map<?, ?> map) {
                current = map.get(part);
            } else {
                return defaultVal;
            }
        }
        return current != null ? current.toString() : defaultVal;
    }

    private static String env(String name, String defaultVal) {
        String val = System.getenv(name);
        return val != null && !val.isBlank() ? val : defaultVal;
    }
}
