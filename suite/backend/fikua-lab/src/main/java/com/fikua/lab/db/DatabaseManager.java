package com.fikua.lab.db;

import com.fikua.lab.config.LabConfig;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.SQLException;

/**
 * Database connection pool and migration management.
 * Uses HikariCP for connection pooling and SQL file-based migrations.
 */
public class DatabaseManager implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(DatabaseManager.class);
    private final HikariDataSource dataSource;

    public DatabaseManager(LabConfig config) {
        HikariConfig hikari = new HikariConfig();
        hikari.setJdbcUrl(config.dbUrl());
        hikari.setUsername(config.dbUser());
        hikari.setPassword(config.dbPassword());
        hikari.setMaximumPoolSize(10);
        hikari.setMinimumIdle(2);
        hikari.setConnectionTimeout(5000);

        this.dataSource = new HikariDataSource(hikari);
        log.info("Database pool initialized: {}", config.dbUrl());
    }

    private static final String[] MIGRATIONS = {
            "V1__initial_schema.sql",
            "V2__seed_profiles.sql",
            "V3__issuance_records.sql",
            "V4__issuance_email_draft.sql",
            "V5__issuance_tx_code.sql"
    };

    /** Run database migrations from SQL files. */
    public void migrate() {
        String migrationsDir = System.getenv().getOrDefault("FIKUA_MIGRATIONS_DIR", null);
        try (Connection conn = dataSource.getConnection();
             var stmt = conn.createStatement()) {
            for (String migration : MIGRATIONS) {
                String sql = loadMigration(migrationsDir, migration);
                stmt.execute(sql);
                log.info("Migration applied: {}", migration);
            }
            log.info("All database migrations applied successfully");
        } catch (Exception e) {
            log.error("Failed to run migrations", e);
            throw new RuntimeException("Database migration failed", e);
        }
    }

    private String loadMigration(String migrationsDir, String filename) throws IOException {
        if (migrationsDir != null) {
            Path path = Path.of(migrationsDir, filename);
            log.info("Loading migration from filesystem: {}", path);
            return Files.readString(path, StandardCharsets.UTF_8);
        }
        try (InputStream is = getClass().getClassLoader().getResourceAsStream("db/migration/" + filename)) {
            if (is == null) throw new IOException("Migration not found on classpath: " + filename);
            log.info("Loading migration from classpath: {}", filename);
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /** Get a connection from the pool. */
    public Connection getConnection() throws SQLException {
        return dataSource.getConnection();
    }

    /** Get the underlying DataSource. */
    public DataSource dataSource() {
        return dataSource;
    }

    @Override
    public void close() {
        if (dataSource != null && !dataSource.isClosed()) {
            dataSource.close();
            log.info("Database pool closed");
        }
    }
}
