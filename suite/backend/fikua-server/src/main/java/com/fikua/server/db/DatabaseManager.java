package com.fikua.server.db;

import com.fikua.server.config.LabConfig;
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

    /** Run database migrations from SQL files. */
    public void migrate() {
        String migrationsDir = System.getenv().getOrDefault("FIKUA_MIGRATIONS_DIR", null);
        try {
            String sql;
            if (migrationsDir != null) {
                Path path = Path.of(migrationsDir, "V1__initial_schema.sql");
                sql = Files.readString(path, StandardCharsets.UTF_8);
                log.info("Loading migration from filesystem: {}", path);
            } else {
                try (InputStream is = getClass().getClassLoader().getResourceAsStream("db/migration/V1__initial_schema.sql")) {
                    if (is == null) throw new IOException("Migration resource not found on classpath");
                    sql = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                }
                log.info("Loading migration from classpath");
            }

            try (Connection conn = dataSource.getConnection();
                 var stmt = conn.createStatement()) {
                stmt.execute(sql);
            }
            log.info("Database migration applied successfully");
        } catch (Exception e) {
            log.error("Failed to run migration", e);
            throw new RuntimeException("Database migration failed", e);
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
