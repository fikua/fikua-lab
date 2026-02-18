package com.fikua.server.db;

import com.fikua.server.config.LabConfig;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.flywaydb.core.Flyway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;

/**
 * Database connection pool and migration management.
 * Uses HikariCP for connection pooling and Flyway for schema migrations.
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

    /** Run Flyway migrations. */
    public void migrate() {
        Flyway flyway = Flyway.configure()
                .dataSource(dataSource)
                .locations("classpath:db/migration")
                .load();

        int count = flyway.migrate().migrationsExecuted;
        log.info("Flyway: {} migrations applied", count);
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
