package com.fikua.issuer.infra;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fikua.core.profile.ProfileConfig;
import com.fikua.issuer.app.port.ProfileStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

/**
 * JDBC implementation of ProfileStore using PostgreSQL.
 */
public class JdbcProfileStore implements ProfileStore {

    private static final Logger log = LoggerFactory.getLogger(JdbcProfileStore.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final DataSource dataSource;

    public JdbcProfileStore(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public ActiveProfile findActive() {
        String sql = "SELECT id, config FROM profiles WHERE is_active = true LIMIT 1";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            if (rs.next()) {
                return new ActiveProfile(
                        rs.getString("id"),
                        MAPPER.readValue(rs.getString("config"), ProfileConfig.class)
                );
            }
            return null;
        } catch (Exception e) {
            log.error("Failed to find active profile", e);
            return null;
        }
    }
}
