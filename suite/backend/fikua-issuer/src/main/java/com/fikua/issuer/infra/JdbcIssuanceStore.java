package com.fikua.issuer.infra;

import com.fikua.issuer.app.port.IssuanceStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.sql.*;
import java.util.UUID;

/**
 * JDBC implementation of IssuanceStore using PostgreSQL.
 */
public class JdbcIssuanceStore implements IssuanceStore {

    private static final Logger log = LoggerFactory.getLogger(JdbcIssuanceStore.class);
    private final DataSource dataSource;

    public JdbcIssuanceStore(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public IssuanceRecord create(String credentialType, String credentialData,
                                  String sourceType, String sourceRef) {
        String id = UUID.randomUUID().toString();
        String sql = """
                INSERT INTO issuance_records (id, credential_type, credential_data, source_type, source_ref)
                VALUES (?::uuid, ?, ?::jsonb, ?, ?)
                """;
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, id);
            ps.setString(2, credentialType);
            ps.setString(3, credentialData != null ? credentialData : "{}");
            ps.setString(4, sourceType);
            ps.setString(5, sourceRef);
            ps.executeUpdate();
            return findById(id);
        } catch (Exception e) {
            log.error("Failed to create issuance record", e);
            throw new RuntimeException("Failed to create issuance record", e);
        }
    }

    @Override
    public IssuanceRecord findById(String id) {
        String sql = """
                SELECT id, credential_type, credential_data, source_type, source_ref,
                       status, pre_auth_code, offer_id, created_at, updated_at
                FROM issuance_records WHERE id = ?::uuid
                """;
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? mapRow(rs) : null;
            }
        } catch (Exception e) {
            log.error("Failed to find issuance record {}", id, e);
            return null;
        }
    }

    @Override
    public void updateStatus(String id, String status) {
        String sql = "UPDATE issuance_records SET status = ?, updated_at = now() WHERE id = ?::uuid";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, status);
            ps.setString(2, id);
            ps.executeUpdate();
        } catch (Exception e) {
            log.error("Failed to update status for issuance record {}", id, e);
        }
    }

    @Override
    public void updatePreAuthCode(String id, String preAuthCode) {
        String sql = "UPDATE issuance_records SET pre_auth_code = ?, updated_at = now() WHERE id = ?::uuid";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, preAuthCode);
            ps.setString(2, id);
            ps.executeUpdate();
        } catch (Exception e) {
            log.error("Failed to update pre_auth_code for issuance record {}", id, e);
        }
    }

    @Override
    public void updateOfferId(String id, String offerId) {
        String sql = "UPDATE issuance_records SET offer_id = ?, updated_at = now() WHERE id = ?::uuid";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, offerId);
            ps.setString(2, id);
            ps.executeUpdate();
        } catch (Exception e) {
            log.error("Failed to update offer_id for issuance record {}", id, e);
        }
    }

    private IssuanceRecord mapRow(ResultSet rs) throws SQLException {
        return new IssuanceRecord(
                rs.getString("id"),
                rs.getString("credential_type"),
                rs.getString("credential_data"),
                rs.getString("source_type"),
                rs.getString("source_ref"),
                rs.getString("status"),
                rs.getString("pre_auth_code"),
                rs.getString("offer_id"),
                rs.getTimestamp("created_at"),
                rs.getTimestamp("updated_at")
        );
    }
}
