package com.fikua.issuer.infra;

import com.fikua.issuer.app.port.IssuanceStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * JDBC implementation of IssuanceStore using PostgreSQL.
 */
public class JdbcIssuanceStore implements IssuanceStore {

    private static final Logger log = LoggerFactory.getLogger(JdbcIssuanceStore.class);
    private final DataSource dataSource;

    private static final String SELECT_COLUMNS =
            "id, credential_type, credential_data, source_type, source_ref, " +
            "status, pre_auth_code, offer_id, recipient_email, created_at, updated_at";

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
    public IssuanceRecord createDraft(String credentialType, String credentialData,
                                       String sourceType, String sourceRef, String recipientEmail) {
        String id = UUID.randomUUID().toString();
        String sql = """
                INSERT INTO issuance_records (id, credential_type, credential_data, source_type, source_ref,
                                              status, recipient_email)
                VALUES (?::uuid, ?, ?::jsonb, ?, ?, 'draft', ?)
                """;
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, id);
            ps.setString(2, credentialType);
            ps.setString(3, credentialData != null ? credentialData : "{}");
            ps.setString(4, sourceType);
            ps.setString(5, sourceRef);
            ps.setString(6, recipientEmail != null ? recipientEmail.toLowerCase().trim() : null);
            ps.executeUpdate();
            return findById(id);
        } catch (Exception e) {
            log.error("Failed to create draft issuance record", e);
            throw new RuntimeException("Failed to create draft issuance record", e);
        }
    }

    @Override
    public IssuanceRecord findById(String id) {
        String sql = "SELECT " + SELECT_COLUMNS + " FROM issuance_records WHERE id = ?::uuid";
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
    public IssuanceRecord findDraftByEmail(String email) {
        String sql = "SELECT " + SELECT_COLUMNS +
                " FROM issuance_records WHERE recipient_email = ? AND status = 'draft'" +
                " ORDER BY created_at DESC LIMIT 1";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, email != null ? email.toLowerCase().trim() : null);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? mapRow(rs) : null;
            }
        } catch (Exception e) {
            log.error("Failed to find draft issuance record by email {}", email, e);
            return null;
        }
    }

    private static final Set<String> ALLOWED_SORT_FIELDS =
            Set.of("created_at", "updated_at", "status", "credential_type");
    private static final Set<String> ALLOWED_SORT_ORDERS = Set.of("asc", "desc");

    @Override
    public List<IssuanceRecord> findAll(int offset, int limit, String sortField, String sortOrder) {
        String safeField = ALLOWED_SORT_FIELDS.contains(sortField) ? sortField : "created_at";
        String safeOrder = ALLOWED_SORT_ORDERS.contains(sortOrder) ? sortOrder : "desc";
        String sql = ("SELECT " + SELECT_COLUMNS +
                " FROM issuance_records ORDER BY %s %s LIMIT ? OFFSET ?").formatted(safeField, safeOrder);
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, limit);
            ps.setInt(2, offset);
            try (ResultSet rs = ps.executeQuery()) {
                List<IssuanceRecord> records = new ArrayList<>();
                while (rs.next()) {
                    records.add(mapRow(rs));
                }
                return records;
            }
        } catch (Exception e) {
            log.error("Failed to list issuance records", e);
            return List.of();
        }
    }

    @Override
    public int count() {
        String sql = "SELECT count(*) FROM issuance_records";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            return rs.next() ? rs.getInt(1) : 0;
        } catch (Exception e) {
            log.error("Failed to count issuance records", e);
            return 0;
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
                rs.getString("recipient_email"),
                rs.getTimestamp("created_at"),
                rs.getTimestamp("updated_at")
        );
    }
}
