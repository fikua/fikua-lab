package com.fikua.server.db;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.util.UUID;

/**
 * Repository for issuance records stored in PostgreSQL.
 * Uses JSONB credential_data for extensibility across credential types.
 */
public class IssuanceRecordRepository {

    private static final Logger log = LoggerFactory.getLogger(IssuanceRecordRepository.class);
    private final DatabaseManager db;

    public IssuanceRecordRepository(DatabaseManager db) {
        this.db = db;
    }

    public record IssuanceRecordRow(
            String id,
            String credentialType,
            String credentialData,
            String sourceType,
            String sourceRef,
            String status,
            String preAuthCode,
            String offerId,
            Timestamp createdAt,
            Timestamp updatedAt
    ) {}

    /** Create a new issuance record with abstract credential data. */
    public IssuanceRecordRow create(String credentialType, String credentialData,
                                     String sourceType, String sourceRef) {
        String id = UUID.randomUUID().toString();
        String sql = """
                INSERT INTO issuance_records (id, credential_type, credential_data, source_type, source_ref)
                VALUES (?::uuid, ?, ?::jsonb, ?, ?)
                """;
        try (Connection conn = db.getConnection();
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

    /** Find an issuance record by ID. */
    public IssuanceRecordRow findById(String id) {
        String sql = """
                SELECT id, credential_type, credential_data, source_type, source_ref,
                       status, pre_auth_code, offer_id, created_at, updated_at
                FROM issuance_records WHERE id = ?::uuid
                """;
        try (Connection conn = db.getConnection();
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

    /** Update issuance record status. */
    public void updateStatus(String id, String status) {
        String sql = "UPDATE issuance_records SET status = ?, updated_at = now() WHERE id = ?::uuid";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, status);
            ps.setString(2, id);
            ps.executeUpdate();
        } catch (Exception e) {
            log.error("Failed to update status for issuance record {}", id, e);
        }
    }

    /** Link a pre-auth code to the issuance record. */
    public void updatePreAuthCode(String id, String preAuthCode) {
        String sql = "UPDATE issuance_records SET pre_auth_code = ?, updated_at = now() WHERE id = ?::uuid";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, preAuthCode);
            ps.setString(2, id);
            ps.executeUpdate();
        } catch (Exception e) {
            log.error("Failed to update pre_auth_code for issuance record {}", id, e);
        }
    }

    /** Link a credential offer ID to the issuance record. */
    public void updateOfferId(String id, String offerId) {
        String sql = "UPDATE issuance_records SET offer_id = ?, updated_at = now() WHERE id = ?::uuid";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, offerId);
            ps.setString(2, id);
            ps.executeUpdate();
        } catch (Exception e) {
            log.error("Failed to update offer_id for issuance record {}", id, e);
        }
    }

    private IssuanceRecordRow mapRow(ResultSet rs) throws SQLException {
        return new IssuanceRecordRow(
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
