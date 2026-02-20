package com.fikua.lab.db;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fikua.core.profile.ProfileConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Repository for test profiles stored in PostgreSQL.
 * Full CRUD operations for admin management.
 */
public class ProfileRepository {

    private static final Logger log = LoggerFactory.getLogger(ProfileRepository.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final DatabaseManager db;

    public ProfileRepository(DatabaseManager db) {
        this.db = db;
    }

    public record ProfileRow(
            String id,
            String name,
            String role,
            ProfileConfig config,
            boolean isActive,
            Timestamp createdAt,
            Timestamp updatedAt
    ) {}

    public List<ProfileRow> findAll() {
        var profiles = new ArrayList<ProfileRow>();
        String sql = "SELECT id, name, role, config, is_active, created_at, updated_at FROM profiles ORDER BY created_at";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                profiles.add(mapRow(rs));
            }
        } catch (Exception e) {
            log.error("Failed to list profiles", e);
        }
        return profiles;
    }

    public ProfileRow findById(String id) {
        String sql = "SELECT id, name, role, config, is_active, created_at, updated_at FROM profiles WHERE id = ?";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setObject(1, UUID.fromString(id));
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? mapRow(rs) : null;
            }
        } catch (Exception e) {
            log.error("Failed to find profile {}", id, e);
            return null;
        }
    }

    public ProfileRow findActive() {
        String sql = "SELECT id, name, role, config, is_active, created_at, updated_at FROM profiles WHERE is_active = true LIMIT 1";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            return rs.next() ? mapRow(rs) : null;
        } catch (Exception e) {
            log.error("Failed to find active profile", e);
            return null;
        }
    }

    public ProfileRow create(String name, String role, ProfileConfig config) {
        String id = UUID.randomUUID().toString();
        String sql = "INSERT INTO profiles (id, name, role, config) VALUES (?::uuid, ?, ?, ?::jsonb)";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, id);
            ps.setString(2, name);
            ps.setString(3, role);
            ps.setString(4, MAPPER.writeValueAsString(config));
            ps.executeUpdate();
            return findById(id);
        } catch (Exception e) {
            log.error("Failed to create profile", e);
            throw new RuntimeException("Failed to create profile", e);
        }
    }

    public ProfileRow update(String id, String name, String role, ProfileConfig config) {
        String sql = "UPDATE profiles SET name = ?, role = ?, config = ?::jsonb, updated_at = now() WHERE id = ?::uuid";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, name);
            ps.setString(2, role);
            ps.setString(3, MAPPER.writeValueAsString(config));
            ps.setString(4, id);
            ps.executeUpdate();
            return findById(id);
        } catch (Exception e) {
            log.error("Failed to update profile {}", id, e);
            throw new RuntimeException("Failed to update profile", e);
        }
    }

    public boolean delete(String id) {
        String sql = "DELETE FROM profiles WHERE id = ?::uuid";
        try (Connection conn = db.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, id);
            return ps.executeUpdate() > 0;
        } catch (Exception e) {
            log.error("Failed to delete profile {}", id, e);
            return false;
        }
    }

    public void activate(String id) {
        String deactivate = "UPDATE profiles SET is_active = false WHERE is_active = true";
        String activate = "UPDATE profiles SET is_active = true, updated_at = now() WHERE id = ?::uuid";
        try (Connection conn = db.getConnection()) {
            conn.setAutoCommit(false);
            try (PreparedStatement ps1 = conn.prepareStatement(deactivate);
                 PreparedStatement ps2 = conn.prepareStatement(activate)) {
                ps1.executeUpdate();
                ps2.setString(1, id);
                ps2.executeUpdate();
                conn.commit();
            } catch (Exception e) {
                conn.rollback();
                throw e;
            }
        } catch (Exception e) {
            log.error("Failed to activate profile {}", id, e);
            throw new RuntimeException("Failed to activate profile", e);
        }
    }

    private ProfileRow mapRow(ResultSet rs) throws Exception {
        return new ProfileRow(
                rs.getString("id"),
                rs.getString("name"),
                rs.getString("role"),
                MAPPER.readValue(rs.getString("config"), ProfileConfig.class),
                rs.getBoolean("is_active"),
                rs.getTimestamp("created_at"),
                rs.getTimestamp("updated_at")
        );
    }
}
