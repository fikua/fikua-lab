package com.fikua.issuer.app.port;

import java.sql.Timestamp;

/**
 * Port for persistent issuance records.
 * Tracks credential issuance lifecycle from trigger to issued.
 */
public interface IssuanceStore {

    /** Issuance record data. */
    record IssuanceRecord(
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

    IssuanceRecord create(String credentialType, String credentialData, String sourceType, String sourceRef);
    IssuanceRecord findById(String id);
    void updateStatus(String id, String status);
    void updatePreAuthCode(String id, String preAuthCode);
    void updateOfferId(String id, String offerId);
}
