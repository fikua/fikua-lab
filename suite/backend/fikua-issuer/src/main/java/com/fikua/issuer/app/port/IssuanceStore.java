package com.fikua.issuer.app.port;

import java.sql.Timestamp;
import java.util.List;

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
            String recipientEmail,
            Timestamp createdAt,
            Timestamp updatedAt
    ) {}

    IssuanceRecord create(String credentialType, String credentialData, String sourceType, String sourceRef);
    IssuanceRecord createDraft(String credentialType, String credentialData,
                               String sourceType, String sourceRef, String recipientEmail);
    IssuanceRecord findById(String id);
    IssuanceRecord findDraftByEmail(String email);
    List<IssuanceRecord> findAll(int offset, int limit, String sortField, String sortOrder);
    int count();
    void updateStatus(String id, String status);
    void updatePreAuthCode(String id, String preAuthCode);
    void updateOfferId(String id, String offerId);
}
