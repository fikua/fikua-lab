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
            String txCode,
            Timestamp createdAt,
            Timestamp updatedAt
    ) {}

    IssuanceRecord create(String credentialType, String credentialData, String sourceType, String sourceRef);
    IssuanceRecord findById(String id);
    List<IssuanceRecord> findAll(int offset, int limit, String sortField, String sortOrder);
    int count();
    void updateStatus(String id, String status);
    void updatePreAuthCode(String id, String preAuthCode);
    void updateOfferId(String id, String offerId);
    void updateRecipientEmail(String id, String recipientEmail);
    void updateTxCode(String id, String txCode);
    /** Atomically consume the tx_code: returns it and sets it to null. Returns null if already consumed. */
    String consumeTxCode(String offerId);
    IssuanceRecord findByOfferId(String offerId);
}
