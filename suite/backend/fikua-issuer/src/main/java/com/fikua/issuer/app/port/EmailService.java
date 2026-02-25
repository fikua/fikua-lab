package com.fikua.issuer.app.port;

/**
 * Port for sending emails.
 * Implementations: ResendEmailService (production), NoOpEmailService (dev/test).
 */
public interface EmailService {

    /** Send a credential invitation email with a link to the wallet. */
    void sendCredentialInvitation(String recipientEmail, String recipientName, String invitationLink);

    /** Send a transaction code email for credential claim verification. */
    void sendTxCode(String recipientEmail, String recipientName, String txCode);
}
