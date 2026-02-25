package com.fikua.issuer.infra;

import com.fikua.issuer.app.port.EmailService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * No-op EmailService for dev/test — logs email content instead of sending.
 * Used when FIKUA_RESEND_API_KEY is not configured.
 */
public class NoOpEmailService implements EmailService {

    private static final Logger log = LoggerFactory.getLogger(NoOpEmailService.class);

    @Override
    public void sendCredentialInvitation(String recipientEmail, String recipientName, String invitationLink) {
        log.info("[NoOp Email] Credential invitation to {} ({}): {}", recipientEmail, recipientName, invitationLink);
    }

    @Override
    public void sendTxCode(String recipientEmail, String recipientName, String txCode) {
        log.info("[NoOp Email] TX code to {} ({}): {}", recipientEmail, recipientName, txCode);
    }
}
