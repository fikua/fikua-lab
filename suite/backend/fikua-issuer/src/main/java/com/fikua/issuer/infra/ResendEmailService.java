package com.fikua.issuer.infra;

import com.fikua.issuer.app.port.EmailService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * EmailService implementation using Resend HTTP API.
 * Sends real emails via POST https://api.resend.com/emails.
 */
public class ResendEmailService implements EmailService {

    private static final Logger log = LoggerFactory.getLogger(ResendEmailService.class);
    private static final String RESEND_API_URL = "https://api.resend.com/emails";

    private final HttpClient httpClient;
    private final String apiKey;
    private final String fromEmail;

    public ResendEmailService(String apiKey, String fromEmail) {
        this.apiKey = apiKey;
        this.fromEmail = fromEmail;
        this.httpClient = HttpClient.newHttpClient();
    }

    @Override
    public void sendCredentialInvitation(String recipientEmail, String recipientName, String invitationLink) {
        String subject = "Your Student ID credential is ready";
        String html = """
                <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 480px; margin: 0 auto; padding: 32px;">
                  <h2 style="color: #12107c; margin-bottom: 8px;">Fikua Lab</h2>
                  <p>Hello <strong>%s</strong>,</p>
                  <p>A <strong>Student ID</strong> credential has been issued for you. Click the button below to claim it in your wallet:</p>
                  <div style="text-align: center; margin: 32px 0;">
                    <a href="%s" style="background: #12107c; color: #fff; padding: 14px 32px; border-radius: 8px; text-decoration: none; font-weight: 600;">Open Wallet</a>
                  </div>
                  <p style="color: #666; font-size: 13px;">If the button doesn't work, copy this link:<br>%s</p>
                  <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;">
                  <p style="color: #999; font-size: 12px;">Fikua Lab — EUDI Wallet Testing Platform</p>
                </div>
                """.formatted(escapeHtml(recipientName), invitationLink, invitationLink);
        sendEmail(recipientEmail, subject, html);
    }

    @Override
    public void sendOtp(String recipientEmail, String otp) {
        String subject = "Your verification code: " + otp;
        String html = """
                <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 480px; margin: 0 auto; padding: 32px;">
                  <h2 style="color: #12107c; margin-bottom: 8px;">Fikua Lab</h2>
                  <p>Your verification code is:</p>
                  <div style="text-align: center; margin: 24px 0;">
                    <span style="font-size: 36px; font-weight: 700; letter-spacing: 8px; color: #12107c; font-family: monospace;">%s</span>
                  </div>
                  <p style="color: #666; font-size: 13px;">This code expires in 5 minutes. Do not share it with anyone.</p>
                  <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;">
                  <p style="color: #999; font-size: 12px;">Fikua Lab — EUDI Wallet Testing Platform</p>
                </div>
                """.formatted(otp);
        sendEmail(recipientEmail, subject, html);
    }

    private void sendEmail(String to, String subject, String html) {
        String jsonBody = """
                {"from":"%s","to":["%s"],"subject":"%s","html":"%s"}"""
                .formatted(
                        escapeJson(fromEmail),
                        escapeJson(to),
                        escapeJson(subject),
                        escapeJson(html)
                );

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(RESEND_API_URL))
                .header("Authorization", "Bearer " + apiKey)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .build();

        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                log.info("Email sent to {} — subject: {}", to, subject);
            } else {
                log.error("Resend API error (HTTP {}): {}", response.statusCode(), response.body());
            }
        } catch (Exception e) {
            log.error("Failed to send email to {}", to, e);
        }
    }

    private static String escapeJson(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\")
                     .replace("\"", "\\\"")
                     .replace("\n", "\\n")
                     .replace("\r", "\\r")
                     .replace("\t", "\\t");
    }

    private static String escapeHtml(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;")
                     .replace("<", "&lt;")
                     .replace(">", "&gt;")
                     .replace("\"", "&quot;");
    }
}
