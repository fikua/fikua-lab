package com.fikua.verifier.app;

import com.fikua.core.crypto.EcKeyManager;
import com.fikua.core.crypto.ResponseEncryptionKey;
import com.fikua.core.crypto.SigningKey;
import com.fikua.core.mdoc.MdocBuilder;
import com.fikua.core.mdoc.SessionTranscript;
import com.fikua.core.profile.ProfilePresets;
import com.fikua.verifier.app.port.ProfileStore;
import com.fikua.verifier.app.port.SessionStore.VerificationSession;
import com.fikua.verifier.infra.InMemorySessionStore;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.upokecenter.cbor.CBORObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end mso_mdoc verification through the verifier's encrypted-response
 * path: createSession advertises mdoc formats, and an encrypted DeviceResponse
 * with a correct SessionTranscript verifies (while a wrong transcript is rejected).
 */
class MdocEncryptedResponseTest {

    private static final String DOC_TYPE = "eu.europa.ec.eudi.pid.1";
    private static final String BASE_URL = "https://verifier.example.test";

    private static final ProfileStore MDOC_PROFILE = () ->
            new ProfileStore.ActiveProfile("haip-mdoc", ProfilePresets.haipMdocVerifier());
    private static final ProfileStore SD_JWT_PROFILE = () ->
            new ProfileStore.ActiveProfile("haip", ProfilePresets.haipVerifier());

    private VerificationService newService(Path certsDir, ResponseEncryptionKey encKey) {
        return newService(certsDir, encKey, MDOC_PROFILE);
    }

    private VerificationService newService(Path certsDir, ResponseEncryptionKey encKey, ProfileStore profile) {
        SigningKey key = com.fikua.verifier.infra.PemKeyLoader.loadOrGenerate(certsDir.toString());
        return new VerificationService(
                key, encKey, new InMemorySessionStore(), profile, BASE_URL);
    }

    /** A self-signed P-256 issuer key (so the x5chain anchors on itself with no pinned anchor). */
    private static EcKeyManager selfSignedIssuer() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();
        X500Name subject = new X500Name("CN=Test mdoc Issuer, O=Fikua Lab Test, C=ES");
        Date notBefore = new Date(System.currentTimeMillis() - 60_000);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(kp.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(
                new JcaX509v3CertificateBuilder(subject, BigInteger.valueOf(1),
                        notBefore, notAfter, subject, kp.getPublic()).build(signer));
        return EcKeyManager.fromPem(kp.getPrivate(), cert);
    }

    /** Build a base64url DeviceResponse with a deviceSignature over the given transcript inputs. */
    private static String buildDeviceResponse(EcKeyManager issuer, EcKeyManager deviceKey,
                                              String clientId, String nonce, byte[] thumbprint,
                                              String responseUri) {
        CBORObject issuerSigned = CBORObject.DecodeFromBytes(new MdocBuilder(issuer)
                .docType(DOC_TYPE)
                .namespace(DOC_TYPE)
                .element("given_name", "Jan")
                .element("family_name", "Kowalski")
                .deviceKey(deviceKey.publicKey())
                .x5cChain(issuer.x5cChain())
                .build().cborBytes());

        byte[] deviceNameSpacesBytes = CBORObject.FromObject(CBORObject.NewMap().EncodeToBytes())
                .WithTag(24).EncodeToBytes();

        byte[] st = SessionTranscript.openid4vpHandover(clientId, nonce, thumbprint, responseUri);
        byte[] deviceAuthBytes = SessionTranscript.deviceAuthenticationBytes(
                st, DOC_TYPE, deviceNameSpacesBytes);

        CBORObject protectedMap = CBORObject.NewMap();
        protectedMap.set(CBORObject.FromObject(1), CBORObject.FromObject(-7));
        byte[] protectedBytes = protectedMap.EncodeToBytes();
        CBORObject sigStructure = CBORObject.NewArray();
        sigStructure.Add("Signature1");
        sigStructure.Add(protectedBytes);
        sigStructure.Add(new byte[0]);
        sigStructure.Add(deviceAuthBytes);
        byte[] sig = deviceKey.signRawBytes(sigStructure.EncodeToBytes());

        CBORObject deviceSignature = CBORObject.NewArray();
        deviceSignature.Add(CBORObject.FromObject(protectedBytes));
        deviceSignature.Add(CBORObject.NewMap());
        deviceSignature.Add(CBORObject.Null);
        deviceSignature.Add(CBORObject.FromObject(sig));

        CBORObject deviceAuth = CBORObject.NewMap();
        deviceAuth.set(CBORObject.FromObject("deviceSignature"), deviceSignature);
        CBORObject deviceSigned = CBORObject.NewMap();
        deviceSigned.set(CBORObject.FromObject("nameSpaces"),
                CBORObject.DecodeFromBytes(deviceNameSpacesBytes));
        deviceSigned.set(CBORObject.FromObject("deviceAuth"), deviceAuth);

        CBORObject document = CBORObject.NewMap();
        document.set(CBORObject.FromObject("docType"), CBORObject.FromObject(DOC_TYPE));
        document.set(CBORObject.FromObject("issuerSigned"), issuerSigned);
        document.set(CBORObject.FromObject("deviceSigned"), deviceSigned);
        CBORObject documents = CBORObject.NewArray();
        documents.Add(document);
        CBORObject deviceResponse = CBORObject.NewMap();
        deviceResponse.set(CBORObject.FromObject("version"), CBORObject.FromObject("1.0"));
        deviceResponse.set(CBORObject.FromObject("documents"), documents);
        deviceResponse.set(CBORObject.FromObject("status"), CBORObject.FromObject(0));

        return Base64.getUrlEncoder().withoutPadding().encodeToString(deviceResponse.EncodeToBytes());
    }

    private static String encrypt(ResponseEncryptionKey encKey, String vpToken, String state) throws Exception {
        ECKey publicJwk = ECKey.parse(new com.fasterxml.jackson.databind.ObjectMapper()
                .writeValueAsString(encKey.publicJwk()));
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("vp_token", vpToken)
                .claim("state", state)
                .build();
        EncryptedJWT jwe = new EncryptedJWT(
                new JWEHeader(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128GCM), claims);
        jwe.encrypt(new ECDHEncrypter(publicJwk));
        return jwe.serialize();
    }

    @Test
    void createSession_advertisesMsoMdocFormatAndDcql(@TempDir Path certsDir) throws Exception {
        VerificationService service = newService(certsDir, ResponseEncryptionKey.generate());
        VerificationSession session = service.createSession(DOC_TYPE, List.of("given_name", "family_name"));

        var jwt = com.nimbusds.jwt.SignedJWT.parse(session.requestJwt());
        var claimsSet = jwt.getJWTClaimsSet();

        @SuppressWarnings("unchecked")
        Map<String, Object> cm = (Map<String, Object>) claimsSet.getClaim("client_metadata");
        @SuppressWarnings("unchecked")
        Map<String, Object> formats = (Map<String, Object>) cm.get("vp_formats_supported");
        assertTrue(formats.containsKey("mso_mdoc"), "mdoc profile must advertise mso_mdoc");

        @SuppressWarnings("unchecked")
        Map<String, Object> dcql = (Map<String, Object>) claimsSet.getClaim("dcql_query");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> creds = (List<Map<String, Object>>) dcql.get("credentials");
        Map<String, Object> cred = creds.get(0);
        assertEquals("mso_mdoc", cred.get("format"));
        @SuppressWarnings("unchecked")
        Map<String, Object> meta = (Map<String, Object>) cred.get("meta");
        assertEquals(DOC_TYPE, meta.get("doctype_value"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> claims = (List<Map<String, Object>>) cred.get("claims");
        @SuppressWarnings("unchecked")
        List<String> path = (List<String>) claims.get(0).get("path");
        assertEquals(2, path.size(), "mdoc claim path is [namespace, element]");
        assertEquals(DOC_TYPE, path.get(0));
    }

    @Test
    void encryptedMdocResponse_happyPath(@TempDir Path certsDir) throws Exception {
        var encKey = ResponseEncryptionKey.generate();
        VerificationService service = newService(certsDir, encKey);
        VerificationSession session = service.createSession(DOC_TYPE, List.of("given_name", "family_name"));

        EcKeyManager issuer = selfSignedIssuer();
        EcKeyManager deviceKey = EcKeyManager.generate();
        String dr = buildDeviceResponse(issuer, deviceKey,
                session.clientId(), session.nonce(), encKey.jwkThumbprintSha256(), session.responseUri());

        var outcome = service.handleEncryptedResponse(encrypt(encKey, dr, session.state()));

        assertEquals("success", outcome.result().status(), "valid mdoc DeviceResponse must verify");
    }

    @Test
    void perSessionFormat_overridesSdJwtProfile(@TempDir Path certsDir) throws Exception {
        // Active profile is SD-JWT, but the session requests mso_mdoc explicitly.
        var encKey = ResponseEncryptionKey.generate();
        VerificationService service = newService(certsDir, encKey, SD_JWT_PROFILE);
        VerificationSession session =
                service.createSession(DOC_TYPE, List.of("given_name", "family_name"), "mso_mdoc");

        // The request must advertise mso_mdoc despite the SD-JWT profile.
        var jwt = com.nimbusds.jwt.SignedJWT.parse(session.requestJwt());
        @SuppressWarnings("unchecked")
        Map<String, Object> cm = (Map<String, Object>) jwt.getJWTClaimsSet().getClaim("client_metadata");
        @SuppressWarnings("unchecked")
        Map<String, Object> formats = (Map<String, Object>) cm.get("vp_formats_supported");
        assertTrue(formats.containsKey("mso_mdoc"), "per-session format must win over the profile");

        EcKeyManager issuer = selfSignedIssuer();
        EcKeyManager deviceKey = EcKeyManager.generate();
        String dr = buildDeviceResponse(issuer, deviceKey,
                session.clientId(), session.nonce(), encKey.jwkThumbprintSha256(), session.responseUri());

        var outcome = service.handleEncryptedResponse(encrypt(encKey, dr, session.state()));
        assertEquals("success", outcome.result().status(),
                "mdoc verification must run even when the active profile is SD-JWT");
    }

    @Test
    void encryptedMdocResponse_wrongTranscript_rejected(@TempDir Path certsDir) throws Exception {
        var encKey = ResponseEncryptionKey.generate();
        VerificationService service = newService(certsDir, encKey);
        VerificationSession session = service.createSession(DOC_TYPE, List.of("given_name"));

        EcKeyManager issuer = selfSignedIssuer();
        EcKeyManager deviceKey = EcKeyManager.generate();
        // deviceSignature built over the WRONG nonce.
        String dr = buildDeviceResponse(issuer, deviceKey,
                session.clientId(), "WRONG-NONCE", encKey.jwkThumbprintSha256(), session.responseUri());

        var outcome = service.handleEncryptedResponse(encrypt(encKey, dr, session.state()));

        assertEquals("error", outcome.result().status(), "wrong SessionTranscript must be rejected");
    }
}
