package com.fikua.issuer;

import com.fikua.core.crypto.SigningKey;
import com.fikua.core.oauth2.DPoPValidator;
import com.fikua.issuer.app.IssuanceService;
import com.fikua.issuer.app.port.IssuanceStore;
import com.fikua.issuer.app.port.ProfileStore;
import com.fikua.issuer.app.port.SessionStore;
import com.fikua.issuer.infra.InMemorySessionStore;
import com.fikua.issuer.infra.JdbcIssuanceStore;
import com.fikua.issuer.infra.JdbcProfileStore;
import com.fikua.issuer.infra.PemKeyLoader;
import com.fikua.issuer.infra.http.IssuerController;
import io.javalin.Javalin;

import javax.sql.DataSource;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Issuer service entry point.
 * Wires infrastructure adapters, creates application service, registers HTTP routes.
 */
public class IssuerService {

    private IssuanceService issuanceService;

    /** Start the issuer service, registering routes on the given Javalin app. */
    public void start(Javalin app, DataSource dataSource, String baseUrl, String certsDir) {
        // Load signing key
        SigningKey key = PemKeyLoader.loadOrGenerate(certsDir);

        // Create infrastructure adapters
        SessionStore sessions = new InMemorySessionStore();
        IssuanceStore issuances = new JdbcIssuanceStore(dataSource);
        ProfileStore profiles = new JdbcProfileStore(dataSource);

        // DPoP validator with JTI replay protection
        Set<String> jtiSet = ConcurrentHashMap.newKeySet();
        DPoPValidator dpop = new DPoPValidator(jtiSet::add);

        // Create application service
        issuanceService = new IssuanceService(key, sessions, issuances, profiles, dpop, baseUrl);

        // Register HTTP controller
        new IssuerController(issuanceService, baseUrl).register(app);
    }

    /** Get the issuance service (for orchestrator-level operations like reset). */
    public IssuanceService issuanceService() {
        return issuanceService;
    }
}
