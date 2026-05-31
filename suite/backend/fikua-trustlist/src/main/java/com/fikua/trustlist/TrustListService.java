package com.fikua.trustlist;

import com.fikua.trustlist.infra.http.TrustListController;
import io.javalin.Javalin;

/**
 * Trusted List service — a mock of the EU List of Trusted Lists (LOTL).
 *
 * Serves, centrally to the wallet / verifier / issuer:
 *   - Trusted Issuers List         (anchors for credential signers)
 *   - Trusted Verifiers List       (RP anchors + ARF Registration: allowed claims)
 *   - Trusted Wallet Providers List(anchors for Wallet Attestations)
 *   - Trusted Schemas List         (recognized VCTs)
 *   - LOTL index
 *
 * v0: static JSON resources. Later versions can sign the lists, expose ETSI
 * TS 119 612 documents, and add an admin API to register entities.
 */
public class TrustListService {

    /** Start the trust-list service, registering routes on the given Javalin app. */
    public void start(Javalin app) {
        new TrustListController().register(app);
    }
}
