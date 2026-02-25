package com.fikua.verifier.infra;

import com.fikua.verifier.app.port.SessionStore;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of the verification session store.
 * Uses ConcurrentHashMap for thread-safe access.
 */
public class InMemorySessionStore implements SessionStore {

    private final Map<String, VerificationSession> sessionsById = new ConcurrentHashMap<>();
    private final Map<String, VerificationSession> sessionsByState = new ConcurrentHashMap<>();

    @Override
    public VerificationSession store(VerificationSession session) {
        sessionsById.put(session.sessionId(), session);
        sessionsByState.put(session.state(), session);
        return session;
    }

    @Override
    public VerificationSession findByState(String state) {
        return sessionsByState.get(state);
    }

    @Override
    public VerificationSession findById(String sessionId) {
        return sessionsById.get(sessionId);
    }

    @Override
    public void updateStatus(String sessionId, String status) {
        sessionsById.computeIfPresent(sessionId, (id, existing) -> {
            VerificationSession updated = new VerificationSession(
                    existing.sessionId(), existing.state(), existing.nonce(),
                    existing.dcqlQueryJson(), existing.responseMode(),
                    existing.clientId(), existing.responseUri(), existing.requestJwt(),
                    status, existing.vpToken(), existing.verifiedClaimsJson(), existing.error()
            );
            sessionsByState.put(existing.state(), updated);
            return updated;
        });
    }

    @Override
    public void updateResult(String sessionId, String status, String vpToken,
                             String verifiedClaimsJson, String error) {
        sessionsById.computeIfPresent(sessionId, (id, existing) -> {
            VerificationSession updated = new VerificationSession(
                    existing.sessionId(), existing.state(), existing.nonce(),
                    existing.dcqlQueryJson(), existing.responseMode(),
                    existing.clientId(), existing.responseUri(), existing.requestJwt(),
                    status, vpToken, verifiedClaimsJson, error
            );
            sessionsByState.put(existing.state(), updated);
            return updated;
        });
    }

    @Override
    public void clear() {
        sessionsById.clear();
        sessionsByState.clear();
    }
}
