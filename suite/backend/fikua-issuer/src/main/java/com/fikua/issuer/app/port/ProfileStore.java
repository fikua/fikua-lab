package com.fikua.issuer.app.port;

import com.fikua.core.profile.ProfileConfig;

/**
 * Port for accessing test profile configuration.
 * The issuer needs the active profile to determine flow behavior (pre-auth vs HAIP).
 */
public interface ProfileStore {

    /** Profile with its ID and config. */
    record ActiveProfile(String id, ProfileConfig config) {}

    /** Find the currently active profile, or null if none. */
    ActiveProfile findActive();
}
