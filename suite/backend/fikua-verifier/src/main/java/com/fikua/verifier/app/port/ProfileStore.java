package com.fikua.verifier.app.port;

import com.fikua.core.profile.ProfileConfig;

/**
 * Port for accessing the active verifier profile configuration.
 * Each service defines its own port — no shared port module.
 */
public interface ProfileStore {

    record ActiveProfile(String id, ProfileConfig config) {}

    ActiveProfile findActive();
}
