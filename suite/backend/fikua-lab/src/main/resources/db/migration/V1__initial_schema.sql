-- Fikua Lab: initial database schema

CREATE TABLE IF NOT EXISTS profiles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) NOT NULL,
    role        VARCHAR(50) NOT NULL,
    config      JSONB NOT NULL DEFAULT '{}',
    is_active   BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- At most one active profile per role. (Originally this was a GLOBAL unique
-- index on (is_active); V7 replaces it with the per-role index below. Because
-- migrations re-run on every boot, V1 must declare the per-role form too —
-- otherwise, once V7 has dropped the old global index, a re-run of the old V1
-- DDL would try to recreate a global unique index over data that legitimately
-- has multiple active profiles (one per role) and fail.)
CREATE UNIQUE INDEX IF NOT EXISTS idx_profiles_active_per_role
    ON profiles (role, is_active) WHERE is_active = true;

-- Session audit log for debugging conformance test runs
CREATE TABLE IF NOT EXISTS session_log (
    id          BIGSERIAL PRIMARY KEY,
    session_id  VARCHAR(255) NOT NULL,
    profile_id  UUID REFERENCES profiles(id),
    event_type  VARCHAR(100) NOT NULL,
    event_data  JSONB,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_session_log_session ON session_log(session_id);
CREATE INDEX IF NOT EXISTS idx_session_log_created ON session_log(created_at);
