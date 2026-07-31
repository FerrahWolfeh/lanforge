-- Migration 22: User Authentication and Management (PostgreSQL)
CREATE SCHEMA IF NOT EXISTS auth;
DO $$ BEGIN IF NOT EXISTS (
    SELECT 1
    FROM pg_type
    WHERE typname = 'user_role_t'
        AND typnamespace = 'auth'::regnamespace
) THEN CREATE TYPE auth.user_role_t AS ENUM ('admin', 'operator', 'viewer');
END IF;
END $$;
CREATE TABLE IF NOT EXISTS auth.users (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role auth.user_role_t NOT NULL DEFAULT 'admin'::auth.user_role_t,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_auth_users_username ON auth.users(username);