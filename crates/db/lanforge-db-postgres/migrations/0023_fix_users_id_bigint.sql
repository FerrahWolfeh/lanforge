-- Migration 23: Upgrade auth.users id column from INT to BIGINT

ALTER TABLE auth.users ALTER COLUMN id TYPE BIGINT;
