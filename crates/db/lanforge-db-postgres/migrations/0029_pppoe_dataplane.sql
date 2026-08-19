-- Migration 29: Add dataplane selection column to pppoe.config
ALTER TABLE pppoe.config
ADD COLUMN IF NOT EXISTS dataplane VARCHAR(16) NOT NULL DEFAULT 'kernel';
