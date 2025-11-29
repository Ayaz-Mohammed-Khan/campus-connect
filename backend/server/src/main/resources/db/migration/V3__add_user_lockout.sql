-- Phase 1 Security: Account Lockout
-- Adds columns to track failed login attempts and lockout duration
ALTER TABLE users
ADD COLUMN failed_attempts INT NOT NULL DEFAULT 0,
ADD COLUMN lockout_end TIMESTAMPTZ;