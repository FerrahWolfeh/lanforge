-- Migrate static_devices v6_suffix from TEXT to INET
ALTER TABLE static_devices ALTER COLUMN v6_suffix TYPE INET USING NULLIF(v6_suffix, '')::INET;
