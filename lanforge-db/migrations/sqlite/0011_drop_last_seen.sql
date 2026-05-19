-- Drop last_seen column from devices and migrate old hostname_origin values to new enum mappings.
ALTER TABLE devices DROP COLUMN last_seen;

UPDATE devices SET hostname_origin = CASE hostname_origin
    WHEN 1 THEN 3  -- Mdns
    WHEN 2 THEN 0  -- Dhcp
    WHEN 3 THEN 1  -- Static
    ELSE 0         -- Fallback
END;
