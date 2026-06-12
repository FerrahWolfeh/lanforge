-- Phase 2: Schema Type Improvements (Postgres)

-- 1. MAC address improvements
-- We change TEXT mac columns to MACADDR for native validation and storage efficiency.
-- This requires dropping and recreating foreign key constraints.

ALTER TABLE v4_leases DROP CONSTRAINT IF EXISTS v4_leases_mac_fkey;
ALTER TABLE v6_leases DROP CONSTRAINT IF EXISTS v6_leases_mac_fkey;
ALTER TABLE v6_prefixes DROP CONSTRAINT IF EXISTS v6_prefixes_mac_fkey;
ALTER TABLE slaac_addrs DROP CONSTRAINT IF EXISTS slaac_addrs_mac_fkey;
ALTER TABLE seen_v4 DROP CONSTRAINT IF EXISTS seen_v4_mac_fkey;

ALTER TABLE devices ALTER COLUMN mac TYPE MACADDR USING mac::MACADDR;
ALTER TABLE v4_leases ALTER COLUMN mac TYPE MACADDR USING mac::MACADDR;
ALTER TABLE v6_leases ALTER COLUMN mac TYPE MACADDR USING mac::MACADDR;
ALTER TABLE v6_prefixes ALTER COLUMN mac TYPE MACADDR USING mac::MACADDR;
ALTER TABLE slaac_addrs ALTER COLUMN mac TYPE MACADDR USING mac::MACADDR;
ALTER TABLE seen_v4 ALTER COLUMN mac TYPE MACADDR USING mac::MACADDR;
ALTER TABLE lease_history ALTER COLUMN mac TYPE MACADDR USING mac::MACADDR;

ALTER TABLE v4_leases ADD CONSTRAINT v4_leases_mac_fkey FOREIGN KEY (mac) REFERENCES devices(mac) ON DELETE CASCADE;
ALTER TABLE v6_leases ADD CONSTRAINT v6_leases_mac_fkey FOREIGN KEY (mac) REFERENCES devices(mac) ON DELETE CASCADE;
ALTER TABLE v6_prefixes ADD CONSTRAINT v6_prefixes_mac_fkey FOREIGN KEY (mac) REFERENCES devices(mac) ON DELETE CASCADE;
ALTER TABLE slaac_addrs ADD CONSTRAINT slaac_addrs_mac_fkey FOREIGN KEY (mac) REFERENCES devices(mac) ON DELETE CASCADE;
ALTER TABLE seen_v4 ADD CONSTRAINT seen_v4_mac_fkey FOREIGN KEY (mac) REFERENCES devices(mac) ON DELETE CASCADE;

-- 2. IP address improvements
-- Using INET for IP columns provides native subnet operators and validation.

ALTER TABLE v4_leases ALTER COLUMN ip TYPE INET USING ip::INET;
ALTER TABLE v6_leases ALTER COLUMN ip TYPE INET USING ip::INET;
ALTER TABLE slaac_addrs ALTER COLUMN ip TYPE INET USING ip::INET;
ALTER TABLE seen_v4 ALTER COLUMN ip TYPE INET USING ip::INET;
ALTER TABLE lease_history ALTER COLUMN ip TYPE INET USING ip::INET;

-- 3. IPv6 Prefix improvements
-- Merge prefix (TEXT) and len (INT) into a single CIDR column.

ALTER TABLE v6_prefixes ADD COLUMN cidr CIDR;
UPDATE v6_prefixes SET cidr = (prefix || '/' || len)::CIDR;
ALTER TABLE v6_prefixes DROP COLUMN prefix;
ALTER TABLE v6_prefixes DROP COLUMN len;
ALTER TABLE v6_prefixes ALTER COLUMN cidr SET NOT NULL;

-- 4. DNS Allowlist validation
-- Basic domain character validation.

ALTER TABLE dns_allowlist ADD CONSTRAINT dns_allowlist_domain_check CHECK (domain ~ '^[a-z0-9.-]+$');
