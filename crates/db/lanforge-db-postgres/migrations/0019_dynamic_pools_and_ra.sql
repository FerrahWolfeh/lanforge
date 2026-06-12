-- Migration 19: Add tables for dynamic DHCP pools and Router Advertisement (RA) options

-- 1. Create schema for RA
CREATE SCHEMA IF NOT EXISTS ra;

-- 2. DHCPv4 Pools
CREATE TABLE dhcp.v4_pools (
    id SERIAL PRIMARY KEY,
    range_start INET NOT NULL,
    range_end INET NOT NULL,
    lease_time INT NOT NULL
);

-- 3. DHCPv6 Pools (can store suffixes as text or full addresses/CIDR)
CREATE TABLE dhcp.v6_pools (
    id SERIAL PRIMARY KEY,
    range_start TEXT,
    range_end TEXT,
    address TEXT,
    lease_time INT NOT NULL
);

-- 4. RA Prefixes
CREATE TABLE ra.prefixes (
    id SERIAL PRIMARY KEY,
    source TEXT NOT NULL,
    address INET,
    prefix_len SMALLINT NOT NULL DEFAULT 64,
    on_link BOOLEAN NOT NULL DEFAULT true,
    autonomous BOOLEAN NOT NULL DEFAULT true,
    preferred_lifetime INT,
    valid_lifetime INT
);

-- 5. RA RDNSS (DNS Server Announcements)
CREATE TABLE ra.rdnss (
    id SERIAL PRIMARY KEY,
    lifetime INT
);

CREATE TABLE ra.rdnss_servers (
    id SERIAL PRIMARY KEY,
    rdnss_id INT NOT NULL REFERENCES ra.rdnss(id) ON DELETE CASCADE,
    address INET NOT NULL
);

CREATE INDEX idx_rdnss_servers_rdnss_id ON ra.rdnss_servers(rdnss_id);

-- 6. RA DNSSL (DNS Search List Announcements)
CREATE TABLE ra.dnssl (
    id SERIAL PRIMARY KEY,
    lifetime INT
);

CREATE TABLE ra.dnssl_domains (
    id SERIAL PRIMARY KEY,
    dnssl_id INT NOT NULL REFERENCES ra.dnssl(id) ON DELETE CASCADE,
    domain TEXT NOT NULL
);

CREATE INDEX idx_dnssl_domains_dnssl_id ON ra.dnssl_domains(dnssl_id);
