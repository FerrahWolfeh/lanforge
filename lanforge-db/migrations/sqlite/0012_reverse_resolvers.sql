-- Create dns_reverse_resolvers table for SQLite
CREATE TABLE IF NOT EXISTS dns_reverse_resolvers (
    subnet TEXT PRIMARY KEY,
    resolver_target TEXT NOT NULL
);

-- Seed default rule for Tailscale (100.64.0.0/10 -> udp://100.100.100.100:53)
INSERT INTO dns_reverse_resolvers (subnet, resolver_target)
VALUES ('100.64.0.0/10', 'udp://100.100.100.100:53')
ON CONFLICT(subnet) DO NOTHING;
