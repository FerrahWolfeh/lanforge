-- Migration 21: Add nftables performance tuning columns to pppoe.config
ALTER TABLE pppoe.config
    ADD COLUMN IF NOT EXISTS nft_enabled BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS nft_table_name TEXT NOT NULL DEFAULT 'lanforge',
    ADD COLUMN IF NOT EXISTS nft_flow_offload BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS nft_mss_clamping BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS nft_bypass_dns BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS nft_bypass_vowifi BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS nft_custom_rules_file TEXT;
