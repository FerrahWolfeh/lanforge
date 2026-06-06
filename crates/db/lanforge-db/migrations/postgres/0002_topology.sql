-- Add topology columns to devices table
ALTER TABLE devices ADD COLUMN parent_mac TEXT;
ALTER TABLE devices ADD COLUMN parent_port TEXT;
ALTER TABLE devices ADD COLUMN local_ifindex INTEGER DEFAULT 0;
ALTER TABLE devices ADD COLUMN topo_updated BIGINT DEFAULT 0;
