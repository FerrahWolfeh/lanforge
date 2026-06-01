--
-- PostgreSQL database dump
--

\restrict goOXHfVkL4cWZeRf1m2RK8urW1X6Zefio7bYkrJ6wlxYshi7Je40an6BeoiGb3r

-- Dumped from database version 17.10 (Debian 17.10-0+deb13u1)
-- Dumped by pg_dump version 17.10 (Debian 17.10-0+deb13u1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: auth; Type: SCHEMA; Schema: -; Owner: datcr
--

CREATE SCHEMA auth;


ALTER SCHEMA auth OWNER TO datcr;

--
-- Name: dhcp; Type: SCHEMA; Schema: -; Owner: datcr
--

CREATE SCHEMA dhcp;


ALTER SCHEMA dhcp OWNER TO datcr;

--
-- Name: dns; Type: SCHEMA; Schema: -; Owner: datcr
--

CREATE SCHEMA dns;


ALTER SCHEMA dns OWNER TO datcr;

--
-- Name: net; Type: SCHEMA; Schema: -; Owner: datcr
--

CREATE SCHEMA net;


ALTER SCHEMA net OWNER TO datcr;

--
-- Name: blocking_mode; Type: TYPE; Schema: dns; Owner: datcr
--

CREATE TYPE dns.blocking_mode AS ENUM (
    'nxdomain',
    'null_ip',
    'custom_ip',
    'refused'
);


ALTER TYPE dns.blocking_mode OWNER TO datcr;

--
-- Name: device_origin; Type: TYPE; Schema: public; Owner: datcr
--

CREATE TYPE public.device_origin AS ENUM (
    'static',
    'system',
    'dynamic'
);


ALTER TYPE public.device_origin OWNER TO datcr;

--
-- Name: hostname_origin_t; Type: TYPE; Schema: public; Owner: datcr
--

CREATE TYPE public.hostname_origin_t AS ENUM (
    'dhcp',
    'dns',
    'mdns',
    'ndp',
    'netbios',
    'static',
    'system',
    'user'
);


ALTER TYPE public.hostname_origin_t OWNER TO datcr;

--
-- Name: lease_action_t; Type: TYPE; Schema: public; Owner: datcr
--

CREATE TYPE public.lease_action_t AS ENUM (
    'granted',
    'renewed',
    'released',
    'expired',
    'declined',
    'purged'
);


ALTER TYPE public.lease_action_t OWNER TO datcr;

--
-- Name: lease_type_t; Type: TYPE; Schema: public; Owner: datcr
--

CREATE TYPE public.lease_type_t AS ENUM (
    'v4',
    'v6',
    'prefix'
);


ALTER TYPE public.lease_type_t OWNER TO datcr;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: api_tokens; Type: TABLE; Schema: auth; Owner: datcr
--

CREATE TABLE auth.api_tokens (
    id integer NOT NULL,
    token text NOT NULL,
    name text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_used timestamp with time zone,
    scopes text DEFAULT 'admin'::text NOT NULL,
    expires_at timestamp with time zone
);


ALTER TABLE auth.api_tokens OWNER TO datcr;

--
-- Name: api_tokens_new_id_seq; Type: SEQUENCE; Schema: auth; Owner: datcr
--

CREATE SEQUENCE auth.api_tokens_new_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE auth.api_tokens_new_id_seq OWNER TO datcr;

--
-- Name: api_tokens_new_id_seq; Type: SEQUENCE OWNED BY; Schema: auth; Owner: datcr
--

ALTER SEQUENCE auth.api_tokens_new_id_seq OWNED BY auth.api_tokens.id;


--
-- Name: lease_history; Type: TABLE; Schema: dhcp; Owner: datcr
--

CREATE TABLE dhcp.lease_history (
    id integer NOT NULL,
    mac macaddr NOT NULL,
    ip inet NOT NULL,
    lease_type public.lease_type_t NOT NULL,
    action public.lease_action_t NOT NULL,
    occurred_at timestamp with time zone NOT NULL
);


ALTER TABLE dhcp.lease_history OWNER TO datcr;

--
-- Name: lease_history_id_seq; Type: SEQUENCE; Schema: dhcp; Owner: datcr
--

CREATE SEQUENCE dhcp.lease_history_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE dhcp.lease_history_id_seq OWNER TO datcr;

--
-- Name: lease_history_id_seq; Type: SEQUENCE OWNED BY; Schema: dhcp; Owner: datcr
--

ALTER SEQUENCE dhcp.lease_history_id_seq OWNED BY dhcp.lease_history.id;


--
-- Name: static_devices; Type: TABLE; Schema: dhcp; Owner: datcr
--

CREATE TABLE dhcp.static_devices (
    mac macaddr NOT NULL,
    v4_static inet,
    v6_suffix inet,
    boot_file text
);


ALTER TABLE dhcp.static_devices OWNER TO datcr;

--
-- Name: v4_leases; Type: TABLE; Schema: dhcp; Owner: datcr
--

CREATE TABLE dhcp.v4_leases (
    mac macaddr NOT NULL,
    ip inet NOT NULL,
    expires timestamp with time zone NOT NULL
);


ALTER TABLE dhcp.v4_leases OWNER TO datcr;

--
-- Name: v6_leases; Type: TABLE; Schema: dhcp; Owner: datcr
--

CREATE TABLE dhcp.v6_leases (
    mac macaddr NOT NULL,
    iaid bigint NOT NULL,
    ip inet NOT NULL,
    expires timestamp with time zone NOT NULL
);


ALTER TABLE dhcp.v6_leases OWNER TO datcr;

--
-- Name: adblock_config; Type: TABLE; Schema: dns; Owner: datcr
--

CREATE TABLE dns.adblock_config (
    id boolean DEFAULT true NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    blocking_mode dns.blocking_mode DEFAULT 'nxdomain'::dns.blocking_mode NOT NULL,
    blocking_ip_v4 inet,
    blocking_ip_v6 inet,
    refresh_hours smallint DEFAULT 12 NOT NULL,
    refresh_at_night boolean DEFAULT false NOT NULL,
    extras jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT adblock_config_refresh_hours_check CHECK ((refresh_hours >= 0)),
    CONSTRAINT custom_ip_requires_v4 CHECK (((blocking_mode <> 'custom_ip'::dns.blocking_mode) OR (blocking_ip_v4 IS NOT NULL))),
    CONSTRAINT single_row CHECK (id)
);


ALTER TABLE dns.adblock_config OWNER TO datcr;

--
-- Name: adblock_urls; Type: TABLE; Schema: dns; Owner: datcr
--

CREATE TABLE dns.adblock_urls (
    id integer NOT NULL,
    url text NOT NULL,
    kind text DEFAULT 'block'::text NOT NULL
);


ALTER TABLE dns.adblock_urls OWNER TO datcr;

--
-- Name: allowlist; Type: TABLE; Schema: dns; Owner: datcr
--

CREATE TABLE dns.allowlist (
    id integer NOT NULL,
    domain text NOT NULL,
    CONSTRAINT dns_allowlist_domain_check CHECK ((domain ~ '^[a-z0-9.-]+$'::text))
);


ALTER TABLE dns.allowlist OWNER TO datcr;

--
-- Name: dns_adblock_urls_id_seq; Type: SEQUENCE; Schema: dns; Owner: datcr
--

CREATE SEQUENCE dns.dns_adblock_urls_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE dns.dns_adblock_urls_id_seq OWNER TO datcr;

--
-- Name: dns_adblock_urls_id_seq; Type: SEQUENCE OWNED BY; Schema: dns; Owner: datcr
--

ALTER SEQUENCE dns.dns_adblock_urls_id_seq OWNED BY dns.adblock_urls.id;


--
-- Name: dns_allowlist_id_seq; Type: SEQUENCE; Schema: dns; Owner: datcr
--

CREATE SEQUENCE dns.dns_allowlist_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE dns.dns_allowlist_id_seq OWNER TO datcr;

--
-- Name: dns_allowlist_id_seq; Type: SEQUENCE OWNED BY; Schema: dns; Owner: datcr
--

ALTER SEQUENCE dns.dns_allowlist_id_seq OWNED BY dns.allowlist.id;


--
-- Name: rewrites; Type: TABLE; Schema: dns; Owner: datcr
--

CREATE TABLE dns.rewrites (
    id integer NOT NULL,
    domain text NOT NULL,
    rtype text DEFAULT 'A'::text NOT NULL,
    answer text NOT NULL
);


ALTER TABLE dns.rewrites OWNER TO datcr;

--
-- Name: dns_rewrites_new_id_seq; Type: SEQUENCE; Schema: dns; Owner: datcr
--

CREATE SEQUENCE dns.dns_rewrites_new_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE dns.dns_rewrites_new_id_seq OWNER TO datcr;

--
-- Name: dns_rewrites_new_id_seq; Type: SEQUENCE OWNED BY; Schema: dns; Owner: datcr
--

ALTER SEQUENCE dns.dns_rewrites_new_id_seq OWNED BY dns.rewrites.id;


--
-- Name: upstreams; Type: TABLE; Schema: dns; Owner: datcr
--

CREATE TABLE dns.upstreams (
    id integer NOT NULL,
    addr text NOT NULL,
    protocol text DEFAULT 'udp'::text NOT NULL,
    domain text
);


ALTER TABLE dns.upstreams OWNER TO datcr;

--
-- Name: dns_upstreams_id_seq; Type: SEQUENCE; Schema: dns; Owner: datcr
--

CREATE SEQUENCE dns.dns_upstreams_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE dns.dns_upstreams_id_seq OWNER TO datcr;

--
-- Name: dns_upstreams_id_seq; Type: SEQUENCE OWNED BY; Schema: dns; Owner: datcr
--

ALTER SEQUENCE dns.dns_upstreams_id_seq OWNED BY dns.upstreams.id;


--
-- Name: reverse_resolvers; Type: TABLE; Schema: dns; Owner: datcr
--

CREATE TABLE dns.reverse_resolvers (
    subnet cidr NOT NULL,
    resolver_target text NOT NULL
);


ALTER TABLE dns.reverse_resolvers OWNER TO datcr;

--
-- Name: device_topology; Type: TABLE; Schema: net; Owner: datcr
--

CREATE TABLE net.device_topology (
    mac macaddr NOT NULL,
    parent_mac macaddr,
    parent_port text,
    local_ifindex integer DEFAULT 0 NOT NULL,
    topo_updated timestamp with time zone DEFAULT to_timestamp((0)::double precision) NOT NULL
);


ALTER TABLE net.device_topology OWNER TO datcr;

--
-- Name: devices; Type: TABLE; Schema: net; Owner: datcr
--

CREATE TABLE net.devices (
    mac macaddr NOT NULL,
    hostname text NOT NULL,
    hostname_origin public.hostname_origin_t DEFAULT 'dhcp'::public.hostname_origin_t NOT NULL,
    duid bytea,
    origin public.device_origin DEFAULT 'dynamic'::public.device_origin NOT NULL,
    managed_at timestamp with time zone,
    class integer DEFAULT 0 NOT NULL
);


ALTER TABLE net.devices OWNER TO datcr;

--
-- Name: seen_v4; Type: TABLE; Schema: net; Owner: datcr
--

CREATE TABLE net.seen_v4 (
    mac macaddr NOT NULL,
    ip inet NOT NULL,
    last_seen timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE net.seen_v4 OWNER TO datcr;

--
-- Name: slaac_addrs; Type: TABLE; Schema: net; Owner: datcr
--

CREATE TABLE net.slaac_addrs (
    mac macaddr NOT NULL,
    ip inet NOT NULL,
    last_seen timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE net.slaac_addrs OWNER TO datcr;

--
-- Name: v6_prefixes; Type: TABLE; Schema: net; Owner: datcr
--

CREATE TABLE net.v6_prefixes (
    mac macaddr NOT NULL,
    iaid bigint NOT NULL,
    expires timestamp with time zone NOT NULL,
    cidr cidr NOT NULL
);


ALTER TABLE net.v6_prefixes OWNER TO datcr;

--
-- Name: _sqlx_migrations; Type: TABLE; Schema: public; Owner: datcr
--

CREATE TABLE public._sqlx_migrations (
    version bigint NOT NULL,
    description text NOT NULL,
    installed_on timestamp with time zone DEFAULT now() NOT NULL,
    success boolean NOT NULL,
    checksum bytea NOT NULL,
    execution_time bigint NOT NULL
);


ALTER TABLE public._sqlx_migrations OWNER TO datcr;

--
-- Name: api_tokens id; Type: DEFAULT; Schema: auth; Owner: datcr
--

ALTER TABLE ONLY auth.api_tokens ALTER COLUMN id SET DEFAULT nextval('auth.api_tokens_new_id_seq'::regclass);


--
-- Name: lease_history id; Type: DEFAULT; Schema: dhcp; Owner: datcr
--

ALTER TABLE ONLY dhcp.lease_history ALTER COLUMN id SET DEFAULT nextval('dhcp.lease_history_id_seq'::regclass);


--
-- Name: adblock_urls id; Type: DEFAULT; Schema: dns; Owner: datcr
--

ALTER TABLE ONLY dns.adblock_urls ALTER COLUMN id SET DEFAULT nextval('dns.dns_adblock_urls_id_seq'::regclass);


--
-- Name: allowlist id; Type: DEFAULT; Schema: dns; Owner: datcr
--

ALTER TABLE ONLY dns.allowlist ALTER COLUMN id SET DEFAULT nextval('dns.dns_allowlist_id_seq'::regclass);


--
-- Name: rewrites id; Type: DEFAULT; Schema: dns; Owner: datcr
--

ALTER TABLE ONLY dns.rewrites ALTER COLUMN id SET DEFAULT nextval('dns.dns_rewrites_new_id_seq'::regclass);


--
-- Name: upstreams id; Type: DEFAULT; Schema: dns; Owner: datcr
--

ALTER TABLE ONLY dns.upstreams ALTER COLUMN id SET DEFAULT nextval('dns.dns_upstreams_id_seq'::regclass);


--
-- Name: api_tokens api_tokens_new_name_key; Type: CONSTRAINT; Schema: auth; Owner: datcr
--

ALTER TABLE ONLY auth.api_tokens
    ADD CONSTRAINT api_tokens_new_name_key UNIQUE (name);


--
-- Name: api_tokens api_tokens_new_pkey; Type: CONSTRAINT; Schema: auth; Owner: datcr
--

ALTER TABLE ONLY auth.api_tokens
    ADD CONSTRAINT api_tokens_new_pkey PRIMARY KEY (id);


--
-- Name: api_tokens api_tokens_new_token_key; Type: CONSTRAINT; Schema: auth; Owner: datcr
--

ALTER TABLE ONLY auth.api_tokens
    ADD CONSTRAINT api_tokens_new_token_key UNIQUE (token);


--
-- Name: lease_history lease_history_pkey; Type: CONSTRAINT; Schema: dhcp; Owner: datcr
--

ALTER TABLE ONLY dhcp.lease_history
    ADD CONSTRAINT lease_history_pkey PRIMARY KEY (id);


--
-- Name: static_devices static_devices_pkey; Type: CONSTRAINT; Schema: dhcp; Owner: datcr
--

ALTER TABLE ONLY dhcp.static_devices
    ADD CONSTRAINT static_devices_pkey PRIMARY KEY (mac);


--
-- Name: v4_leases v4_leases_pkey; Type: CONSTRAINT; Schema: dhcp; Owner: datcr
--

ALTER TABLE ONLY dhcp.v4_leases
    ADD CONSTRAINT v4_leases_pkey PRIMARY KEY (mac);


--
-- Name: v6_leases v6_leases_pkey; Type: CONSTRAINT; Schema: dhcp; Owner: datcr
--

ALTER TABLE ONLY dhcp.v6_leases
    ADD CONSTRAINT v6_leases_pkey PRIMARY KEY (mac, iaid);


--
-- Name: adblock_config adblock_config_pkey; Type: CONSTRAINT; Schema: dns; Owner: datcr
--

ALTER TABLE ONLY dns.adblock_config
    ADD CONSTRAINT adblock_config_pkey PRIMARY KEY (id);


--
-- Name: adblock_urls dns_adblock_urls_pkey; Type: CONSTRAINT; Schema: dns; Owner: datcr
--

ALTER TABLE ONLY dns.adblock_urls
    ADD CONSTRAINT dns_adblock_urls_pkey PRIMARY KEY (id);


--
-- Name: adblock_urls dns_adblock_urls_url_key; Type: CONSTRAINT; Schema: dns; Owner: datcr
--

ALTER TABLE ONLY dns.adblock_urls
    ADD CONSTRAINT dns_adblock_urls_url_key UNIQUE (url);


--
-- Name: allowlist dns_allowlist_domain_key; Type: CONSTRAINT; Schema: dns; Owner: datcr
--

ALTER TABLE ONLY dns.allowlist
    ADD CONSTRAINT dns_allowlist_domain_key UNIQUE (domain);


--
-- Name: allowlist dns_allowlist_pkey; Type: CONSTRAINT; Schema: dns; Owner: datcr
--

ALTER TABLE ONLY dns.allowlist
    ADD CONSTRAINT dns_allowlist_pkey PRIMARY KEY (id);


--
-- Name: reverse_resolvers dns_reverse_resolvers_pkey; Type: CONSTRAINT; Schema: dns; Owner: datcr
--

ALTER TABLE ONLY dns.reverse_resolvers
    ADD CONSTRAINT dns_reverse_resolvers_pkey PRIMARY KEY (subnet);


--
-- Name: rewrites dns_rewrites_new_domain_rtype_key; Type: CONSTRAINT; Schema: dns; Owner: datcr
--

ALTER TABLE ONLY dns.rewrites
    ADD CONSTRAINT dns_rewrites_new_domain_rtype_key UNIQUE (domain, rtype);


--
-- Name: rewrites dns_rewrites_new_pkey; Type: CONSTRAINT; Schema: dns; Owner: datcr
--

ALTER TABLE ONLY dns.rewrites
    ADD CONSTRAINT dns_rewrites_new_pkey PRIMARY KEY (id);


--
-- Name: upstreams dns_upstreams_addr_protocol_key; Type: CONSTRAINT; Schema: dns; Owner: datcr
--

ALTER TABLE ONLY dns.upstreams
    ADD CONSTRAINT dns_upstreams_addr_protocol_key UNIQUE (addr, protocol);


--
-- Name: upstreams dns_upstreams_pkey; Type: CONSTRAINT; Schema: dns; Owner: datcr
--

ALTER TABLE ONLY dns.upstreams
    ADD CONSTRAINT dns_upstreams_pkey PRIMARY KEY (id);


--
-- Name: device_topology device_topology_pkey; Type: CONSTRAINT; Schema: net; Owner: datcr
--

ALTER TABLE ONLY net.device_topology
    ADD CONSTRAINT device_topology_pkey PRIMARY KEY (mac);


--
-- Name: devices devices_pkey; Type: CONSTRAINT; Schema: net; Owner: datcr
--

ALTER TABLE ONLY net.devices
    ADD CONSTRAINT devices_pkey PRIMARY KEY (mac);


--
-- Name: seen_v4 seen_v4_pkey; Type: CONSTRAINT; Schema: net; Owner: datcr
--

ALTER TABLE ONLY net.seen_v4
    ADD CONSTRAINT seen_v4_pkey PRIMARY KEY (mac, ip);


--
-- Name: slaac_addrs slaac_addrs_pkey; Type: CONSTRAINT; Schema: net; Owner: datcr
--

ALTER TABLE ONLY net.slaac_addrs
    ADD CONSTRAINT slaac_addrs_pkey PRIMARY KEY (mac, ip);


--
-- Name: v6_prefixes v6_prefixes_pkey; Type: CONSTRAINT; Schema: net; Owner: datcr
--

ALTER TABLE ONLY net.v6_prefixes
    ADD CONSTRAINT v6_prefixes_pkey PRIMARY KEY (mac, iaid);


--
-- Name: _sqlx_migrations _sqlx_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: datcr
--

ALTER TABLE ONLY public._sqlx_migrations
    ADD CONSTRAINT _sqlx_migrations_pkey PRIMARY KEY (version);


--
-- Name: idx_lease_history_mac_occurred; Type: INDEX; Schema: dhcp; Owner: datcr
--

CREATE INDEX idx_lease_history_mac_occurred ON dhcp.lease_history USING btree (mac, occurred_at DESC);


--
-- Name: idx_devices_duid; Type: INDEX; Schema: net; Owner: datcr
--

CREATE INDEX idx_devices_duid ON net.devices USING btree (duid);


--
-- Name: static_devices static_devices_mac_fkey; Type: FK CONSTRAINT; Schema: dhcp; Owner: datcr
--

ALTER TABLE ONLY dhcp.static_devices
    ADD CONSTRAINT static_devices_mac_fkey FOREIGN KEY (mac) REFERENCES net.devices(mac) ON DELETE CASCADE;


--
-- Name: v4_leases v4_leases_mac_fkey; Type: FK CONSTRAINT; Schema: dhcp; Owner: datcr
--

ALTER TABLE ONLY dhcp.v4_leases
    ADD CONSTRAINT v4_leases_mac_fkey FOREIGN KEY (mac) REFERENCES net.devices(mac) ON DELETE CASCADE;


--
-- Name: v6_leases v6_leases_mac_fkey; Type: FK CONSTRAINT; Schema: dhcp; Owner: datcr
--

ALTER TABLE ONLY dhcp.v6_leases
    ADD CONSTRAINT v6_leases_mac_fkey FOREIGN KEY (mac) REFERENCES net.devices(mac) ON DELETE CASCADE;


--
-- Name: device_topology device_topology_mac_fkey; Type: FK CONSTRAINT; Schema: net; Owner: datcr
--

ALTER TABLE ONLY net.device_topology
    ADD CONSTRAINT device_topology_mac_fkey FOREIGN KEY (mac) REFERENCES net.devices(mac) ON DELETE CASCADE;


--
-- Name: seen_v4 seen_v4_mac_fkey; Type: FK CONSTRAINT; Schema: net; Owner: datcr
--

ALTER TABLE ONLY net.seen_v4
    ADD CONSTRAINT seen_v4_mac_fkey FOREIGN KEY (mac) REFERENCES net.devices(mac) ON DELETE CASCADE;


--
-- Name: slaac_addrs slaac_addrs_mac_fkey; Type: FK CONSTRAINT; Schema: net; Owner: datcr
--

ALTER TABLE ONLY net.slaac_addrs
    ADD CONSTRAINT slaac_addrs_mac_fkey FOREIGN KEY (mac) REFERENCES net.devices(mac) ON DELETE CASCADE;


--
-- Name: v6_prefixes v6_prefixes_mac_fkey; Type: FK CONSTRAINT; Schema: net; Owner: datcr
--

ALTER TABLE ONLY net.v6_prefixes
    ADD CONSTRAINT v6_prefixes_mac_fkey FOREIGN KEY (mac) REFERENCES net.devices(mac) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict goOXHfVkL4cWZeRf1m2RK8urW1X6Zefio7bYkrJ6wlxYshi7Je40an6BeoiGb3r