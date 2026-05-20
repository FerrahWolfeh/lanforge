# DNS Rewrite Rules in Lanforge

Lanforge's integrated DNS module supports dynamic, hardware-linked rewrite rules that go beyond traditional static host mappings. These rules leverage Lanforge Core's global device state to bind DNS responses directly to live network leases and announce local services.

---

## 1. Dynamic Device Resolution (`dev:`)

Instead of mapping a domain name to a static IP address, you can rewrite domains to dynamically track the IP addresses of any device registered in Lanforge.

### Syntax
`dev:<identifier>[|fallback]`

* **`<identifier>`**: A **Device Name** (e.g., `nas-box`) or a **MAC Address** (e.g., `00:11:22:33:44:55`).
  * *Device Name*: Must be alphanumeric or contain hyphens (cannot start/end with a hyphen, max 63 characters).
  * *MAC Address*: Verified against standard hardware address formats.
* **`[|fallback]`** (Optional): A fallback action or IP address to return if the device is offline or has no active DHCP leases/IPv6 SLAAC addresses.
  * Example IP: `dev:nas-box|192.168.1.99`
  * Example NXDOMAIN (default if omitted): `dev:nas-box|nxdomain`

### Examples
* **`dev:media-server`**: Resolves the domain to the active IP(s) of the device named `media-server`. If offline, returns `NXDOMAIN`.
* **`dev:00:aa:bb:cc:dd:ee|192.168.1.250`**: Tracks the device with the matching MAC address. If the device is not seen on the network, resolves to `192.168.1.250`.

### Behavior & TTL
To ensure that client DNS caches do not hold onto stale IPs after a device roams or gets a new lease, **dynamic device resolutions return a short TTL of 5 seconds**.

---

## 2. Local Service Discovery via SRV Records (`srv:`)

Lanforge supports zero-configuration local service discovery using DNS SRV records. This enables apps to query for standard services (like HTTP, Plex, or Minecraft) running on your local network.

### Syntax
`srv:<service>:<protocol>:<device>:<port>`

* **`<service>`**: A service identifier. Can be a standard protocol (`http`, `https`, `ssh`, `ftp`, `plex`, `jellyfin`, `minecraft`, `ldap`) or any custom service name.
* **`<protocol>`**: The transport protocol, either `tcp` or `udp` (parsed case-insensitively, leading underscores like `_tcp` are optional and stripped during parsing).
* **`<device>`**: The target device identifier (`DeviceIdentifier`), which can be a device name or MAC address.
* **`<port>`**: The target port number (1 - 65535).

### Example
* **`srv:http:tcp:nas-box:8096`**:
  * Matches incoming SRV requests (e.g., `_http._tcp.nas.home`).
  * Returns a valid DNS SRV record pointing to the target `<device>.lan` (e.g., `nas-box.lan`) on port `8096`.
  * Returns a short TTL of 5 seconds to track port/host changes dynamically.

---

## 3. Technical Reference & Architecture

* **Strong Types**: Rules are validated and parsed using strong enums (`DeviceIdentifier`, `DnsService`, `DnsServiceProtocol`, `RewriteAnswer`) at the foundational level (`lanforge-types`) instead of using raw heap-allocated strings, preventing malformed rules from entering the database.
* **Zero-Allocation Wire Generation**: The `write_srv_response` helper writes SRV replies directly to the wire response buffer without creating temporary objects or strings where possible.
* **Local Resolver Integration**: The `RewriteStore` invokes `LocalResolver::resolve_device` which queries the context `State` for the active MAC address or name, returning all active IPv4 (A) and IPv6 (AAAA) addresses associated with the device.
