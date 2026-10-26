use lanforge_api::api::*;
use lanforge_api::rpc::*;
use std::mem::{align_of, size_of};

fn print_size<T>(name: &str) {
    println!(
        "{:<35} {:>5} B  (align: {:>2})",
        name,
        size_of::<T>(),
        align_of::<T>()
    );
}

#[test]
fn test_print_api_struct_sizes() {
    println!("\n=== TOP-LEVEL PROTOCOLS ===");
    print_size::<Response>("Response");
    print_size::<RpcRequest>("RpcRequest");
    print_size::<RpcResponse>("RpcResponse");

    println!("\n=== SYSTEM & STATUS ===");
    print_size::<StatusResponse>("StatusResponse");
    print_size::<ServicesStatus>("ServicesStatus");
    print_size::<ServiceStatusInfo>("ServiceStatusInfo");
    print_size::<ServiceDot>("ServiceDot");
    print_size::<ServiceDoh>("ServiceDoh");
    print_size::<ServiceDoq>("ServiceDoq");
    print_size::<NetworkStatus>("NetworkStatus");
    print_size::<DevicesStats>("DevicesStats");
    print_size::<ResourcesStatus>("ResourcesStatus");
    print_size::<DbStatus>("DbStatus");
    print_size::<Capabilities>("Capabilities");
    print_size::<SystemConfigExport>("SystemConfigExport");
    print_size::<SystemConfigImportResponse>("SystemConfigImportResponse");
    print_size::<ServiceBannersResponse>("ServiceBannersResponse");

    println!("\n=== DEVICES & HOSTS ===");
    print_size::<DeviceEntry>("DeviceEntry");
    print_size::<DevicesResponse>("DevicesResponse");
    print_size::<DevicesMeta>("DevicesMeta");
    print_size::<GroupedDevice>("GroupedDevice");
    print_size::<HostConfigEntry>("HostConfigEntry");
    print_size::<HostsResponse>("HostsResponse");
    print_size::<TransientHostEntry>("TransientHostEntry");
    print_size::<TransientHostsResponse>("TransientHostsResponse");
    print_size::<WhoisResponse>("WhoisResponse");
    print_size::<LeaseInfo>("LeaseInfo");
    print_size::<Ipv6Entry>("Ipv6Entry");

    println!("\n=== DHCP ===");
    print_size::<LeasesResponse>("LeasesResponse");
    print_size::<LeaseEntry>("LeaseEntry");
    print_size::<DhcpPoolsResponse>("DhcpPoolsResponse");
    print_size::<DhcpPoolEntry>("DhcpPoolEntry");
    print_size::<DhcpOptionsResponse>("DhcpOptionsResponse");
    print_size::<DhcpPoolsConfigResponse>("DhcpPoolsConfigResponse");
    print_size::<DhcpReconcileResponse>("DhcpReconcileResponse");

    println!("\n=== DNS ===");
    print_size::<DnsAnalyticsResponse>("DnsAnalyticsResponse");
    print_size::<TopDomainEntry>("TopDomainEntry");
    print_size::<QueryTypeEntry>("QueryTypeEntry");
    print_size::<QueryRateEntry>("QueryRateEntry");
    print_size::<TopClientEntry>("TopClientEntry");
    print_size::<ProtocolStatEntry>("ProtocolStatEntry");
    print_size::<DnsQueryLogResponse>("DnsQueryLogResponse");
    print_size::<DnsQueryLogEntry>("DnsQueryLogEntry");
    print_size::<DnsQueryResponse>("DnsQueryResponse");
    print_size::<DnsUpstreamsResponse>("DnsUpstreamsResponse");
    print_size::<DnsRewritesResponse>("DnsRewritesResponse");
    print_size::<DnsAllowlistResponse>("DnsAllowlistResponse");
    print_size::<DnsAdblockUrlsResponse>("DnsAdblockUrlsResponse");
    print_size::<DnsAdblockRulesResponse>("DnsAdblockRulesResponse");
    print_size::<DnsReverseResolversResponse>("DnsReverseResolversResponse");

    println!("\n=== AUTH & USERS ===");
    print_size::<AuthTokenResponse>("AuthTokenResponse");
    print_size::<AuthTokensResponse>("AuthTokensResponse");
    print_size::<UserResponse>("UserResponse");
    print_size::<UserListResponse>("UserListResponse");
}
