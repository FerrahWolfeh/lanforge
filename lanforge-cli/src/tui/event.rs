use crossterm::event::KeyEvent;
use lanforge_api::api::{
    DevicesResponse, DhcpPoolsResponse, DnsAdblockStatusResponse, DnsAdblockUrlsResponse,
    DnsAllowlistResponse, DnsAnalyticsResponse, DnsCacheStatsExtResponse, DnsQueryLogResponse,
    DnsRewritesResponse, DnsStatsResponse, DnsUpstreamsResponse, LeasesResponse,
    ServiceBannersResponse, StatusResponse, TopologyResponse, WhoisResponse,
};
use lanforge_types::events::TimedEvent;

pub enum AppEvent {
    Key(KeyEvent),
    DaemonEvent(TimedEvent),
    StatusUpdate(Box<StatusResponse>),
    ServiceBannersUpdate(ServiceBannersResponse),
    DevicesUpdate(Box<DevicesResponse>),
    TopologyUpdate(Box<TopologyResponse>),
    LeasesUpdate(LeasesResponse),
    DhcpPoolsUpdate(DhcpPoolsResponse),
    DnsStatsUpdate(Box<DnsStatsResponse>),
    DnsAnalyticsUpdate(Box<DnsAnalyticsResponse>),
    DnsUpstreamsUpdate(Box<DnsUpstreamsResponse>),
    DnsQueryLogUpdate(Box<DnsQueryLogResponse>),
    DnsCacheStatsUpdate(DnsCacheStatsExtResponse),
    DnsAdblockStatusUpdate(Box<DnsAdblockStatusResponse>),
    DnsRewritesUpdate(DnsRewritesResponse),
    DnsAdblockUrlsUpdate(DnsAdblockUrlsResponse),
    DnsAllowlistUpdate(DnsAllowlistResponse),
    WhoisUpdate(Box<WhoisResponse>),
    Tick,
}
