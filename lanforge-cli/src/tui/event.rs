use crate::tui::action::ActionResult;
use crossterm::event::KeyEvent;
use lanforge_api::api::{
    DevicesResponse, DhcpPoolsResponse, DnsAdblockStatusResponse, DnsAdblockUrlsResponse,
    DnsAllowlistResponse, DnsAnalyticsResponse, DnsCacheStatsExtResponse, DnsQueryLogEntry,
    DnsQueryLogResponse, DnsRewritesResponse, DnsStatsResponse, DnsUpstreamsResponse,
    LeasesResponse, ServiceBannersResponse, StatusResponse, TopologyResponse, WhoisResponse,
};
use lanforge_types::events::TimedEvent;

pub enum AppEvent {
    Key(KeyEvent),
    DaemonEvent(TimedEvent),
    DnsLiveQuery(DnsQueryLogEntry),
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
    ActionResult(ActionResult),
    Tick,
}
