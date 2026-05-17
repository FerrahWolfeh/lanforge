use crossterm::event::KeyEvent;
use lanforge_api::api::StatusResponse;
use lanforge_types::events::TimedEvent;

pub enum AppEvent {
    Key(KeyEvent),
    DaemonEvent(TimedEvent),
    StatusUpdate(Box<StatusResponse>),
    DnsStatsUpdate(Box<lanforge_api::api::DnsStatsResponse>),
    DnsAnalyticsUpdate(Box<lanforge_api::api::DnsAnalyticsResponse>),
    DnsUpstreamsUpdate(Box<lanforge_api::api::DnsUpstreamsResponse>),
    DnsQueryLogUpdate(Box<lanforge_api::api::DnsQueryLogResponse>),
    DnsAdblockStatusUpdate(Box<lanforge_api::api::DnsAdblockStatusResponse>),
    Tick,
}
