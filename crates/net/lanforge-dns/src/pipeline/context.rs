use crate::error::DnsError;
use crate::wire::{WireHeader, WireQuestion, WireDecoder};
use lanforge_types::DnsMessage;
use once_cell::sync::OnceCell;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

/// Internal representation of the parsed query to unify wire and fallback paths.
pub enum QueryView<'a> {
    /// Zero-allocation fast-path view.
    Wire {
        header: WireHeader<'a>,
        question: WireQuestion<'a>,
    },
    /// Full allocation fallback view.
    Fallback {
        message: DnsMessage,
        qname: Arc<str>,
        qtype: u16,
    },
}

/// The context of a single DNS query passing through the pipeline.
pub struct QueryContext<'a> {
    /// The raw UDP/TCP payload.
    pub raw: &'a [u8],
    /// The IP address of the client that sent the query.
    pub src_addr: IpAddr,
    /// When the query was received, for latency tracking.
    pub start_time: Instant,
    /// The parsed view of the query (either fast wire or slow fallback).
    pub view: QueryView<'a>,
    /// Lazily evaluated full qname (e.g. for adblock matching).
    qname_cache: OnceCell<Arc<str>>,
}

impl<'a> QueryContext<'a> {
    /// Creates a new query context. It first attempts the fast wire parse,
    /// and if it fails (due to pointers etc), falls back to Hickory.
    pub fn parse(raw: &'a [u8], src_addr: IpAddr) -> Result<Self, DnsError> {
        let start_time = Instant::now();

        // 1. Fast path triage
        if let Some(header) = WireHeader::parse(raw) {
            if header.is_query() {
                if let Some(question) = WireQuestion::parse(raw) {
                    return Ok(Self {
                        raw,
                        src_addr,
                        start_time,
                        view: QueryView::Wire { header, question },
                        qname_cache: OnceCell::new(),
                    });
                }
            } else {
                return Err(DnsError::WireParseError); // Not a query
            }
        }

        // 2. Slow path fallback
        let mut decoder = WireDecoder::new(raw);
        if let Some(message) = decoder.decode_message()
            && let Some(question) = message.questions.first()
        {
            let qname = question.name.clone();
            let qtype = u16::from(question.qtype);
            return Ok(Self {
                raw,
                src_addr,
                start_time,
                view: QueryView::Fallback {
                    message,
                    qname,
                    qtype,
                },
                qname_cache: OnceCell::new(),
            });
        }

        Err(DnsError::WireParseError)
    }

    /// Returns the QTYPE of the query.
    #[must_use]
    pub const fn qtype(&self) -> u16 {
        match &self.view {
            QueryView::Wire { question, .. } => question.qtype(),
            QueryView::Fallback { qtype, .. } => *qtype,
        }
    }

    /// Retrieves the domain name as a String.
    /// This uses a `OnceCell` to avoid allocating the string multiple times if requested by
    /// different middleware (e.g., adblocker, logging).
    pub fn qname_arc(&self) -> Arc<str> {
        self.qname_cache.get_or_init(|| self.init_qname()).clone()
    }

    /// Retrieves the domain name as a String.
    pub fn qname(&self) -> &str {
        self.qname_cache.get_or_init(|| self.init_qname()).as_ref()
    }

    fn init_qname(&self) -> Arc<str> {
        match &self.view {
            QueryView::Wire { question, .. } => {
                let mut domain = String::with_capacity(32);
                for label in question.labels() {
                    if !domain.is_empty() {
                        domain.push('.');
                    }
                    if let Ok(s) = std::str::from_utf8(label) {
                        domain.push_str(s);
                    }
                }
                domain.to_lowercase().into()
            }
            QueryView::Fallback { qname, .. } => {
                let mut s = qname.to_lowercase();
                if s.ends_with('.') {
                    s.pop();
                }
                s.into()
            }
        }
    }
}
