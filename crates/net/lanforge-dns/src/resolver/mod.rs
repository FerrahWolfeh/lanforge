pub mod builder;
pub mod local;
pub mod recursive;
pub mod rewrite;

#[cfg(feature = "adblock")]
pub mod filter;

pub use builder::ResponseBuilder;
pub use local::LocalResolver;
pub use recursive::UpstreamManager;
pub use rewrite::RewriteStore;

#[cfg(feature = "adblock")]
pub use filter::AdBlocker;

use lanforge_dns_wire::WireLabelIter;

#[must_use]
#[cfg_attr(feature = "hotpath", hotpath::measure)]
pub fn labels_to_domain(labels: WireLabelIter<'_>) -> String {
    let mut domain = String::with_capacity(64);
    for label in labels {
        if !domain.is_empty() {
            domain.push('.');
        }
        if let Ok(s) = std::str::from_utf8(label) {
            domain.push_str(s);
        }
    }
    domain.make_ascii_lowercase();
    domain
}
