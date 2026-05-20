pub mod rewrite;
pub mod local;
pub mod cache;
#[cfg(feature = "adblock")]
pub mod adblock;
pub mod upstream;

pub use rewrite::RewriteMiddleware;
pub use local::LocalResolverMiddleware;
pub use cache::CacheMiddleware;
#[cfg(feature = "adblock")]
pub use adblock::AdblockMiddleware;
pub use upstream::UpstreamMiddleware;
