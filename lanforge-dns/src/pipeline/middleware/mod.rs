#[cfg(feature = "adblock")]
pub mod adblock;
pub mod cache;
pub mod local;
pub mod rewrite;
pub mod upstream;

#[cfg(feature = "adblock")]
pub use adblock::AdblockMiddleware;
pub use cache::CacheMiddleware;
pub use local::LocalResolverMiddleware;
pub use rewrite::RewriteMiddleware;
pub use upstream::UpstreamMiddleware;
