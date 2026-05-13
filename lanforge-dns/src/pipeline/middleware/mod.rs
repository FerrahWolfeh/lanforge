pub mod rewrite;
pub mod local;
pub mod cache;
pub mod adblock;
pub mod upstream;

pub use rewrite::RewriteMiddleware;
pub use local::LocalResolverMiddleware;
pub use cache::CacheMiddleware;
pub use adblock::AdblockMiddleware;
pub use upstream::UpstreamMiddleware;
