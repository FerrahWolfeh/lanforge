pub mod rewrite;
pub mod local;
pub mod adblock;
pub mod upstream;

pub use rewrite::RewriteMiddleware;
pub use local::LocalResolverMiddleware;
pub use adblock::AdblockMiddleware;
pub use upstream::UpstreamMiddleware;
