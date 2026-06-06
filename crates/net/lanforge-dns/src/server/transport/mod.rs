pub mod tls;

#[cfg(feature = "doh-upstream")]
pub mod doh;

#[cfg(feature = "dot")]
pub mod dot;

#[cfg(feature = "doq")]
pub mod doq;
