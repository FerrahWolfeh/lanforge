//! Common traits for DHCP pools.

/// A common trait for managing IP address pools.
pub trait DhcpPool<Addr> {
    /// Reserves a batch of static addresses to prevent dynamic allocation collisions.
    fn reserve_statics(&mut self, ips: impl IntoIterator<Item = Addr>);

    /// Returns an IP address to the available pool.
    fn release(&mut self, ip: &Addr);

    /// Quarantines or blacklists a conflicted address (usually reported via DECLINE).
    fn decline(&mut self, ip: Addr);
}
