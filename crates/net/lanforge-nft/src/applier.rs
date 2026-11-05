//! Where compiled rulesets go: the kernel ([`KernelNft`]) in production, an in-memory recorder
//! ([`RecordingNft`]) in rootless tests. The firewall service holds no simulation branches.

use nftables::helper::NftablesError;
use nftables::schema::Nftables;

/// Applies an nftables batch atomically. Runs on a blocking thread.
pub trait NftApplier: Clone + Send + Sync + 'static {
    /// Applies `ruleset` as one transaction.
    ///
    /// # Errors
    /// The batch was refused (the kernel keeps its previous ruleset) or `nft` could not run.
    fn apply(&self, ruleset: &Nftables<'static>) -> Result<(), NftablesError>;
}

/// The kernel, through `nft -j -f -`.
#[derive(Debug, Clone, Copy, Default)]
pub struct KernelNft;

impl NftApplier for KernelNft {
    fn apply(&self, ruleset: &Nftables<'static>) -> Result<(), NftablesError> {
        nftables::helper::apply_ruleset(ruleset)
    }
}

#[cfg(any(test, feature = "inert"))]
pub use recording::RecordingNft;

#[cfg(any(test, feature = "inert"))]
mod recording {
    use super::{NftApplier, Nftables, NftablesError};
    use nftables::schema::{NfCmd, NfListObject, NfObject};
    use parking_lot::RwLock;
    use std::sync::Arc;

    /// Accepts every batch and keeps the last one as pretty JSON; a batch that only deletes the
    /// table clears it (nothing of ours is left).
    #[derive(Debug, Clone, Default)]
    pub struct RecordingNft {
        last: Arc<RwLock<Option<String>>>,
    }

    impl RecordingNft {
        /// The last batch applied, `None` before the first one or after the table was deleted.
        #[must_use]
        pub fn payload(&self) -> Option<String> {
            self.last.read().clone()
        }
    }

    impl NftApplier for RecordingNft {
        fn apply(&self, ruleset: &Nftables<'static>) -> Result<(), NftablesError> {
            let deletes_table = matches!(
                ruleset.objects.as_ref(),
                [NfObject::CmdObject(NfCmd::Delete(NfListObject::Table(_)))]
            );
            *self.last.write() = if deletes_table {
                None
            } else {
                Some(serde_json::to_string_pretty(ruleset).unwrap_or_default())
            };
            Ok(())
        }
    }
}
