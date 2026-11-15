//! Where compiled rulesets go: the kernel ([`KernelNft`]) in production, an in-memory recorder
//! ([`RecordingNft`]) in rootless tests. The firewall service holds no simulation branches.

use std::io::Write;
use std::process::{Command, Stdio};

use nftables::helper::{self, NftablesError};
use nftables::schema::Nftables;

/// Applies an nftables batch atomically. Runs on a blocking thread.
pub trait NftApplier: Clone + Send + Sync + 'static {
    /// Applies `ruleset` as one transaction.
    ///
    /// # Errors
    /// The batch was refused (the kernel keeps its previous ruleset) or `nft` could not run.
    fn apply(&self, ruleset: &Nftables<'static>) -> Result<(), NftablesError>;

    /// Runs `script`, an nft script in the text syntax (the admin's `custom_rules_file`), as
    /// one transaction.
    ///
    /// # Errors
    /// `nft` refused it (none of it applied) or could not run; the message says why.
    fn apply_script(&self, script: &str) -> Result<(), String>;
}

/// The kernel, through `nft -j -f -`.
#[derive(Debug, Clone, Copy, Default)]
pub struct KernelNft;

impl NftApplier for KernelNft {
    fn apply(&self, ruleset: &Nftables<'static>) -> Result<(), NftablesError> {
        helper::apply_ruleset(ruleset)
    }

    /// Through `nft -f -` (the `nftables` helpers always pass `-j`).
    fn apply_script(&self, script: &str) -> Result<(), String> {
        let mut nft = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot run nft: {e}"))?;
        // Dropped at the end of the statement: nft sees the end of its input.
        nft.stdin
            .take()
            .expect("stdin is piped")
            .write_all(script.as_bytes())
            .map_err(|e| format!("cannot pass the rules to nft: {e}"))?;
        let out = nft
            .wait_with_output()
            .map_err(|e| format!("nft did not finish: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
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

    /// Accepts every batch and keeps the last one as pretty JSON.
    ///
    /// A batch that only deletes the table clears it (nothing of ours is left). Scripts are
    /// recorded in order; with [`Self::refusing_scripts`] each one is refused as nft would
    /// refuse a bad file.
    #[derive(Debug, Clone, Default)]
    pub struct RecordingNft {
        last: Arc<RwLock<Option<String>>>,
        scripts: Arc<RwLock<Vec<String>>>,
        refuse_scripts: bool,
    }

    impl RecordingNft {
        /// A recorder that refuses every script (and still accepts rulesets).
        #[must_use]
        pub fn refusing_scripts() -> Self {
            Self {
                refuse_scripts: true,
                ..Self::default()
            }
        }

        /// The last batch applied, `None` before the first one or after the table was deleted.
        #[must_use]
        pub fn payload(&self) -> Option<String> {
            self.last.read().clone()
        }

        /// Every script run (or refused), in order.
        #[must_use]
        pub fn scripts(&self) -> Vec<String> {
            self.scripts.read().clone()
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

        fn apply_script(&self, script: &str) -> Result<(), String> {
            self.scripts.write().push(script.to_string());
            if self.refuse_scripts {
                Err("/dev/stdin:1:1-3: Error: syntax error".to_string())
            } else {
                Ok(())
            }
        }
    }
}
