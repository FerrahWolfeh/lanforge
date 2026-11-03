//! Identity of a lanforge build, shared by the daemon and the CLI so either side can tell
//! whether it talks to the same build, an older one or a newer one.

use std::cmp::Ordering;
use std::fmt;

/// A build: workspace version plus the git commit it was built from.
///
/// Written as a semver version with build metadata, `0.40.0+a1b2c3d4e5f6.1762160000.dirty`:
/// commit hash, commit time (Unix seconds) and `dirty` when the tree had uncommitted changes.
/// A build made without git is just the version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildInfo {
    pub version: String,
    pub commit: Option<Commit>,
}

/// The git commit a build came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub hash: String,
    /// Committer time, Unix seconds: orders two builds of different commits.
    pub time: u64,
    /// Built with uncommitted changes: the hash alone does not say what is inside.
    pub dirty: bool,
}

/// Where another build stands relative to this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildOrder {
    Same,
    Older,
    Newer,
    /// Different, but no way to tell which is newer (same commit with local changes, no
    /// git data, or two commits made in the same second).
    Different,
}

impl BuildInfo {
    /// Reads a build token; `None` when it is not one.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        let token = token.trim();
        let (version, meta) = match token.split_once('+') {
            Some((version, meta)) => (version, Some(meta)),
            None => (token, None),
        };
        if version.is_empty() || !version.starts_with(|c: char| c.is_ascii_digit()) {
            return None;
        }
        let commit = match meta {
            None => None,
            Some(meta) => {
                let mut parts = meta.split('.');
                let hash = parts.next().filter(|h| !h.is_empty())?;
                let time = parts.next()?.parse().ok()?;
                let dirty = match parts.next() {
                    None => false,
                    Some("dirty") => true,
                    Some(_) => return None,
                };
                if parts.next().is_some() {
                    return None;
                }
                Some(Commit {
                    hash: hash.to_string(),
                    time,
                    dirty,
                })
            }
        };
        Some(Self {
            version: version.to_string(),
            commit,
        })
    }

    /// Where `other` stands relative to this build.
    #[must_use]
    pub fn order_of(&self, other: &Self) -> BuildOrder {
        match (&self.commit, &other.commit) {
            // Same commit: one side with local changes the hash misses makes them differ (two
            // dirty builds of one commit cannot be told apart and pass as the same).
            (Some(mine), Some(theirs)) if mine.hash == theirs.hash => {
                if mine.dirty == theirs.dirty {
                    BuildOrder::Same
                } else {
                    BuildOrder::Different
                }
            }
            (Some(mine), Some(theirs)) => match theirs.time.cmp(&mine.time) {
                Ordering::Less => BuildOrder::Older,
                Ordering::Greater => BuildOrder::Newer,
                Ordering::Equal => BuildOrder::Different,
            },
            _ if self.version == other.version && self.commit == other.commit => BuildOrder::Same,
            _ => BuildOrder::Different,
        }
    }
}

impl fmt::Display for BuildInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.version)?;
        if let Some(commit) = &self.commit {
            write!(f, "+{}.{}", commit.hash, commit.time)?;
            if commit.dirty {
                f.write_str(".dirty")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{BuildInfo, BuildOrder};

    fn build(token: &str) -> BuildInfo {
        BuildInfo::parse(token).unwrap()
    }

    #[test]
    fn a_token_reads_back_as_written() {
        for token in [
            "0.40.0",
            "0.40.0+a1b2c3d4e5f6.1762160000",
            "0.40.0+a1b2c3d4e5f6.1762160000.dirty",
        ] {
            assert_eq!(build(token).to_string(), token);
        }
    }

    #[test]
    fn junk_is_not_a_build() {
        for token in [
            "",
            "lanforge",
            "0.40.0+",
            "0.40.0+abc",
            "0.40.0+abc.x",
            "0.40.0+abc.1.clean",
            "0.40.0+abc.1.dirty.x",
        ] {
            assert_eq!(BuildInfo::parse(token), None, "{token}");
        }
    }

    #[test]
    fn builds_are_ordered_by_commit_time() {
        let cli = build("0.40.0+aaaa.200");
        assert_eq!(cli.order_of(&build("0.40.0+aaaa.200")), BuildOrder::Same);
        assert_eq!(cli.order_of(&build("0.40.0+bbbb.100")), BuildOrder::Older);
        assert_eq!(cli.order_of(&build("0.41.0+cccc.300")), BuildOrder::Newer);
        assert_eq!(
            cli.order_of(&build("0.40.0+dddd.200")),
            BuildOrder::Different
        );
    }

    #[test]
    fn local_changes_on_one_side_make_the_same_commit_different() {
        let clean = build("0.40.0+aaaa.200");
        let local = build("0.40.0+aaaa.200.dirty");
        assert_eq!(clean.order_of(&local), BuildOrder::Different);
        assert_eq!(local.order_of(&clean), BuildOrder::Different);
        // Commits still order dirty builds.
        assert_eq!(local.order_of(&build("0.40.0+bbbb.300")), BuildOrder::Newer);
    }

    #[test]
    fn without_git_only_an_equal_version_is_the_same() {
        assert_eq!(build("0.40.0").order_of(&build("0.40.0")), BuildOrder::Same);
        assert_eq!(
            build("0.40.0").order_of(&build("0.41.0")),
            BuildOrder::Different
        );
        assert_eq!(
            build("0.40.0").order_of(&build("0.40.0+aaaa.1")),
            BuildOrder::Different
        );
    }
}
