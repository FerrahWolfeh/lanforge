//! Identity of a lanforge build, shared by the daemon and the CLI so either side can tell
//! whether it talks to the same build, an older one or a newer one.

use std::cmp::Ordering;
use std::fmt;

/// A build: workspace version plus the git commit and web UI version it was built from.
///
/// Written as a semver version with build metadata, `0.63.0+a1b2c3d4e5f6.1762160000.0.1.0.dirty`:
/// commit hash, commit time (Unix seconds), web UI version (`web/package.json`) and `dirty` when
/// the tree had uncommitted changes. A build made without git is just the version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildInfo {
    pub version: String,
    pub commit: Option<Commit>,
}

/// The git commit and web UI version a build came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub hash: String,
    /// Committer time, Unix seconds: orders two builds of different commits.
    pub time: u64,
    /// Web UI version (`web/package.json`).
    pub webui: String,
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
        if !version.starts_with(|c: char| c.is_ascii_digit()) {
            return None;
        }
        let commit = match meta {
            None => None,
            Some(meta) => {
                let (rest, dirty) = meta
                    .strip_suffix(".dirty")
                    .map_or((meta, false), |r| (r, true));
                let mut parts = rest.splitn(3, '.');
                let hash = parts
                    .next()
                    .filter(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_alphanumeric()))?;
                let time = parts.next()?.parse().ok()?;
                // `X.Y.Z`, optionally with a pre-release: a bare `1.0` means the time is missing.
                let webui = parts.next().filter(|w| {
                    let core = w.split_once('-').map_or(*w, |(core, _)| core);
                    core.split('.').count() == 3
                        && core
                            .split('.')
                            .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                })?;
                Some(Commit {
                    hash: hash.to_string(),
                    time,
                    webui: webui.to_string(),
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
                if mine.dirty == theirs.dirty && mine.webui == theirs.webui {
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
            write!(f, "+{}.{}.{}", commit.hash, commit.time, commit.webui)?;
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
            "0.40.0+a1b2c3d4e5f6.1762160000.0.1.0",
            "0.40.0+a1b2c3d4e5f6.1762160000.0.1.0.dirty",
            "0.64.0-rc.1+a1b2c3d4e5f6.1762160000.0.2.0-beta.1",
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
            "0.40.0+abc.1",
            "0.40.0+abc.0.1.0",
            "0.40.0+abc.1.x",
            "0.40.0+abc.1.0.1.0.dirty.x",
        ] {
            assert_eq!(BuildInfo::parse(token), None, "{token}");
        }
    }

    #[test]
    fn builds_are_ordered_by_commit_time() {
        let cli = build("0.40.0+aaaa.200.0.1.0");
        assert_eq!(
            cli.order_of(&build("0.40.0+aaaa.200.0.1.0")),
            BuildOrder::Same
        );
        // Same versions, different commits: the commit time still says which side is behind.
        assert_eq!(
            cli.order_of(&build("0.40.0+bbbb.100.0.1.0")),
            BuildOrder::Older
        );
        assert_eq!(
            cli.order_of(&build("0.40.0+cccc.300.0.1.0")),
            BuildOrder::Newer
        );
        assert_eq!(
            cli.order_of(&build("0.41.0+cccc.300.0.2.0")),
            BuildOrder::Newer
        );
        assert_eq!(
            cli.order_of(&build("0.40.0+dddd.200.0.1.0")),
            BuildOrder::Different
        );
    }

    #[test]
    fn local_changes_on_one_side_make_the_same_commit_different() {
        let clean = build("0.40.0+aaaa.200.0.1.0");
        let local = build("0.40.0+aaaa.200.0.1.0.dirty");
        assert_eq!(clean.order_of(&local), BuildOrder::Different);
        assert_eq!(local.order_of(&clean), BuildOrder::Different);
        // A web UI version bumped but not committed yet is a local change too.
        let bumped = build("0.40.0+aaaa.200.0.2.0.dirty");
        assert_eq!(local.order_of(&bumped), BuildOrder::Different);
        // Commits still order dirty builds.
        assert_eq!(
            local.order_of(&build("0.40.0+bbbb.300.0.1.0")),
            BuildOrder::Newer
        );
    }

    #[test]
    fn without_git_only_an_equal_version_is_the_same() {
        assert_eq!(build("0.40.0").order_of(&build("0.40.0")), BuildOrder::Same);
        assert_eq!(
            build("0.40.0").order_of(&build("0.41.0")),
            BuildOrder::Different
        );
        assert_eq!(
            build("0.40.0").order_of(&build("0.40.0+aaaa.1.0.1.0")),
            BuildOrder::Different
        );
    }
}
