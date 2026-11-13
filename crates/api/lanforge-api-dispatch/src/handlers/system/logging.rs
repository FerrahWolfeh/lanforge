//! The daemon's log filter: read it, save it, or set it for a limited time.

use std::sync::Arc;
use std::time::Duration;

use lanforge_api::api::{Response, SetLogLevelRequest};
use lanforge_core::bus::{LanforgeEvent, SystemEvent};
use lanforge_core::logging::LogLevels;

use crate::ClientContext;

impl ClientContext {
    fn log_levels(&self) -> Result<Arc<LogLevels>, Response> {
        self.ctx
            .get_shared::<LogLevels>()
            .ok_or_else(|| Response::Error {
                error: "log filter control is not available".into(),
            })
    }

    #[must_use]
    pub fn handle_log_level(&self) -> Response {
        match self.log_levels() {
            Ok(levels) => Response::LogLevel(Box::new(levels.status())),
            Err(e) => e,
        }
    }

    /// Who may set which filter (`trace` is admin-only) is the transport's call: the UDS is
    /// root's, the HTTP route checks the role before calling this.
    #[must_use]
    pub fn handle_set_log_level(&self, req: SetLogLevelRequest) -> Response {
        let levels = match self.log_levels() {
            Ok(levels) => levels,
            Err(e) => return e,
        };
        if let Some(f) = &req.filter
            && let Err(error) = f.check_duration(req.duration_secs)
        {
            return Response::Rejected { error };
        }
        match (req.filter, req.duration_secs) {
            (None, Some(_)) => {
                return Response::Rejected {
                    error: "a time limit needs a filter".into(),
                };
            }
            (Some(f), Some(secs)) => levels.set_for(f, Duration::from_secs(secs)),
            (filter, None) => {
                levels.save(filter.clone());
                let _ =
                    self.ctx
                        .bus()
                        .publish(LanforgeEvent::System(SystemEvent::LogFilterSaved {
                            filter,
                        }));
            }
        }
        Response::LogLevel(Box::new(levels.status()))
    }
}
