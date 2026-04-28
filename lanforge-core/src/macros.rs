/// DSL macro to simplify matching on Lanforge events from a `TimedEvent`.
///
/// This macro extracts the `.event` field and performs a match, automatically
/// handling the default case (ignoring other events).
/// Supports attributes (like `#[cfg]`) on individual arms.
#[macro_export]
macro_rules! match_event {
    ($timed_event:expr, { $( $(#[$attr:meta])* $variant:pat => $action:expr $(,)? )* }) => {
        match $timed_event.event {
            $( $(#[$attr])* $variant => $action, )*
            _ => {}
        }
    };
}

/// DSL macro to simplify subscribing to and handling events from the Lanforge event bus.
///
/// This macro handles:
/// - Subscribing to the provided bus.
/// - Spawning a background `tokio` task.
/// - Recv loop that automatically handles `RecvError`.
/// - Pattern matching on the specific `LanforgeEvent` variants using `match_event!`.
#[macro_export]
macro_rules! spawn_event_listener {
    ($bus:expr, { $( $(#[$attr:meta])* $variant:pat => $action:expr $(,)? )* }) => {
        let mut rx = $bus.subscribe();
        tokio::spawn(async move {
            while let Ok(timed_event) = rx.recv().await {
                $crate::match_event!(timed_event, {
                    $( $(#[$attr])* $variant => $action )*
                });
            }
        });
    };
}

/// DSL macro to simplify service registration and spawning.
///
/// Handles:
/// - Conditional spawning (`if condition`).
/// - Explicit cloning of shared variables (`[ctx, var1, ...]`).
/// - Dispatching to `spawn_async` or `spawn_sync`.
/// - Supports attributes (like `#[cfg]`) on individual services.
///
/// # Example
///
/// ```rust,ignore
/// spawn_services!(self.registry, &self.ctx, {
///     async [ctx, db_url, log_db_url] => DbWorker::new(db_url, log_db_url, ctx),
///     #[cfg(feature = "extra")]
///     sync  [ctx] if cfg.dhcpv4_enabled => Dhcpv4Service::new(d4_cfg, ctx),
/// });
/// ```
#[macro_export]
macro_rules! spawn_services {
    ($registry:expr, $ctx_ref:expr, {
        $( $(#[$attr:meta])* $kind:ident $( [ $($clone:ident),* ] )? $( if $cond:expr )? => $ctor:expr ),* $(,)?
    }) => {
        $(
            $(#[$attr])*
            {
                let mut run = true;
                $( run = $cond; )?
                if run {
                    $( $( let $clone = $clone.clone(); )* )?
                    $crate::spawn_one!($registry, $ctx_ref, $kind, $ctor, $($($clone),*)?);
                }
            }
        )*
    };
}

/// Internal helper for `spawn_services!`. Do not use directly.
#[macro_export]
macro_rules! spawn_one {
    ($registry:expr, $ctx_ref:expr, async, $ctor:expr, $($clone:ident),*) => {
        $registry.spawn_async($ctx_ref, move || {
            $( let $clone = $clone.clone(); )*
            $ctor
        })
    };
    ($registry:expr, $ctx_ref:expr, sync, $ctor:expr, $($clone:ident),*) => {
        $registry.spawn_sync($ctx_ref, move || {
            $( let $clone = $clone.clone(); )*
            $ctor
        })
    };
}
