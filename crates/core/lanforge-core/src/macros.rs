/// DSL macro to simplify matching on Lanforge events from a `TimedEvent`.
///
/// This macro extracts the `.event` field and performs a match, automatically
/// handling the default case (ignoring other events).
/// Supports attributes (like `#[cfg]`) on individual arms.
#[macro_export]
macro_rules! match_event {
    ($timed_event:expr, { $( $(#[$attr:meta])* $variant:pat => $action:expr $(,)? )* }) => {
        match &$timed_event.event {
            $( $(#[$attr])* $variant => $action, )*
            _ => {}
        }
    };
}

