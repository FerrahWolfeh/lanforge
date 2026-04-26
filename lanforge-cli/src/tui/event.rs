use crossterm::event::KeyEvent;
use lanforge_api::api::StatusResponse;
use lanforge_core::bus::TimedEvent;
use lanforge_core::context::state::State;

pub enum AppEvent {
    Key(KeyEvent),
    DaemonEvent(TimedEvent),
    StatusUpdate(Box<StatusResponse>),
    StateUpdate(Box<State>),
    Tick,
}
