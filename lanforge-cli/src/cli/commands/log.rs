use super::CliCommand;
use chrono::DateTime;
use chrono::Local;
use color_eyre::eyre::Result;
use colored::Colorize;
use lanforge_api::api::Response;
use lanforge_api::api::SimpleSuccess;
use lanforge_api::api::{Command as ControlCommand, CommandAction};
use lanforge_core::bus::TimedEvent;

use crate::format::CliFormat;

pub struct LogHandler {
    pub follow: bool,
    pub verbose: bool,
    pub lines: usize,
}

impl CliCommand for LogHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        Ok(ControlCommand::new(CommandAction::Log {
            follow: self.follow,
            n: Some(self.lines),
        }))
    }

    fn on_response(&self, response: &Response) -> Result<Option<ControlCommand>> {
        match response {
            Response::Success(SimpleSuccess { message }) => {
                println!("{} {}", "i".blue(), message.italic());
            }
            Response::Error { error } => {
                eprintln!("{} {}", "✘".red().bold(), error);
            }
            Response::Event(event) => self.print_event(event),
            _ => {} // Ignore other responses in log stream
        }
        Ok(None)
    }

    fn is_streaming(&self) -> bool {
        // We always return true because even if follow is false,
        // we expect the daemon to stream historical entries.
        true
    }
}

impl LogHandler {
    fn print_event(&self, timed_event: &TimedEvent) {
        let now = DateTime::<Local>::from(timed_event.timestamp)
            .format("%H:%M:%S")
            .to_string();

        timed_event
            .event
            .format_cli(&now.dimmed().to_string(), self.verbose);
    }
}
