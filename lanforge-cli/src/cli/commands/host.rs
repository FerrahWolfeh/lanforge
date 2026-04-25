use super::CliCommand;
use crate::args::HostCommand;
use color_eyre::Result;
use color_eyre::eyre::bail;
use inquire::{Confirm, Select, Text as InquireText};
use iocraft::prelude::*;
use lanforge_api::api::{Command as ControlCommand, CommandAction, Response};

pub struct HostHandler {
    pub action: HostCommand,
}

impl CliCommand for HostHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        match &self.action {
            HostCommand::Add {
                mac,
                hostname,
                v4,
                v6_suffix,
            } => {
                let final_mac = if let Some(m) = mac {
                    m.clone()
                } else {
                    let ans = InquireText::new("MAC address:").prompt()?;
                    if ans.trim().is_empty() {
                        // user skipped, we probably want to return an error or a dummy command handled gracefully.
                        // Actually, if it's empty, returning an error exits early.
                        bail!("MAC address is required");
                    }
                    ans.trim().to_string()
                };

                let final_hostname = if let Some(h) = hostname {
                    h.clone()
                } else {
                    let ans = InquireText::new("Hostname:").prompt()?;
                    if ans.trim().is_empty() {
                        bail!("Hostname is required");
                    }
                    ans.trim().to_string()
                };

                let mut final_v4 = v4.clone();
                let mut final_v6 = v6_suffix.clone();

                if v4.is_none() && v6_suffix.is_none() {
                    let opts = vec![
                        "[1] Hostname only (dynamic IP from pool)",
                        "[2] Hostname + Fixed IPv4",
                        "[3] Hostname + Fixed IPv4 + ULA suffix",
                    ];
                    let choice = Select::new("Configuration level:", opts).prompt()?;
                    if choice.starts_with("[2]") || choice.starts_with("[3]") {
                        let ans = InquireText::new("Fixed IPv4:").prompt()?;
                        if !ans.trim().is_empty() {
                            final_v4 = Some(ans.trim().to_string());
                        }
                    }
                    if choice.starts_with("[3]") {
                        let ans = InquireText::new("ULA Suffix (ex: ::1234):").prompt()?;
                        if !ans.trim().is_empty() {
                            final_v6 = Some(ans.trim().to_string());
                        }
                    }

                    element! {
                        View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
                            View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                                Text(content: " CONFIRM ADDITION ", color: Color::White, weight: Weight::Bold)
                            }
                            View(flex_direction: FlexDirection::Column, border_style: BorderStyle::Round, border_color: Color::DarkGrey, padding_left: 2, padding_right: 2) {
                                SummaryLine(label: "MAC", value: final_mac.clone(), color: Color::Cyan)
                                SummaryLine(label: "Hostname", value: final_hostname.clone(), color: Color::Cyan)
                                #(final_v4.as_ref().map(|v| element! {
                                    SummaryLine(label: "Fixed IPv4", value: v.clone(), color: Color::Green)
                                }))
                                #(final_v6.as_ref().map(|v| element! {
                                    SummaryLine(label: "V6 Suffix", value: v.clone(), color: Color::Yellow)
                                }))
                            }
                        }
                    }.print();

                    let confirm = Confirm::new("Save host configuration?")
                        .with_default(true)
                        .prompt()?;
                    if !confirm {
                        bail!("Cancelled.");
                    }
                }

                Ok(ControlCommand::new(CommandAction::HostAdd {
                    mac: Some(final_mac),
                    hostname: Some(final_hostname),
                    v4: final_v4,
                    v6_suffix: final_v6,
                }))
            }
            HostCommand::Set { mac, field, value } => {
                Ok(ControlCommand::new(CommandAction::HostSet {
                    mac: mac.clone(),
                    field: field.clone(),
                    value: value.clone(),
                }))
            }
            HostCommand::Remove { mac } => Ok(ControlCommand::new(CommandAction::HostRemove {
                mac: mac.clone(),
            })),
            HostCommand::List => Ok(ControlCommand::new(CommandAction::HostList)),
        }
    }

    fn on_response(&self, response: &Response) -> Result<Option<ControlCommand>> {
        match response {
            Response::Hosts(resp) => {
                super::devices::render_hosts(resp);
            }
            Response::Error { error } => {
                element! {
                    View(padding_left: 2, margin_top: 1) {
                        Text(content: "✘ ", color: Color::Red)
                        Text(content: format!("Error: {error}"), color: Color::Red, weight: Weight::Bold)
                    }
                }.print();
            }
            Response::Success(success) => {
                element! {
                    View(padding_left: 2, margin_top: 1) {
                        Text(content: "✓ ", color: Color::Green)
                        Text(content: success.message.clone(), color: Color::Green, weight: Weight::Bold)
                    }
                }.print();
            }
            Response::Event(e) => {
                element! {
                    View(padding_left: 2, margin_top: 1) {
                        Text(content: "● ", color: Color::Yellow)
                        Text(content: format!("Event: {e:?}"), color: Color::Yellow)
                    }
                }
                .print();
            }
            _ => {
                println!("Unexpected response: {response:?}");
            }
        }
        Ok(None)
    }
}

#[component]
fn SummaryLine(props: &SummaryLineProps) -> impl Into<AnyElement<'_>> {
    element! {
        View(flex_direction: FlexDirection::Row) {
            Text(content: format!("{:<12}", props.label), color: Color::DarkGrey)
            Text(content: props.value.clone(), color: props.color)
        }
    }
}

#[derive(Props)]
struct SummaryLineProps {
    pub label: String,
    pub value: String,
    pub color: Color,
}

impl Default for SummaryLineProps {
    fn default() -> Self {
        Self {
            label: String::new(),
            value: String::new(),
            color: Color::White,
        }
    }
}
