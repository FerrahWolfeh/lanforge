//! A value deserialized from an empty object must equal the type's `Default`: every
//! `#[serde(default = "...")]` has to agree with the hand-written `Default` impl, or a config built
//! in code and one read from storage/API without the field silently differ (the
//! `deprecate_on_renumber` class).

use lanforge_types::network::ra::RaServerConfig;
use lanforge_types::network::traffic::{NicTuningConfig, SqmConfig, TrafficConfig};
use lanforge_types::system::{SetupPppoeNftables, SetupRaConfig};
use serde::de::DeserializeOwned;
use std::fmt::Debug;

fn check<T: DeserializeOwned + Default + PartialEq + Debug>(name: &str, errors: &mut Vec<String>) {
    match serde_json::from_str::<T>("{}") {
        Ok(empty) if empty == T::default() => {}
        Ok(empty) => errors.push(format!(
            "{name}:\n  empty:   {empty:?}\n  default: {:?}",
            T::default()
        )),
        Err(e) => errors.push(format!("{name}: `{{}}` does not deserialize: {e}")),
    }
}

#[test]
fn empty_objects_equal_defaults() {
    let mut errors = Vec::new();
    check::<TrafficConfig>("TrafficConfig", &mut errors);
    check::<NicTuningConfig>("NicTuningConfig", &mut errors);
    check::<SqmConfig>("SqmConfig", &mut errors);
    check::<SetupRaConfig>("SetupRaConfig", &mut errors);
    check::<SetupPppoeNftables>("SetupPppoeNftables", &mut errors);
    check::<RaServerConfig>("RaServerConfig", &mut errors);
    assert!(errors.is_empty(), "\n{}", errors.join("\n"));
}
