//! `lanforge config backup` / `restore`: the daemon serves the plain bundle (the CLI seals and
//! opens it, so the password never reaches the daemon) and restores one through the file forms.

use std::collections::BTreeMap;
use std::net::IpAddr;

use lanforge_api::api::{BackupBundle, BackupDevice, Response, SimpleSuccess};
use lanforge_core::bus::LanforgeEvent;
use lanforge_db_core::{DbError, Stores};
use lanforge_types::device::Origin;
use lanforge_types::events::StorageEvent;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::update::DeviceUpdate;
use tracing::info;

use crate::ClientContext;

impl ClientContext {
    /// The files of the config directory plus the state an admin cannot recreate from them.
    pub async fn handle_backup(&self) -> Response {
        let Some(path) = self.resolve_config_path() else {
            return Response::NotFound {
                error: "no configuration file to back up".to_string(),
            };
        };
        let files = match BackupBundle::read_files(&path) {
            Ok(files) => files,
            Err(e) => {
                return Response::Error {
                    error: format!("cannot read the configuration from {}: {e}", path.display()),
                };
            }
        };
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service handle is not available".to_string(),
            };
        };
        let (users, api_tokens) = match storage
            .call(|s: &Stores| {
                Ok::<_, DbError>((s.auth().list_users()?, s.auth().load_api_tokens()?))
            })
            .await
        {
            Ok(auth) => auth,
            Err(e) => {
                return Response::Error {
                    error: format!("Database error: {e}"),
                };
            }
        };
        let mut devices: Vec<BackupDevice> = self.ctx.with_state(|state| {
            state
                .devices
                .values()
                .filter_map(|d| BackupDevice::from_device(d))
                .collect()
        });
        devices.sort_by_key(|d| d.mac);
        Response::Backup(Box::new(BackupBundle {
            files,
            users,
            api_tokens,
            devices,
            name_bindings: self.ctx.name_bindings().into_iter().collect(),
            linked_addresses: self.ctx.linked_addresses().into_iter().collect(),
        }))
    }

    /// Restores `bundle`. Everything is checked first and nothing is written when anything is
    /// refused. Otherwise the files are written, users and tokens are replaced (a restore is
    /// the truth), the configuration is reloaded in place and the device settings are applied.
    pub async fn handle_restore(&self, bundle: BackupBundle) -> Response {
        let issues = bundle.issues();
        if !issues.is_empty() {
            return Response::Rejected {
                error: format!("backup refused, nothing restored: {}", issues.join("; ")),
            };
        }
        let Some(path) = self.writable_config_path() else {
            return Response::Rejected {
                error: "the configuration file is read-only or missing: nothing restored"
                    .to_string(),
            };
        };
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service handle is not available".to_string(),
            };
        };

        {
            let _serial = self.ctx.config_change_lock();
            let _file_guard = self.ctx.config_file_lock();
            if let Err(e) = bundle.write_files(&path) {
                return Response::Error {
                    error: format!("cannot write the configuration to {}: {e}", path.display()),
                };
            }
        }
        let BackupBundle {
            users,
            api_tokens,
            devices,
            name_bindings,
            linked_addresses,
            ..
        } = bundle;
        let (user_count, token_count) = (users.len(), api_tokens.len());
        if let Err(e) = storage
            .call(move |s: &Stores| s.auth().replace_auth(&users, &api_tokens))
            .await
        {
            return Response::Error {
                error: format!("files restored, but users and tokens were not: {e}"),
            };
        }

        let reloaded = self.handle_reload().await;
        if !matches!(reloaded, Response::Success(_)) {
            return reloaded;
        }
        let device_count = devices.len();
        self.restore_device_state(&devices, name_bindings, linked_addresses);
        let _ = self.flush_now().await;
        info!(user_count, token_count, device_count, "Backup restored");
        Response::Success(SimpleSuccess {
            message: format!(
                "Backup restored and reloaded in place: {user_count} user(s), {token_count} API token(s), {device_count} device(s)"
            ),
        })
    }

    /// Puts the hand-made device settings, the name bindings and the linked addresses of a
    /// backup into the live state (the db worker persists them).
    fn restore_device_state(
        &self,
        devices: &[BackupDevice],
        name_bindings: Vec<(String, MacAddr)>,
        linked_addresses: Vec<(IpAddr, MacAddr)>,
    ) {
        for device in devices {
            let origin = self
                .ctx
                .get_device(&device.mac)
                .map_or(Origin::Dynamic, |d| d.origin);
            if origin == Origin::System {
                continue;
            }
            let mac = device.mac;
            let _ = self.ctx.apply(DeviceUpdate::CliHostUpdated {
                mac,
                update: Box::new(device.to_update(origin)),
            });
            let _ = self.ctx.apply(DeviceUpdate::IgnoreDnsLogSet {
                mac,
                ignore: device.ignore_dns_log,
            });
            let _ = self.ctx.apply(DeviceUpdate::IgnoredLogDomainsSet {
                mac,
                domains: device.ignored_log_domains.clone(),
            });
        }
        let mut links: BTreeMap<_, Vec<IpAddr>> = BTreeMap::new();
        for (ip, mac) in linked_addresses {
            links.entry(mac).or_default().push(ip);
        }
        for (mac, addresses) in links {
            let _ = self
                .ctx
                .apply(DeviceUpdate::LinkedAddressesSet { mac, addresses });
        }
        let mut bindings = self.ctx.name_bindings();
        bindings.extend(name_bindings);
        self.ctx.restore_name_bindings(bindings);
        // Drops the bindings the restored configuration no longer references; saved either way.
        self.ctx.refresh_name_references();
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Storage(StorageEvent::NameBindingsChanged));
    }
}
