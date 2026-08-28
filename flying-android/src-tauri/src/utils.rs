#[cfg(not(target_os = "android"))]
use tauri::Manager;
use tauri_plugin_store::StoreExt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", tag = "status", content = "data")]
pub enum TransferStatus {
    Ready(String), //peer_id
    Processing(u8),
    Completed,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum ConnectionConfig {
    Listen,
    Connect { connect_ip: String },
    RelayListen { relay_addr: String },
    RelayDial { relay_addr: String, peer_id: String },
}

impl ConnectionConfig {
    pub fn to_flying_mode(&self) -> Result<flying::ConnectionMode, String> {
        match self {
            ConnectionConfig::Listen => Ok(flying::ConnectionMode::Listen),
            ConnectionConfig::Connect { connect_ip } => {
                let ip = connect_ip
                    .parse()
                    .map_err(|e| format!("Invalid IP address: {}", e))?;
                Ok(flying::ConnectionMode::Connect(ip))
            }
            ConnectionConfig::RelayListen { relay_addr } => {
                let multiaddr = relay_addr
                    .parse()
                    .map_err(|e| format!("Invalid multiaddr: {}", e))?;
                Ok(flying::ConnectionMode::RelayListen {
                    relay_addr: multiaddr,
                })
            }
            ConnectionConfig::RelayDial {
                relay_addr,
                peer_id,
            } => {
                let multiaddr = relay_addr
                    .parse()
                    .map_err(|e| format!("Invalid multiaddr: {}", e))?;
                let peer_id = peer_id
                    .parse()
                    .map_err(|e| format!("Invalid peer ID: {}", e))?;
                Ok(flying::ConnectionMode::RelayDial {
                    relay_addr: multiaddr,
                    remote_peer_id: peer_id,
                })
            }
        }
    }
}

#[tauri::command]
pub fn generate_password() -> Result<String, String> {
    Ok(flying::generate_password())
}

#[tauri::command]
pub fn get_default_folder(app: tauri::AppHandle) -> Result<String, String> {
    let store = app
        .store("settings.json")
        .map_err(|e| format!("Failed to load store: {}", e))?;

    #[cfg(target_os = "android")]
    let path = "/storage/emulated/0/Download".to_string();

    #[cfg(not(target_os = "android"))]
    let path = match store.get("default_folder_path") {
        Some(json_val) => json_val.as_str().unwrap_or("").to_string(),
        None => app
            .path()
            .download_dir()
            .map_err(|e| format!("Failed to get download directory:{}", e))?
            .to_string_lossy()
            .to_string(),
    };
    store.close_resource();
    Ok(path)
}
