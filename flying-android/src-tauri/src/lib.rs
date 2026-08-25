mod collab_server;
mod discovery;
mod file_picker;
mod receiver;
mod sender;
mod utils;

use std::sync::{Arc, Mutex as StdMutex};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", tag = "status", content = "data")]
pub enum TransferStatus {
    Ready(String), //peer_id
    Processing(u8),
    Completed,
    Error(String),
}

#[derive(Default, Clone)]
pub struct SendState {
    pub abort_handle: Arc<StdMutex<Option<tokio::sync::oneshot::Sender<()>>>>,
}

#[derive(Default, Clone)]
pub struct ReceiveState {
    pub abort_handle: Arc<StdMutex<Option<tokio::sync::oneshot::Sender<()>>>>,
}

#[derive(Default)]
pub struct CollabServerState {
    pub room_manager: Arc<utils::RoomManager>,
    pub abort_handle: StdMutex<Option<tokio::sync::oneshot::Sender<()>>>,
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_android_fs::init())
        .manage(SendState::default())
        .manage(ReceiveState::default())
        .manage(CollabServerState::default())
        .invoke_handler(tauri::generate_handler![
            discovery::discover_hosts,
            file_picker::pick_file,
            file_picker::pick_folder,
            sender::send_file,
            sender::cancel_send,
            receiver::receive_file,
            receiver::cancel_receive,
            utils::generate_password,
            utils::get_default_folder,
            collab_server::start_collab_server,
            collab_server::stop_collab_server,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
