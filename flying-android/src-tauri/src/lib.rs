mod collab_server;
mod discovery;
mod file_picker;
mod receiver;
mod room_manager;
mod sender;
mod utils;

use std::sync::{Arc, Mutex as StdMutex};

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
    pub room_manager: Arc<room_manager::RoomManager>,
    pub abort_handle: StdMutex<Option<tokio::sync::oneshot::Sender<()>>>,
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
