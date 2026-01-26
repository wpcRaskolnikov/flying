mod discovery;
mod file_picker;
mod receiver;
mod sender;

use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Default)]
pub struct TransferState {
    pub send_abort_handle: Option<tokio::sync::oneshot::Sender<()>>,
    pub receive_abort_handle: Option<tokio::sync::oneshot::Sender<()>>,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let transfer_state = Arc::new(Mutex::new(TransferState::default()));

    tauri::Builder::default()
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_android_fs::init())
        .manage(transfer_state)
        .invoke_handler(tauri::generate_handler![
            discovery::generate_password,
            discovery::discover_hosts,
            file_picker::pick_file,
            file_picker::pick_folder,
            sender::send_file,
            sender::cancel_send,
            receiver::receive_file,
            receiver::cancel_receive,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
