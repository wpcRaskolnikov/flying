mod collab_server;
mod discovery;
mod file_picker;
mod receiver;
mod sender;
use std::sync::Mutex as StdMutex;
use tauri::Manager;
use tauri_plugin_store::StoreExt;

#[derive(Default, Clone)]
pub struct TransferState {
    pub abort_handle: std::sync::Arc<StdMutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    pub mdns_daemon: std::sync::Arc<StdMutex<Option<flying::mdns::ServiceDaemon>>>,
}

#[derive(Default)]
pub struct CollabServerState {
    pub store: std::sync::Arc<collab_server::RoomStore>,
    pub server_handle: StdMutex<Option<tokio::task::JoinHandle<()>>>,
    pub port: StdMutex<u16>,
    pub mdns_daemon: StdMutex<Option<flying::mdns::ServiceDaemon>>,
}

#[tauri::command]
fn get_default_folder(app: tauri::AppHandle) -> Result<String, String> {
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_android_fs::init())
        .manage(TransferState::default())
        .manage(CollabServerState::default())
        .invoke_handler(tauri::generate_handler![
            discovery::generate_password,
            discovery::discover_hosts,
            discovery::discover_collab_hosts,
            file_picker::pick_file,
            file_picker::pick_folder,
            sender::send_file,
            sender::cancel_send,
            receiver::receive_file,
            receiver::cancel_receive,
            get_default_folder,
            collab_server::start_collab_server,
            collab_server::stop_collab_server,
            collab_server::get_collab_server_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
