mod discovery;
mod file_picker;
mod receiver;
mod sender;
use std::sync::Arc;
use tauri_plugin_store::StoreExt;
use tokio::sync::Mutex;

#[cfg(not(target_os = "android"))]
use tauri::Manager;

#[derive(Default)]
pub struct TransferState {
    pub send_abort_handle: Option<tokio::sync::oneshot::Sender<()>>,
    pub receive_abort_handle: Option<tokio::sync::oneshot::Sender<()>>,
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
            get_default_folder
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
