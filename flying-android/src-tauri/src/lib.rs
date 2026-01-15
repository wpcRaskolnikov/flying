use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tauri::Emitter;
use tauri_plugin_android_fs::{AndroidFsExt, FileUri};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ConnectionMode {
    Listen,
    Connect,
}

impl ConnectionMode {
    fn to_flying_mode(&self, connect_ip: Option<String>) -> flying::ConnectionMode {
        match self {
            ConnectionMode::Listen => flying::ConnectionMode::Listen,
            ConnectionMode::Connect => {
                flying::ConnectionMode::Connect(connect_ip.unwrap_or_default())
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DiscoveredHost {
    name: String,
    ip: String,
}

#[tauri::command]
fn generate_password() -> Result<String, String> {
    Ok(flying::utils::generate_password())
}

#[tauri::command]
fn get_download_dir(_app: tauri::AppHandle) -> Result<String, String> {
    let path = PathBuf::from("/storage/emulated/0/Download");
    Ok(path.to_string_lossy().to_string())
}

#[tauri::command]
async fn pick_file_android(app: tauri::AppHandle) -> Result<Option<(String, String)>, String> {
    let api = app.android_fs_async();

    // Pick files to read
    let selected_files = api
        .file_picker()
        .pick_files(
            None,     // Initial location
            &["*/*"], // Target MIME types (all files)
            false,    // If true, only files on local device
        )
        .await
        .map_err(|e| format!("File picker error: {}", e))?;

    if selected_files.is_empty() {
        Ok(None)
    } else {
        let uri = selected_files[0].clone();
        let file_name = api
            .get_name(&uri)
            .await
            .map_err(|e| format!("Failed to get file name: {}", e))?;

        // Serialize FileUri to JSON string for passing to frontend
        let uri_json =
            serde_json::to_string(&uri).map_err(|e| format!("Failed to serialize URI: {}", e))?;

        Ok(Some((uri_json, file_name)))
    }
}

#[tauri::command]
async fn discover_hosts() -> Result<Vec<DiscoveredHost>, String> {
    // Run the blocking discovery in a separate task
    let services = tokio::task::spawn_blocking(|| {
        flying::mdns::discover_services(5).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))??;

    let discovered: Vec<DiscoveredHost> = services
        .into_iter()
        .map(|service| DiscoveredHost {
            name: service.hostname,
            ip: service.ip.to_string(),
        })
        .collect();

    Ok(discovered)
}

#[tauri::command]
async fn send_file_from_uri(
    file_uri: String,
    password: String,
    connection_mode: ConnectionMode,
    connect_ip: Option<String>,
    app: tauri::AppHandle,
    window: tauri::Window,
) -> Result<(), String> {
    let mode = connection_mode.to_flying_mode(connect_ip);

    tokio::spawn(async move {
        let _ = window.emit("send-start", serde_json::json!({}));

        let result: Result<(), String> = async {
            // Get Android FS API
            let api = app.android_fs_async();

            // Deserialize the URI JSON string back to FileUri
            let uri: FileUri = serde_json::from_str(&file_uri)
                .map_err(|e| format!("Failed to parse URI: {}", e))?;

            // Get file metadata
            let file_name = api
                .get_name(&uri)
                .await
                .map_err(|e| format!("Failed to get file name: {}", e))?;

            // Open file for reading
            let source_file = api
                .open_file_readable(&uri)
                .await
                .map_err(|e| format!("Failed to open file: {}", e))?;

            // Use the new run_sender_from_file function directly (no temp file needed!)
            flying::run_sender_from_file(source_file, &file_name, &password, mode, false)
                .await
                .map_err(|e| format!("Send error: {}", e))?;

            Ok(())
        }
        .await;

        match result {
            Ok(_) => {
                let _ = window.emit("send-complete", serde_json::json!({}));
            }
            Err(e) => {
                let _ = window.emit("send-error", e);
            }
        }
    });

    Ok(())
}

#[tauri::command]
async fn receive_file(
    password: String,
    connection_mode: ConnectionMode,
    connect_ip: Option<String>,
    window: tauri::Window,
) -> Result<(), String> {
    let download_dir = PathBuf::from("/storage/emulated/0/Download");

    let mode = connection_mode.to_flying_mode(connect_ip);

    tokio::spawn(async move {
        let _ = window.emit("receive-start", serde_json::json!({}));

        let result = flying::run_receiver(&download_dir, &password, mode).await;

        match result {
            Ok(_) => {
                let _ = window.emit("receive-complete", serde_json::json!({}));
            }
            Err(e) => {
                let _ = window.emit("receive-error", format!("Receive error: {}", e));
            }
        }
    });

    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_android_fs::init())
        .invoke_handler(tauri::generate_handler![
            generate_password,
            get_download_dir,
            discover_hosts,
            send_file_from_uri,
            pick_file_android,
            receive_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
