use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tauri::Emitter;

fn resolve_android_content_uri(uri: &str) -> Result<PathBuf, String> {
    if uri.starts_with("content://") {
        // Extract path from content URI
        // content://...document/primary%3ADownload%2Ftest%2F100
        if let Some(path_part) = uri.split("primary%3A").nth(1) {
            // Manual URL decode: replace %2F with / and %3A with :
            let decoded = path_part.replace("%2F", "/").replace("%3A", ":");
            let path = PathBuf::from(format!("/storage/emulated/0/{}", decoded));
            return Ok(path);
        }
        Err(format!("Unsupported content URI format: {}", uri))
    } else {
        Ok(PathBuf::from(uri))
    }
}

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
async fn send_file(
    file_path: String,
    password: String,
    connection_mode: ConnectionMode,
    connect_ip: Option<String>,
    window: tauri::Window,
) -> Result<(), String> {
    let path = resolve_android_content_uri(&file_path)?;
    if !path.exists() {
        return Err(format!(
            "File does not exist: {} (resolved from: {})",
            path.display(),
            file_path
        ));
    }

    let mode = connection_mode.to_flying_mode(connect_ip);

    tokio::spawn(async move {
        // Emit start event
        let _ = window.emit("send-start", serde_json::json!({}));

        let result = flying::run_sender(&path, &password, mode, false, false).await;

        match result {
            Ok(_) => {
                let _ = window.emit("send-complete", serde_json::json!({}));
            }
            Err(e) => {
                let _ = window.emit("send-error", format!("Send error: {}", e));
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
        .invoke_handler(tauri::generate_handler![
            generate_password,
            get_download_dir,
            discover_hosts,
            send_file,
            receive_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
