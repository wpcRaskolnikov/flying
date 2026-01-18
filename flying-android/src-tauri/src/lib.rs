use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tauri::Emitter;

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
#[cfg(target_os = "android")]
async fn pick_file(app: tauri::AppHandle) -> Result<Option<(String, String)>, String> {
    use tauri_plugin_android_fs::AndroidFsExt;
    let api = app.android_fs_async();

    // Pick files to read
    let uri = api
        .file_picker()
        .pick_file(
            None,     // Initial location
            &["*/*"], // Target MIME types (all files)
            false,    // If true, only files on local device
        )
        .await
        .map_err(|e| format!("File picker error: {}", e))?;

    let file_name = api
        .get_name(&uri)
        .await
        .map_err(|e| format!("Failed to get file name: {}", e))?;

    let uri_json = uri
        .to_json_string()
        .map_err(|e| format!("Failed to serialize URI: {}", e))?;

    Ok(Some((uri_json, file_name)))
}

#[tauri::command]
#[cfg(not(target_os = "android"))]
async fn pick_file(app: tauri::AppHandle) -> Result<Option<(String, String)>, String> {
    use tauri_plugin_dialog::DialogExt;
    let Some(tauri_plugin_dialog::FilePath::Path(file)) = app.dialog().file().blocking_pick_file()
    else {
        return Ok(None);
    };
    let file_path = file.to_string_lossy().to_string();

    let file_name = file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Invalid file name")?
        .to_string();

    Ok(Some((file_path, file_name)))
}

#[tauri::command]
#[cfg(target_os = "android")]
async fn pick_folder(app: tauri::AppHandle) -> Result<Option<(String, String)>, String> {
    use tauri_plugin_android_fs::AndroidFsExt;
    let api = app.android_fs_async();

    let uri = api
        .file_picker()
        .pick_dir(None, false)
        .await
        .map_err(|e| format!("dir picker error: {}", e))?;

    let file_name = api
        .get_name(&uri)
        .await
        .map_err(|e| format!("Failed to get file name: {}", e))?;

    let uri_json = uri
        .to_json_string()
        .map_err(|e| format!("Failed to serialize URI: {}", e))?;

    Ok(Some((uri_json, file_name)))
}

#[tauri::command]
#[cfg(not(target_os = "android"))]
async fn pick_folder(app: tauri::AppHandle) -> Result<Option<(String, String)>, String> {
    use tauri_plugin_dialog::DialogExt;
    let Some(tauri_plugin_dialog::FilePath::Path(file)) =
        app.dialog().file().blocking_pick_folder()
    else {
        return Ok(None);
    };
    let file_path = file.to_string_lossy().to_string();

    let file_name = file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Invalid file name")?
        .to_string();

    Ok(Some((file_path, file_name)))
}

#[tauri::command]
async fn discover_hosts() -> Result<Vec<DiscoveredHost>, String> {
    let services = tokio::task::spawn_blocking(|| {
        flying::mdns::discover_services(3).map_err(|e| e.to_string())
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
    window: tauri::Window,
) -> Result<(), String> {
    let mode = connection_mode.to_flying_mode(connect_ip);

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create local runtime");

        rt.block_on(async {
            let _ = window.emit("send-start", serde_json::json!({}));

            #[cfg(target_os = "android")]
            let result: Result<(), String> = async {
                use tauri_plugin_android_fs::FileUri;

                let api = app.android_fs_async();
                let uri = FileUri::from_json_str(&file_uri)
                    .map_err(|e| format!("Failed to parse URI: {}", e))?;
                let file_name = api
                    .get_name(&uri)
                    .await
                    .map_err(|e| format!("Failed to get file name: {}", e))?;
                let source_file = api
                    .open_file_readable(&uri)
                    .await
                    .map_err(|e| format!("Failed to open file: {}", e))?;
                flying::run_sender_from_handle(source_file, &file_name, &password, mode)
                    .await
                    .map_err(|e| format!("Send error: {}", e))?;
                Ok(())
            }
            .await;

            #[cfg(not(target_os = "android"))]
            let result: Result<(), String> = async {
                let file_path = std::path::PathBuf::from(&file_uri);
                flying::run_sender(&file_path, &password, mode, false)
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
            discover_hosts,
            send_file_from_uri,
            pick_file,
            pick_folder,
            receive_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
