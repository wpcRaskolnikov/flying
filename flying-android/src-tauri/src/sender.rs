use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::Emitter;
use tokio::sync::Mutex;

#[cfg(target_os = "android")]
use tauri_plugin_android_fs::{AndroidFsExt, Entry, FileUri};

use crate::TransferState;

// Structure to hold file information from Android URI
#[cfg(target_os = "android")]
struct AndroidFileEntry {
    uri: FileUri,
    relative_path: String,
    size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionMode {
    Listen,
    Connect,
}

impl ConnectionMode {
    pub fn to_flying_mode(&self, connect_ip: Option<String>) -> flying::ConnectionMode {
        match self {
            ConnectionMode::Listen => flying::ConnectionMode::Listen,
            ConnectionMode::Connect => {
                flying::ConnectionMode::Connect(connect_ip.unwrap_or_default())
            }
        }
    }
}

#[tauri::command]
pub async fn cancel_send(state: tauri::State<'_, Arc<Mutex<TransferState>>>) -> Result<(), String> {
    let mut transfer_state = state.lock().await;
    if let Some(abort_sender) = transfer_state.send_abort_handle.take() {
        let _ = abort_sender.send(());
        Ok(())
    } else {
        Err("No active send transfer to cancel".to_string())
    }
}

#[tauri::command]
pub async fn send_file(
    file_uri: String,
    password: String,
    connection_mode: ConnectionMode,
    connect_ip: Option<String>,
    port: u16,
    app: tauri::AppHandle,
    window: tauri::Window,
    state: tauri::State<', Arc<Mutex<TransferState>>>,
) -> Result<(), String> {
    let mode = connection_mode.to_flying_mode(connect_ip);

    let (abort_handle, abort_registration) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        let _ = window.emit("send-start", serde_json::json!({}));

        #[cfg(target_os = "android")]
        let result: Result<(), String> = async {
            use tauri_plugin_android_fs::{AndroidFsExt, FileUri};

            let api = _app.android_fs_async();
            let uri = FileUri::from_json_str(&file_uri)
                .map_err(|e| format!("Failed to parse URI: {}", e))?;

            let metadata = api
                .get_metadata(&uri)
                .await
                .map_err(|e| format!("Failed to get metadata: {}", e))?;

            if metadata.is_dir() {
                let folder_name = api
                    .get_name(&uri)
                    .await
                    .map_err(|e| format!("Failed to get folder name: {}", e))?;

                let files = collect_android_files(&_app, &uri, "".to_string())
                    .await
                    .map_err(|e| format!("Failed to collect files: {}", e))?;

                if files.is_empty() {
                    return Err("No files found in folder".to_string());
                }

                let (progress_tx, mut progress_rx) = tokio::sync::mpsc::channel(32);
                let window_clone = window.clone();

                tokio::spawn(async move {
                    while let Some(percent) = progress_rx.recv().await {
                        let _ = window_clone.emit("send-progress", percent);
                    }
                });

                tokio::select! {
                    _ = abort_registration => {
                        Err("Transfer cancelled".to_string())
                    }
                    result = send_android_folder(
                        &_app,
                        files,
                        &folder_name,
                        &password,
                        mode,
                        port,
                        Some(progress_tx)
                    ) => {
                        result.map_err(|e| format!("Send error: {}", e))
                    }
                }
            } else {
                // Handle single file
                let file_name = api
                    .get_name(&uri)
                    .await
                    .map_err(|e| format!("Failed to get file name: {}", e))?;

                let source_file = api
                    .open_file_readable(&uri)
                    .await
                    .map_err(|e| format!("Failed to open file: {}", e))?;

                let file_size = api
                    .get_metadata(&uri)
                    .await
                    .map_err(|e| format!("Failed to get file size: {}", e))?
                    .len();

                let (progress_tx, mut progress_rx) = tokio::sync::mpsc::channel(32);
                let window_clone = window.clone();

                tokio::spawn(async move {
                    while let Some(percent) = progress_rx.recv().await {
                        let _ = window_clone.emit("send-progress", percent);
                    }
                });

                tokio::select! {
                    _ = abort_registration => {
                        Err("Transfer cancelled".to_string())
                    }
                    result = flying::run_sender_from_handle(
                        vec![flying::FileHandle {
                            file: source_file,
                            path: file_name,
                            size: file_size,
                        }],
                        None,
                        &password,
                        mode,
                        port,
                        Some(progress_tx)
                    ) => {
                        result.map_err(|e| format!("Send error: {}", e))
                    }
                }
            }
        }
        .await;

        #[cfg(not(target_os = "android"))]
        let result: Result<(), String> = async {
            let file_path = std::path::PathBuf::from(&file_uri);

            let (progress_tx, mut progress_rx) = tokio::sync::mpsc::channel(32);
            let window_clone = window.clone();

            tokio::spawn(async move {
                while let Some(percent) = progress_rx.recv().await {
                    let _ = window_clone.emit("send-progress", percent);
                }
            });

            tokio::select! {
                _ = abort_registration => {
                    Err("Transfer cancelled".to_string())
                }
                result = flying::run_sender(&file_path, &password, mode, false, port, Some(progress_tx)) => {
                    result.map_err(|e| format!("Send error: {}", e))
                }
            }
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

    let mut transfer_state = state.lock().await;
    transfer_state.send_abort_handle = Some(abort_handle);

    Ok(())
}

#[cfg(target_os = "android")]
async fn collect_android_files(
    app: &tauri::AppHandle,
    dir_uri: &FileUri,
    current_path: String,
) -> Result<Vec<AndroidFileEntry>, String> {
    let api = app.android_fs_async();
    let mut files = Vec::new();

    let entries = api
        .read_dir(dir_uri)
        .await
        .map_err(|e| format!("Failed to read directory: {}", e))?;

    for entry in entries {
        match entry {
            Entry::File { uri, name, len, .. } => {
                let relative_path = if current_path.is_empty() {
                    name
                } else {
                    format!("{}/{}", current_path, name)
                };
                files.push(AndroidFileEntry {
                    uri,
                    relative_path,
                    size: len,
                });
            }
            Entry::Dir { uri, name, .. } => {
                let sub_path = if current_path.is_empty() {
                    name
                } else {
                    format!("{}/{}", current_path, name)
                };
                let mut sub_files = Box::pin(collect_android_files(app, &uri, sub_path)).await?;
                files.append(&mut sub_files);
            }
        }
    }

    Ok(files)
}

// Send folder from Android using the flying protocol
#[cfg(target_os = "android")]
async fn send_android_folder(
    app: &tauri::AppHandle,
    files: Vec<AndroidFileEntry>,
    folder_name: &str,
    password: &str,
    mode: flying::ConnectionMode,
    port: u16,
    progress_tx: Option<tokio::sync::mpsc::Sender<u8>>,
) -> Result<(), String> {
    let api = app.android_fs_async();

    // Open all files and prepare them for sending
    let mut file_handles = Vec::new();

    for file_entry in files {
        let std_file = api
            .open_file_readable(&file_entry.uri)
            .await
            .map_err(|e| format!("Failed to open file {}: {}", file_entry.relative_path, e))?;

        file_handles.push(flying::FileHandle {
            file: std_file,
            path: file_entry.relative_path,
            size: file_entry.size,
        });
    }

    // Use flying's run_sender_from_handle which handles everything
    flying::run_sender_from_handle(
        file_handles,
        Some(folder_name),
        password,
        mode,
        port,
        progress_tx,
    )
    .await
    .map_err(|e| format!("Send error: {}", e))
}
