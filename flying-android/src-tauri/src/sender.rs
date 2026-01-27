use crate::TransferState;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::Emitter;
use tokio::sync::Mutex;

#[cfg(target_os = "android")]
use {
    tauri_plugin_android_fs::{AndroidFsExt, Entry, FileUri},
    tokio::{io::AsyncWriteExt, sync::mpsc::Sender},
};

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
    _app: tauri::AppHandle,
    window: tauri::Window,
    state: tauri::State<'_, Arc<Mutex<TransferState>>>,
) -> Result<(), String> {
    let mode = connection_mode.to_flying_mode(connect_ip);

    let (abort_handle, abort_registration) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        let _ = window.emit("send-start", serde_json::json!({}));

        #[cfg(target_os = "android")]
        let result: Result<(), String> = async {
            let uri = FileUri::from_json_str(&file_uri)
                .map_err(|e| format!("Failed to parse URI: {}", e))?;

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
                result = run_send_android(
                    &_app,
                    &uri,
                    &password,
                    mode,
                    port,
                    Some(progress_tx)
                ) => {
                    result
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
                result = flying::run_sender(&file_path, &password, mode, port, Some(progress_tx)) => {
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
async fn run_send_android(
    app: &tauri::AppHandle,
    uri: &FileUri,
    password: &str,
    mode: flying::ConnectionMode,
    port: u16,
    progress_tx: Option<Sender<u8>>,
) -> Result<(), String> {
    let api = app.android_fs_async();

    let metadata = api
        .get_metadata(uri)
        .await
        .map_err(|e| format!("Failed to get metadata: {}", e))?;

    if metadata.is_dir() {
        send_folder_android(app, uri, password, mode, port, progress_tx).await
    } else {
        send_file_android(app, uri, password, mode, port, progress_tx).await
    }
}

#[cfg(target_os = "android")]
async fn send_file_android(
    app: &tauri::AppHandle,
    uri: &FileUri,
    password: &str,
    mode: flying::ConnectionMode,
    port: u16,
    progress_tx: Option<Sender<u8>>,
) -> Result<(), String> {
    let api = app.android_fs_async();

    let file_name = api
        .get_name(uri)
        .await
        .map_err(|e| format!("Failed to get file name: {}", e))?;

    let source_file = api
        .open_file_readable(uri)
        .await
        .map_err(|e| format!("Failed to open file: {}", e))?;

    let file_size = api
        .get_metadata(uri)
        .await
        .map_err(|e| format!("Failed to get file size: {}", e))?
        .len();

    let (mut stream, _mdns_daemon) = flying::establish_connection(&mode, port)
        .await
        .map_err(|e| format!("Failed to establish connection: {}", e))?;

    // Send handshake
    let key = flying::utils::send_handshake(
        &mut stream,
        flying::VERSION,
        password,
        &file_name,
        false, // is_folder = false for single file
    )
    .await
    .map_err(|e| format!("Handshake failed: {}", e))?;

    let mut tokio_file = tokio::fs::File::from_std(source_file);
    flying::send::send_metadata(&mut stream, &file_name, file_size)
        .await
        .map_err(|e| format!("Failed to send metadata: {}", e))?;

    let is_duplicate = flying::send::check_duplicate(&mut stream, &mut tokio_file)
        .await
        .map_err(|e| format!("Failed to check duplicate: {}", e))?;
    if !is_duplicate {
        flying::send::encrypt_and_send(&mut stream, tokio_file, file_size, &key, progress_tx)
            .await
            .map_err(|e| format!("Failed to send file: {}", e))?;
    }

    stream
        .shutdown()
        .await
        .map_err(|e| format!("Failed to shutdown stream: {}", e))?;

    if let Some(mdns_daemon) = _mdns_daemon {
        let _ = mdns_daemon.shutdown();
    }

    Ok(())
}

#[cfg(target_os = "android")]
async fn send_folder_android(
    app: &tauri::AppHandle,
    uri: &FileUri,
    password: &str,
    mode: flying::ConnectionMode,
    port: u16,
    progress_tx: Option<tokio::sync::mpsc::Sender<u8>>,
) -> Result<(), String> {
    let api = app.android_fs_async();

    let folder_name = api
        .get_name(uri)
        .await
        .map_err(|e| format!("Failed to get folder name: {}", e))?;

    let (mut stream, _mdns_daemon) = flying::establish_connection(&mode, port)
        .await
        .map_err(|e| format!("Failed to establish connection: {}", e))?;

    let key =
        flying::utils::send_handshake(&mut stream, flying::VERSION, password, &folder_name, true)
            .await
            .map_err(|e| format!("Handshake failed: {}", e))?;

    // Recursive send function
    async fn send_recursive(
        app: &tauri::AppHandle,
        stream: &mut tokio::net::TcpStream,
        dir_uri: &FileUri,
        base_path: &str,
        key: &ring::aead::LessSafeKey,
        progress_tx: &Option<tokio::sync::mpsc::Sender<u8>>,
    ) -> Result<(), String> {
        let api = app.android_fs_async();

        let entries = api
            .read_dir(dir_uri)
            .await
            .map_err(|e| format!("Failed to read directory: {}", e))?;
        for entry in entries {
            match entry {
                Entry::File { uri, name, len, .. } => {
                    let relative_path = if base_path.is_empty() {
                        name
                    } else {
                        format!("{}/{}", base_path, name)
                    };

                    flying::send::send_metadata(stream, &relative_path, len)
                        .await
                        .map_err(|e| format!("Failed to send metadata: {}", e))?;

                    let file = api
                        .open_file_readable(&uri)
                        .await
                        .map_err(|e| format!("Failed to open file {}: {}", relative_path, e))?;
                    let tokio_file = tokio::fs::File::from_std(file);

                    flying::send::encrypt_and_send(
                        stream,
                        tokio_file,
                        len,
                        key,
                        progress_tx.clone(),
                    )
                    .await
                    .map_err(|e| format!("Failed to send file {}: {}", relative_path, e))?;
                }
                Entry::Dir { uri, name, .. } => {
                    let sub_path = if base_path.is_empty() {
                        name
                    } else {
                        format!("{}/{}", base_path, name)
                    };

                    Box::pin(send_recursive(
                        app,
                        stream,
                        &uri,
                        &sub_path,
                        key,
                        progress_tx,
                    ))
                    .await?;
                }
            }
        }

        Ok(())
    }

    send_recursive(app, &mut stream, uri, "", &key, &progress_tx).await?;

    // Send end signal
    stream
        .write_u64(0)
        .await
        .map_err(|e| format!("Failed to send end signal: {}", e))?;

    stream
        .shutdown()
        .await
        .map_err(|e| format!("Failed to shutdown stream: {}", e))?;

    if let Some(mdns_daemon) = _mdns_daemon {
        let _ = mdns_daemon.shutdown();
    }

    Ok(())
}
