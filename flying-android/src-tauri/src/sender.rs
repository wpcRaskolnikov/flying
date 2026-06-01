use crate::utils::{TransferState, TransferStatusPayload};

use flying::mdns::ServiceDaemon;

use std::sync::Arc;

use tauri::Emitter;

use serde::{Deserialize, Serialize};

use tokio::sync::{mpsc, oneshot};

#[cfg(target_os = "android")]
use {
    tauri_plugin_android_fs::{AndroidFsExt, Entry, FileUri},
    tokio::fs::File as TokioFile,
    tokio::io::{AsyncReadExt, AsyncWriteExt},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ConnectionConfig {
    Listen,
    Connect {
        connect_ip: String,
    },
    RelayListen {
        relay_addr: String,
        peer_id: String,
    },
    RelayDial {
        relay_addr: String,
        remote_peer_id: String,
    },
}

impl ConnectionConfig {
    pub fn to_flying_mode(&self) -> Result<flying::ConnectionMode, String> {
        match self {
            ConnectionConfig::Listen => Ok(flying::ConnectionMode::Listen),
            ConnectionConfig::Connect { connect_ip } => {
                Ok(flying::ConnectionMode::Connect(connect_ip.clone()))
            }
            ConnectionConfig::RelayListen { relay_addr, .. } => {
                let multiaddr = relay_addr
                    .parse()
                    .map_err(|e| format!("Invalid multiaddr: {}", e))?;
                Ok(flying::ConnectionMode::RelayListen {
                    relay_addr: multiaddr,
                })
            }
            ConnectionConfig::RelayDial {
                relay_addr,
                remote_peer_id,
            } => {
                let multiaddr = relay_addr
                    .parse()
                    .map_err(|e| format!("Invalid multiaddr: {}", e))?;
                let peer_id = remote_peer_id
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

#[tauri::command]
pub async fn cancel_send(state: tauri::State<'_, TransferState>) -> Result<(), String> {
    if let Some(mdns) = state.mdns_daemon.lock().unwrap().take() {
        let _ = mdns.shutdown();
    }
    if let Some(abort_sender) = state.abort_handle.lock().unwrap().take() {
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
    config: ConnectionConfig,
    port: u16,
    _app: tauri::AppHandle,
    window: tauri::Window,
    state: tauri::State<'_, TransferState>,
) -> Result<(), String> {
    let mode = config.to_flying_mode()?;

    let (abort_handle, abort_registration) = oneshot::channel::<()>();
    let (mdns_tx, mdns_rx) = oneshot::channel::<ServiceDaemon>();
    let (peer_id_tx, mut peer_id_rx) = mpsc::channel(1);

    let mdns_daemon_mutex = Arc::clone(&state.mdns_daemon);
    tokio::spawn(async move {
        if let Ok(daemon) = mdns_rx.await {
            let mut state = mdns_daemon_mutex.lock().unwrap();
            *state = Some(daemon);
        }
    });

    tokio::spawn(async move {
        // Emit initial status and wait for connection if needed
        match &mode {
            flying::ConnectionMode::Listen => {
                // Emit Ready (waiting for peer to connect)
                let _ = window.emit(
                    "send-status-update",
                    TransferStatusPayload {
                        status: "Ready".to_string(),
                        progress: 0,
                        message: None,
                        peer_id: None,
                    },
                );
            }
            flying::ConnectionMode::RelayListen { .. }
            | flying::ConnectionMode::RelayDial { .. } => {
                if let Some(peer_id) = peer_id_rx.recv().await {
                    let _ = window.emit(
                        "send-status-update",
                        TransferStatusPayload {
                            status: "Ready".to_string(),
                            progress: 0,
                            message: None,
                            peer_id: Some(peer_id),
                        },
                    );
                }
                let _ = window.emit(
                    "send-status-update",
                    TransferStatusPayload {
                        status: "Sending".to_string(),
                        progress: 0,
                        message: None,
                        peer_id: None,
                    },
                );
            }
            _ => {
                let _ = window.emit(
                    "send-status-update",
                    TransferStatusPayload {
                        status: "Sending".to_string(),
                        progress: 0,
                        message: None,
                        peer_id: None,
                    },
                );
            }
        }

        #[cfg(target_os = "android")]
        let result: Result<(), String> = async {
            let uri = FileUri::from_json_str(&file_uri)
                .map_err(|e| format!("Failed to parse URI: {}", e))?;

            let (progress_tx, mut progress_rx) = mpsc::channel(32);
            let window_clone = window.clone();

            tokio::spawn(async move {
                while let Some(percent) = progress_rx.recv().await {
                    let _ = window_clone.emit(
                        "send-status-update",
                        TransferStatusPayload {
                            status: "Sending".to_string(),
                            progress: percent,
                            message: None,
                            peer_id: None,
                        },
                    );
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
                    Some(progress_tx),
                    Some(peer_id_tx),
                    Some(mdns_tx),
                ) => {
                    result
                }
            }
        }
        .await;

        #[cfg(not(target_os = "android"))]
        let result: Result<(), String> = async {
            let file_path = std::path::PathBuf::from(&file_uri);

            let (progress_tx, mut progress_rx) = mpsc::channel(32);
            let window_clone = window.clone();

            tokio::spawn(async move {
                while let Some(percent) = progress_rx.recv().await {
                    let _ = window_clone.emit(
                        "send-status-update",
                        TransferStatusPayload {
                            status: "Sending".to_string(),
                            progress: percent,
                            message: None,
                            peer_id: None,
                        },
                    );
                }
            });

            tokio::select! {
                _ = abort_registration => {
                    Err("Transfer cancelled".to_string())
                }
                result = flying::run_sender(&file_path, &password, mode, port, Some(progress_tx), Some(peer_id_tx), Some(mdns_tx)) => {
                    result.map_err(|e| format!("Send error: {}", e))
                }
            }
        }
        .await;

        match result {
            Ok(_) => {
                let _ = window.emit(
                    "send-status-update",
                    TransferStatusPayload {
                        status: "Completed".to_string(),
                        progress: 100,
                        message: None,
                        peer_id: None,
                    },
                );
            }
            Err(e) => {
                let _ = window.emit(
                    "send-status-update",
                    TransferStatusPayload {
                        status: "Error".to_string(),
                        progress: 0,
                        message: Some(e),
                        peer_id: None,
                    },
                );
            }
        }
    });

    *state.abort_handle.lock().unwrap() = Some(abort_handle);

    Ok(())
}

#[cfg(target_os = "android")]
async fn run_send_android(
    app: &tauri::AppHandle,
    uri: &FileUri,
    password: &str,
    mode: flying::ConnectionMode,
    port: u16,
    progress_tx: Option<mpsc::Sender<u8>>,
    peer_id_tx: Option<mpsc::Sender<String>>,
    mdns_tx: Option<oneshot::Sender<ServiceDaemon>>,
) -> Result<(), String> {
    let api = app.android_fs_async();

    let metadata = api
        .get_metadata(uri)
        .await
        .map_err(|e| format!("Failed to get metadata: {}", e))?;

    if metadata.is_dir() {
        send_folder_android(
            app,
            uri,
            password,
            mode,
            port,
            progress_tx,
            peer_id_tx,
            mdns_tx,
        )
        .await
    } else {
        send_file_android(
            app,
            uri,
            password,
            mode,
            port,
            progress_tx,
            peer_id_tx,
            mdns_tx,
        )
        .await
    }
}

#[cfg(target_os = "android")]
async fn send_file_android(
    app: &tauri::AppHandle,
    uri: &FileUri,
    password: &str,
    mode: flying::ConnectionMode,
    port: u16,
    progress_tx: Option<mpsc::Sender<u8>>,
    peer_id_tx: Option<mpsc::Sender<String>>,
    mdns_tx: Option<oneshot::Sender<ServiceDaemon>>,
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

    let (mut stream, _mdns_daemon) = flying::establish_connection(&mode, port, peer_id_tx, mdns_tx)
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

    let mut tokio_file = TokioFile::from_std(source_file);
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

    // Wait for ACK from receiver
    let _ = stream.read_u8().await;
    let _ = stream.shutdown().await;

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
    progress_tx: Option<mpsc::Sender<u8>>,
    peer_id_tx: Option<mpsc::Sender<String>>,
    mdns_tx: Option<oneshot::Sender<ServiceDaemon>>,
) -> Result<(), String> {
    let api = app.android_fs_async();

    let folder_name = api
        .get_name(uri)
        .await
        .map_err(|e| format!("Failed to get folder name: {}", e))?;

    let (mut stream, _mdns_daemon) = flying::establish_connection(&mode, port, peer_id_tx, mdns_tx)
        .await
        .map_err(|e| format!("Failed to establish connection: {}", e))?;

    let key =
        flying::utils::send_handshake(&mut stream, flying::VERSION, password, &folder_name, true)
            .await
            .map_err(|e| format!("Handshake failed: {}", e))?;

    // Recursive send function
    async fn send_recursive(
        app: &tauri::AppHandle,
        stream: &mut Box<dyn flying::NetworkStream>,
        dir_uri: &FileUri,
        base_path: &str,
        key: &ring::aead::LessSafeKey,
        progress_tx: &Option<mpsc::Sender<u8>>,
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
                    let tokio_file = TokioFile::from_std(file);

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

    // Wait for ACK from receiver
    let _ = stream.read_u8().await;
    let _ = stream.shutdown().await;

    if let Some(mdns_daemon) = _mdns_daemon {
        let _ = mdns_daemon.shutdown();
    }

    Ok(())
}
