use crate::utils::{SendState, TransferStatusPayload};

use flying::mdns::ServiceDaemon;

use std::pin::Pin;
use std::sync::Arc;

#[cfg(not(target_os = "android"))]
use std::path::PathBuf;

use tauri::Emitter;

use serde::{Deserialize, Serialize};

use futures_util::FutureExt;
use tokio::sync::{mpsc, oneshot};

#[cfg(target_os = "android")]
use {
    tauri_plugin_android_fs::{AndroidFsExt, Entry, FileUri},
    tokio::fs::File as TokioFile,
    tokio::io::{AsyncReadExt, AsyncWriteExt},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
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
pub async fn cancel_send(state: tauri::State<'_, SendState>) -> Result<(), String> {
    if let Some(mdns) = state.mdns_daemon.lock().unwrap().take() {
        let _ = mdns.shutdown();
    }
    if let Some(abort_sender) = state.abort_handle.lock().unwrap().take() {
        let _ = abort_sender.send(());
    }
    Ok(())
}

fn emit_status(
    window: &tauri::Window,
    status: &str,
    progress: u8,
    message: Option<String>,
    peer_id: Option<String>,
) {
    let _ = window.emit(
        "send-status-update",
        TransferStatusPayload {
            status: status.to_string(),
            progress,
            message,
            peer_id,
        },
    );
}

#[tauri::command]
pub async fn send_file(
    file_uri: String,
    password: String,
    config: ConnectionConfig,
    port: u16,
    _app: tauri::AppHandle,
    window: tauri::Window,
    state: tauri::State<'_, SendState>,
) -> Result<(), String> {
    let mode = config.to_flying_mode()?;

    let (abort_handle, abort_registration) = oneshot::channel::<()>();
    let (mdns_tx, mdns_rx) = oneshot::channel::<ServiceDaemon>();
    let mut mdns_rx = mdns_rx.fuse();
    let (peer_id_tx, mut peer_id_rx) = mpsc::channel(1);
    let (progress_tx, mut progress_rx) = mpsc::channel(32);

    let state_mdns = Arc::clone(&state.mdns_daemon);
    let state_abort = Arc::clone(&state.abort_handle);

    // Store abort handle before spawning
    *state.abort_handle.lock().unwrap() = Some(abort_handle);

    tokio::spawn(async move {
        let initial_status = match &mode {
            flying::ConnectionMode::Listen => "Ready",
            _ => "Sending",
        };
        emit_status(&window, initial_status, 0, None, None);

        #[cfg(target_os = "android")]
        let android_uri: Option<FileUri> = FileUri::from_json_str(&file_uri).ok();

        #[cfg(target_os = "android")]
        let transfer_fut: Pin<
            Box<dyn std::future::Future<Output = Result<(), String>> + Send>,
        > = {
            match android_uri {
                Some(ref uri) => Box::pin(run_send_android(
                    &_app,
                    uri,
                    &password,
                    mode,
                    port,
                    Some(progress_tx),
                    Some(peer_id_tx),
                    Some(mdns_tx),
                )),
                None => Box::pin(async move {
                    let _ = mdns_tx;
                    Err("Failed to parse URI".to_string())
                }),
            }
        };

        #[cfg(not(target_os = "android"))]
        let transfer_fut: Pin<
            Box<dyn std::future::Future<Output = Result<(), String>> + Send>,
        > = {
            let file_path = PathBuf::from(&file_uri);
            Box::pin(async move {
                flying::run_sender(
                    &file_path,
                    &password,
                    mode,
                    port,
                    Some(progress_tx),
                    Some(peer_id_tx),
                    Some(mdns_tx),
                )
                .await
                .map_err(|e| format!("Send error: {e}"))
            })
        };

        tokio::pin!(transfer_fut);
        let mut abort_registration = abort_registration;
        let final_result: Result<(), String>;

        loop {
            tokio::select! {
                msg = progress_rx.recv() => {
                    if let Some(percent) = msg {
                        emit_status(&window, "Sending", percent, None, None);
                    }
                }
                msg = peer_id_rx.recv() => {
                    if let Some(peer_id) = msg {
                        emit_status(&window, "Ready", 0, None, Some(peer_id));
                    }
                }
                Ok(daemon) = &mut mdns_rx => {
                    *state_mdns.lock().unwrap() = Some(daemon);
                }
                res = &mut transfer_fut => {
                    final_result = res;
                    break;
                }
                _ = &mut abort_registration => {
                    final_result = Err("Transfer cancelled".to_string());
                    break;
                }
            }
        }

        *state_abort.lock().unwrap() = None;
        if let Some(mdns) = state_mdns.lock().unwrap().take() {
            let _ = mdns.shutdown();
        }

        // Emit final status
        match final_result {
            Ok(_) => emit_status(&window, "Completed", 100, None, None),
            Err(e) => emit_status(&window, "Error", 0, Some(e), None),
        }
    });

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

    let key =
        flying::utils::send_handshake(&mut stream, flying::VERSION, password, &file_name, false)
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

    stream
        .write_u64(0)
        .await
        .map_err(|e| format!("Failed to send end signal: {}", e))?;

    let _ = stream.read_u8().await;
    let _ = stream.shutdown().await;

    if let Some(mdns_daemon) = _mdns_daemon {
        let _ = mdns_daemon.shutdown();
    }

    Ok(())
}
