use crate::ConnectionConfig;
use crate::utils::{SendState, TransferStatusPayload};

use std::sync::Arc;

#[cfg(not(target_os = "android"))]
use std::path::PathBuf;

use tauri::Emitter;

use tokio::sync::{mpsc, oneshot};

#[cfg(target_os = "android")]
use {
    tauri_plugin_android_fs::{AndroidFsExt, Entry, FileUri},
    tokio::fs::File as TokioFile,
    tokio::io::{AsyncReadExt, AsyncWriteExt},
};

#[tauri::command]
pub async fn cancel_send(state: tauri::State<'_, SendState>) -> Result<(), String> {
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
    let (peer_id_tx, _peer_id_rx) = mpsc::channel(1);
    let (progress_tx, _progress_rx) = mpsc::channel(32);

    let state_abort = Arc::clone(&state.abort_handle);

    *state.abort_handle.lock().unwrap() = Some(abort_handle);

    tokio::spawn(async move {
        let initial_status = match &mode {
            flying::ConnectionMode::Listen => "Ready",
            _ => "Connecting",
        };
        emit_status(&window, initial_status, 0, None, None);

        let stream = match flying::establish_connection(&mode, port, Some(peer_id_tx)).await {
            Ok(s) => s,
            Err(e) => {
                emit_status(&window, "Error", 0, Some(format!("Connection failed: {e}")), None);
                *state_abort.lock().unwrap() = None;
                return;
            }
        };

        #[cfg(target_os = "android")]
        let android_uri: Option<FileUri> = FileUri::from_json_str(&file_uri).ok();

        tokio::select! {
            _ = abort_registration => {
                emit_status(&window, "Error", 0, Some("Transfer cancelled".to_string()), None);
            }
            res = async {
                #[cfg(target_os = "android")]
                {
                    match android_uri {
                        Some(ref uri) => {
                            run_send_android(
                                &_app,
                                uri,
                                &password,
                                Some(progress_tx),
                                stream,
                            )
                            .await
                        }
                        None => Err("Failed to parse URI".to_string()),
                    }
                }
                #[cfg(not(target_os = "android"))]
                {
                    let file_path = PathBuf::from(&file_uri);
                    flying::send::run_sender(
                        stream,
                        &file_path,
                        &password,
                        Some(progress_tx),
                    )
                    .await
                    .map_err(|e| format!("Send error: {e}"))
                }
            } => {
                match res {
                    Ok(_) => emit_status(&window, "Completed", 100, None, None),
                    Err(e) => emit_status(&window, "Error", 0, Some(e), None),
                }
            }
        }

        *state_abort.lock().unwrap() = None;
    });

    Ok(())
}

#[cfg(target_os = "android")]
async fn run_send_android(
    app: &tauri::AppHandle,
    uri: &FileUri,
    password: &str,
    progress_tx: Option<mpsc::Sender<u8>>,
    stream: Box<dyn flying::NetworkStream>,
) -> Result<(), String> {
    let api = app.android_fs_async();
    let metadata = api
        .get_metadata(uri)
        .await
        .map_err(|e| format!("Failed to get metadata: {}", e))?;

    if metadata.is_dir() {
        send_folder_android(app, uri, password, progress_tx, stream).await
    } else {
        send_file_android(app, uri, password, progress_tx, stream).await
    }
}

#[cfg(target_os = "android")]
async fn send_file_android(
    app: &tauri::AppHandle,
    uri: &FileUri,
    password: &str,
    progress_tx: Option<mpsc::Sender<u8>>,
    stream: Box<dyn flying::NetworkStream>,
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

    let mut session = flying::session::Session::new(stream, flying::session::Role::Sender);
    session
        .handshake(flying::VERSION, password)
        .await
        .map_err(|e| format!("Handshake failed: {e}"))?;

    flying::send::send_metadata(&mut session, &file_name, file_size)
        .await
        .map_err(|e| format!("Failed to send metadata: {e}"))?;

    let is_duplicate = flying::send::check_duplicate(&mut session)
        .await
        .map_err(|e| format!("Failed to check duplicate: {e}"))?;

    if !is_duplicate {
        let mut tokio_file = TokioFile::from_std(source_file);
        let mut progress = flying::progress::Progress::new(file_size, progress_tx);
        flying::send::encrypt_and_send(&mut session, &mut tokio_file, &mut progress)
            .await
            .map_err(|e| format!("Failed to send file: {e}"))?;
    }

    session
        .write_u8(0)
        .await
        .map_err(|e| format!("Failed to send end signal: {e}"))?;
    session
        .finish()
        .await
        .map_err(|e| format!("Failed to finish session: {e}"))?;

    Ok(())
}

#[cfg(target_os = "android")]
async fn send_folder_android(
    app: &tauri::AppHandle,
    uri: &FileUri,
    password: &str,
    progress_tx: Option<mpsc::Sender<u8>>,
    stream: Box<dyn flying::NetworkStream>,
) -> Result<(), String> {
    let api = app.android_fs_async();

    let folder_name = api
        .get_name(uri)
        .await
        .map_err(|e| format!("Failed to get folder name: {}", e))?;

    let mut session = flying::session::Session::new(stream, flying::session::Role::Sender);
    session
        .handshake(flying::VERSION, password)
        .await
        .map_err(|e| format!("Handshake failed: {e}"))?;

    async fn send_recursive(
        app: &tauri::AppHandle,
        session: &mut flying::session::Session<Box<dyn flying::NetworkStream>>,
        dir_uri: &FileUri,
        base_path: &str,
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

                    flying::send::send_metadata(session, &relative_path, len)
                        .await
                        .map_err(|e| format!("Failed to send metadata: {}", e))?;

                    let file = api
                        .open_file_readable(&uri)
                        .await
                        .map_err(|e| format!("Failed to open file {}: {}", relative_path, e))?;
                    let mut tokio_file = TokioFile::from_std(file);
                    let mut progress = flying::progress::Progress::new(len, progress_tx.clone());
                    flying::send::encrypt_and_send(session, &mut tokio_file, &mut progress)
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
                        session,
                        &uri,
                        &sub_path,
                        progress_tx,
                    ))
                    .await?;
                }
            }
        }

        Ok(())
    }

    send_recursive(app, &mut session, uri, "", &progress_tx).await?;

    session
        .write_u64(0)
        .await
        .map_err(|e| format!("Failed to send end signal: {e}"))?;
    session
        .finish()
        .await
        .map_err(|e| format!("Failed to finish session: {e}"))?;

    Ok(())
}
