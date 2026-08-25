use crate::ConnectionConfig;
use crate::utils::{SendState, TransferStatus};

use flying::establish_connection;

use tauri::Emitter;
use tokio::sync::{mpsc, oneshot};

#[cfg(not(target_os = "android"))]
use std::path::PathBuf;

#[cfg(target_os = "android")]
use {
    flying::NetworkStream,
    flying::metadata::Metadata,
    flying::progress::Progress,
    flying::session::{Role, Session},
    tauri_plugin_android_fs::{AndroidFsExt, Entry, FileUri},
    tokio::fs::File as TokioFile,
    tokio::io::AsyncWriteExt,
};

#[tauri::command]
pub async fn cancel_send(state: tauri::State<'_, SendState>) -> Result<(), String> {
    if let Some(abort_sender) = state.abort_handle.lock().unwrap().take() {
        let _ = abort_sender.send(());
    }
    Ok(())
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

    let (abort_handle, mut abort_registration) = oneshot::channel::<()>();
    let (peer_id_tx, _peer_id_rx) = mpsc::channel(1);
    let (progress_tx, mut progress_rx) = mpsc::channel(32);

    *state.abort_handle.lock().unwrap() = Some(abort_handle);
    let state_handle = state.abort_handle.clone();

    tokio::spawn(async move {
        let emit = |status: TransferStatus| {
            let _ = window.emit("send-status-update", status);
        };

        emit(TransferStatus::Ready(String::new()));

        let stream = match establish_connection(&mode, port, Some(peer_id_tx)).await {
            Ok(s) => s,
            Err(e) => {
                emit(TransferStatus::Error(format!("Connection failed: {e}")));
                *state_handle.lock().unwrap() = None;
                return;
            }
        };

        #[cfg(target_os = "android")]
        let transfer_fut: std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), String>> + Send>,
        > = {
            let uri = FileUri::from_json_str(&file_uri)
                .map_err(|_| "Failed to parse URI".to_string())?;
            Box::pin(async move {
                run_send_android(&_app, &uri, &password, Some(progress_tx), stream)
                    .await
                    .map_err(|e| format!("Send error: {e}"))
            })
        };

        #[cfg(not(target_os = "android"))]
        let transfer_fut: std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), String>> + Send>,
        > = {
            let file_path = PathBuf::from(&file_uri);
            Box::pin(async move {
                flying::send::run_sender(stream, &file_path, &password, Some(progress_tx))
                    .await
                    .map_err(|e| format!("Send error: {e}"))
            })
        };

        tokio::pin!(transfer_fut);

        loop {
            tokio::select! {
                Some(percent) = progress_rx.recv() => {
                    emit(TransferStatus::Processing(percent));
                }
                res = &mut transfer_fut => {
                    match res {
                        Ok(_) => emit(TransferStatus::Completed),
                        Err(e) => emit(TransferStatus::Error(e)),
                    }
                    break;
                }
                _ = &mut abort_registration => {
                    emit(TransferStatus::Error("Transfer cancelled".to_string()));
                    break;
                }
            }
        }

        *state_handle.lock().unwrap() = None;
    });

    Ok(())
}

#[cfg(target_os = "android")]
async fn run_send_android(
    app: &tauri::AppHandle,
    uri: &FileUri,
    password: &str,
    progress_tx: Option<mpsc::Sender<u8>>,
    stream: Box<dyn NetworkStream>,
) -> anyhow::Result<()> {
    let api = app.android_fs_async();
    let metadata = api.get_metadata(uri).await?;

    let mut session = Session::new(stream, Role::Sender);
    session.handshake(flying::VERSION, password).await?;

    if metadata.is_dir() {
        send_folder_android(app, &mut session, uri, None, progress_tx).await;
        session.write_u64(0).await?;
        session.flush().await?;
    } else {
        send_file_android(app, &mut session, uri, None, progress_tx).await?;
    }
    session.finish().await?;

    Ok(())
}

#[cfg(target_os = "android")]
async fn send_file_android(
    app: &tauri::AppHandle,
    session: &mut Session<Box<dyn NetworkStream>>,
    uri: &FileUri,
    base_path: Option<&str>,
    progress_tx: Option<mpsc::Sender<u8>>,
) -> anyhow::Result<()> {
    let api = app.android_fs_async();

    let source_file = api.open_file_readable(uri).await?;
    let file_size = api.get_metadata(uri).await?.len();

    let file_name = api.get_name(uri).await?;
    let relative_path = match base_path {
        Some(base) => format!("{}/{}", base, file_name),
        None => file_name,
    };
    Metadata {
        relative_path,
        transfer_type: flying::metadata::Type::File,
        size: file_size,
    }
    .write(session)
    .await?;

    let mut tokio_file = TokioFile::from_std(source_file);
    let mut progress = Progress::new(file_size, progress_tx);
    flying::send::encrypt_and_send(session, tokio_file, &mut progress).await?;

    Ok(())
}

#[cfg(target_os = "android")]
async fn send_folder_android(
    app: &tauri::AppHandle,
    session: &mut Session<Box<dyn NetworkStream>>,
    uri: &FileUri,
    base_path: Option<&str>,
    progress_tx: Option<mpsc::Sender<u8>>,
) -> anyhow::Result<()> {
    let api = app.android_fs_async();

    let dir_name = api.get_name(uri).await?;
    let relative_path = match base_path {
        Some(base) => format!("{}/{}", base, dir_name),
        None => dir_name,
    };
    Metadata {
        relative_path: relative_path.clone(),
        transfer_type: flying::metadata::Type::Folder,
        size: 0,
    }
    .write(session)
    .await?;

    let entries = api.read_dir(uri).await?;
    for entry in entries {
        match entry {
            Entry::File { uri, .. } => {
                send_file_android(
                    app,
                    session,
                    &uri,
                    Some(&relative_path),
                    progress_tx.clone(),
                )
                .await?;
            }
            Entry::Dir { uri, .. } => {
                Box::pin(send_folder_android(
                    app,
                    session,
                    &uri,
                    Some(&relative_path),
                    progress_tx.clone(),
                ))
                .await?;
            }
        }
    }

    Ok(())
}
