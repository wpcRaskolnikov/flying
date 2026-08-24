use crate::ConnectionConfig;
use crate::utils::{ReceiveState, TransferStatusPayload};

use flying::receive::run_receiver;
use flying::{ConnectionMode, establish_connection};

use tauri::Emitter;

use std::path::PathBuf;

use tokio::sync::mpsc;

#[tauri::command]
pub async fn cancel_receive(state: tauri::State<'_, ReceiveState>) -> Result<(), String> {
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
        "receive-status-update",
        TransferStatusPayload {
            status: status.to_string(),
            progress,
            message,
            peer_id,
        },
    );
}

#[tauri::command]
pub async fn receive_file(
    password: String,
    config: ConnectionConfig,
    output_dir_uri: String,
    port: u16,
    window: tauri::Window,
    state: tauri::State<'_, ReceiveState>,
) -> Result<(), String> {
    let mode = config.to_flying_mode()?;

    let (abort_handle, mut abort_registration) = tokio::sync::oneshot::channel::<()>();
    let (progress_tx, mut progress_rx) = mpsc::channel(32);
    let (peer_id_tx, mut peer_id_rx) = mpsc::channel(1);

    let state_abort = state.abort_handle.clone();

    *state.abort_handle.lock().unwrap() = Some(abort_handle);

    tokio::spawn(async move {
        let output_dir;
        #[cfg(target_os = "android")]
        {
            output_dir = PathBuf::from("/storage/emulated/0/Download");
        }
        #[cfg(not(target_os = "android"))]
        {
            output_dir = PathBuf::from(output_dir_uri);
        }

        let initial_status = match &mode {
            ConnectionMode::Listen => "Ready",
            _ => "Connecting",
        };
        emit_status(&window, initial_status, 0, None, None);

        let stream = match establish_connection(&mode, port, Some(peer_id_tx)).await {
            Ok(s) => s,
            Err(e) => {
                emit_status(
                    &window,
                    "Error",
                    0,
                    Some(format!("Connection failed: {e}")),
                    None,
                );
                *state_abort.lock().unwrap() = None;
                return;
            }
        };

        let transfer_fut = run_receiver(stream, &password, &output_dir, Some(progress_tx));
        tokio::pin!(transfer_fut);

        loop {
            tokio::select! {
                msg = progress_rx.recv() => {
                    if let Some(percent) = msg {
                        emit_status(&window, "Receiving", percent, None, None);
                    }
                }
                msg = peer_id_rx.recv() => {
                    if let Some(peer_id) = msg {
                        emit_status(&window, "Ready", 0, None, Some(peer_id));
                    }
                }
                res = &mut transfer_fut => {
                    match res {
                        Ok(_) => emit_status(&window, "Completed", 100, None, None),
                        Err(e) => emit_status(&window, "Error", 0, Some(format!("Receive error: {e}")), None),
                    }
                    break;
                }
                _ = &mut abort_registration => {
                    emit_status(&window, "Error", 0, Some("Transfer cancelled".to_string()), None);
                    break;
                }
            }
        }

        *state_abort.lock().unwrap() = None;
    });

    Ok(())
}
