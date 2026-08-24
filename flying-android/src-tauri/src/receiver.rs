use crate::ConnectionConfig;
use crate::utils::{ReceiveState, TransferStatus, TransferStatusPayload};

use flying::establish_connection;
use flying::receive::run_receiver;

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

    *state.abort_handle.lock().unwrap() = Some(abort_handle);
    let state_handle = state.abort_handle.clone();

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

        let emit = |payload: TransferStatusPayload| {
            let _ = window.emit("receive-status-update", payload);
        };

        emit(TransferStatusPayload {
            status: TransferStatus::Ready,
            peer_id: None,
        });

        let stream = match establish_connection(&mode, port, Some(peer_id_tx)).await {
            Ok(s) => s,
            Err(e) => {
                emit(TransferStatusPayload {
                    status: TransferStatus::Error(format!("Connection failed: {e}")),
                    peer_id: None,
                });
                *state_handle.lock().unwrap() = None;
                return;
            }
        };

        let transfer_fut = run_receiver(stream, &password, &output_dir, Some(progress_tx));
        tokio::pin!(transfer_fut);

        loop {
            tokio::select! {
                Some(percent) = progress_rx.recv() => {
                    emit(TransferStatusPayload {
                        status: TransferStatus::Processing(percent),
                        peer_id: None,
                    });
                }
                Some(peer_id) = peer_id_rx.recv() => {
                    emit(TransferStatusPayload {
                        status: TransferStatus::Ready,
                        peer_id: Some(peer_id),
                    });
                }
                res = &mut transfer_fut => {
                    match res {
                        Ok(_) => emit(TransferStatusPayload {
                            status: TransferStatus::Completed,
                            peer_id: None,
                        }),
                        Err(e) => emit(TransferStatusPayload {
                            status: TransferStatus::Error(format!("Receive error: {e}")),
                            peer_id: None,
                        }),
                    }
                    break;
                }
                _ = &mut abort_registration => {
                    emit(TransferStatusPayload {
                        status: TransferStatus::Error("Transfer cancelled".to_string()),
                        peer_id: None,
                    });
                    break;
                }
            }
        }

        *state_handle.lock().unwrap() = None;
    });

    Ok(())
}
