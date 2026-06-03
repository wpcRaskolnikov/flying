use crate::sender::ConnectionConfig;
use crate::utils::{TransferState, TransferStatusPayload};

use tauri::Emitter;

use std::path::PathBuf;

use tokio::sync::{mpsc, oneshot};

use futures_util::FutureExt;

#[tauri::command]
pub async fn cancel_receive(state: tauri::State<'_, TransferState>) -> Result<(), String> {
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
    state: tauri::State<'_, TransferState>,
) -> Result<(), String> {
    let mode = config.to_flying_mode()?;

    let (abort_handle, mut abort_registration) = oneshot::channel::<()>();
    let (mdns_tx, mdns_rx) = oneshot::channel::<flying::mdns::ServiceDaemon>();
    let (progress_tx, mut progress_rx) = mpsc::channel(32);
    let (peer_id_tx, mut peer_id_rx) = mpsc::channel(1);

    let state_mdns = state.mdns_daemon.clone();
    let state_abort = state.abort_handle.clone();

    let mut mdns_rx = mdns_rx.fuse();

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
            flying::ConnectionMode::Listen => "Ready",
            _ => "Sending",
        };
        emit_status(&window, initial_status, 0, None, None);

        let transfer_fut = flying::run_receiver(
            &output_dir,
            &password,
            mode,
            port,
            Some(progress_tx),
            Some(peer_id_tx),
            Some(mdns_tx),
        );
        tokio::pin!(transfer_fut);

        let final_result: Result<(), String>;

        loop {
            tokio::select! {
                // Progress updates
                msg = progress_rx.recv() => {
                    if let Some(percent) = msg {
                        emit_status(&window, "Sending", percent, None, None);
                    }
                }
                // Peer ID received
                msg = peer_id_rx.recv() => {
                    if let Some(peer_id) = msg {
                        emit_status(&window, "Ready", 0, None, Some(peer_id));
                    }
                }
                // Transfer completes
                res = &mut transfer_fut => {
                    final_result = res.map_err(|e| format!("Receive error: {e}"));
                    break;
                }
                // User cancels
                _ = &mut abort_registration => {
                    final_result = Err("Transfer cancelled".to_string());
                    break;
                }
                // Capture mDNS daemon from oneshot
                Ok(daemon) = &mut mdns_rx => {
                    *state_mdns.lock().unwrap() = Some(daemon);
                }
            }
        }

        // Clean up state
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
