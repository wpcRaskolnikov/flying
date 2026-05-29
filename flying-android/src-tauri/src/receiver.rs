use crate::sender::ConnectionConfig;
use crate::utils::{TransferState, TransferStatusPayload};
use std::sync::Arc;

use flying::mdns::ServiceDaemon;

use tauri::Emitter;

use std::path::PathBuf;

use tokio::sync::{mpsc, oneshot};

#[tauri::command]
pub async fn cancel_receive(state: tauri::State<'_, TransferState>) -> Result<(), String> {
    if let Some(mdns) = state.mdns_daemon.lock().unwrap().take() {
        let _ = mdns.shutdown();
    }
    if let Some(abort_sender) = state.abort_handle.lock().unwrap().take() {
        let _ = abort_sender.send(());
        Ok(())
    } else {
        Err("No active receive transfer to cancel".to_string())
    }
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

    let (abort_handle, abort_registration) = oneshot::channel::<()>();
    let (mdns_tx, mdns_rx) = oneshot::channel::<ServiceDaemon>();

    let mdns_daemon_mutex = Arc::clone(&state.mdns_daemon);
    tokio::spawn(async move {
        if let Ok(daemon) = mdns_rx.await {
            let mut state = mdns_daemon_mutex.lock().unwrap();
            *state = Some(daemon);
        }
    });

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

        let (progress_tx, mut progress_rx) = mpsc::channel(32);
        let window_clone = window.clone();
        tokio::spawn(async move {
            while let Some(percent) = progress_rx.recv().await {
                let _ = window_clone.emit(
                    "receive-status-update",
                    TransferStatusPayload {
                        status: "Sending".to_string(),
                        progress: percent,
                        message: None,
                        peer_id: None,
                    },
                );
            }
        });

        // Create peer ID channel for receiving peer ID
        let (peer_id_tx, mut peer_id_rx) = mpsc::channel(1);
        let window_peer_id = window.clone();
        tokio::spawn(async move {
            if let Some(peer_id) = peer_id_rx.recv().await {
                let _ = window_peer_id.emit(
                    "receive-status-update",
                    TransferStatusPayload {
                        status: "Ready".to_string(),
                        progress: 0,
                        message: None,
                        peer_id: Some(peer_id),
                    },
                );
            }
        });

        // Emit initial status: Ready for listen modes, Sending for others
        match &mode {
            flying::ConnectionMode::Listen => {
                let _ = window.emit(
                    "receive-status-update",
                    TransferStatusPayload {
                        status: "Ready".to_string(),
                        progress: 0,
                        message: None,
                        peer_id: None,
                    },
                );
            }
            _ => {
                let _ = window.emit(
                    "receive-status-update",
                    TransferStatusPayload {
                        status: "Sending".to_string(),
                        progress: 0,
                        message: None,
                        peer_id: None,
                    },
                );
            }
        }

        // Check for cancellation or run transfer
        let result = tokio::select! {
            _ = abort_registration => {
                Err("Transfer cancelled".to_string())
            }
            result = flying::run_receiver(&output_dir, &password, mode, port, Some(progress_tx), Some(peer_id_tx), Some(mdns_tx)) => {
                result.map_err(|e| format!("Receive error: {}", e))
            }
        };

        match result {
            Ok(_) => {
                let _ = window.emit(
                    "receive-status-update",
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
                    "receive-status-update",
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

    // Store the abort sender
    *state.abort_handle.lock().unwrap() = Some(abort_handle);

    Ok(())
}
