use crate::sender::ConnectionMode;
use crate::utils::TransferState;
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
    connection_mode: ConnectionMode,
    connect_ip: Option<String>,
    relay_addr: Option<String>,
    remote_peer_id: Option<String>,
    _output_dir_uri: String,
    port: u16,
    window: tauri::Window,
    state: tauri::State<'_, TransferState>,
) -> Result<(), String> {
    let mode = connection_mode.to_flying_mode(connect_ip, relay_addr, remote_peer_id)?;

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
        let _ = window.emit("receive-start", serde_json::json!({}));
        let output_dir;

        #[cfg(target_os = "android")]
        {
            // use tauri_plugin_android_fs::{AndroidFsExt, FileUri};
            // let api = app.android_fs_async();

            // let output_uri = FileUri::from_json_str(&output_dir_uri)
            //     .map_err(|e| format!("Failed to parse output directory URI: {}", e))?;
            output_dir = PathBuf::from("/storage/emulated/0/Download");
        }

        #[cfg(not(target_os = "android"))]
        {
            output_dir = PathBuf::from(_output_dir_uri);
        }

        let (progress_tx, mut progress_rx) = mpsc::channel(32);
        let window_clone = window.clone();
        tokio::spawn(async move {
            while let Some(percent) = progress_rx.recv().await {
                let _ = window_clone.emit("receive-progress", percent);
            }
        });

        // Create peer ID channel for receiving peer ID
        let (peer_id_tx, mut peer_id_rx) = mpsc::channel(1);
        let window_peer_id = window.clone();
        tokio::spawn(async move {
            if let Some(peer_id) = peer_id_rx.recv().await {
                let _ = window_peer_id.emit("receive-ready", peer_id);
            }
        });

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
                let _ = window.emit("receive-complete", serde_json::json!({}));
            }
            Err(e) => {
                let _ = window.emit("receive-error", e);
            }
        }
    });

    // Store the abort sender
    *state.abort_handle.lock().unwrap() = Some(abort_handle);

    Ok(())
}
