use std::path::PathBuf;
use std::sync::Arc;
use tauri::Emitter;
use tokio::sync::Mutex;

use crate::{TransferState, sender::ConnectionMode};

#[tauri::command]
pub async fn cancel_receive(
    state: tauri::State<'_, Arc<Mutex<TransferState>>>,
) -> Result<(), String> {
    let mut transfer_state = state.lock().await;
    if let Some(abort_sender) = transfer_state.receive_abort_handle.take() {
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
    _output_dir_uri: String,
    port: u16,
    window: tauri::Window,
    state: tauri::State<'_, Arc<Mutex<TransferState>>>,
) -> Result<(), String> {
    let mode = connection_mode.to_flying_mode(connect_ip);

    let (abort_handle, abort_registration) = tokio::sync::oneshot::channel::<()>();

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

        let (progress_tx, mut progress_rx) = tokio::sync::mpsc::channel(32);
        let window_clone = window.clone();
        tokio::spawn(async move {
            while let Some(percent) = progress_rx.recv().await {
                let _ = window_clone.emit("receive-progress", percent);
            }
        });

        // Check for cancellation or run transfer
        let result = tokio::select! {
            _ = abort_registration => {
                Err("Transfer cancelled".to_string())
            }
            result = flying::run_receiver(&output_dir, &password, mode, port, Some(progress_tx)) => {
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
    let mut transfer_state = state.lock().await;
    transfer_state.receive_abort_handle = Some(abort_handle);

    Ok(())
}
