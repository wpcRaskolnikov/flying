use crate::utils::{CollabServerState, RoomManager};

use flying::mdns::advertise_collab_service;
use flying::utils::create_listener;

use std::sync::Arc;

use futures_util::StreamExt;

use tokio::net::TcpStream;

use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::handshake::server::{
    Callback, ErrorResponse, Request, Response,
};

use tracing::{debug, info, warn};

struct RoomCallback {
    room_tx: tokio::sync::oneshot::Sender<String>,
}

impl Callback for RoomCallback {
    fn on_request(self, request: &Request, response: Response) -> Result<Response, ErrorResponse> {
        let path = request.uri().path().trim_start_matches('/');
        let room = if path.is_empty() {
            "default-room".to_string()
        } else {
            path.to_string()
        };
        let _ = self.room_tx.send(room);
        Ok(response)
    }
}

async fn handle_connection(socket: TcpStream, room_manager: Arc<RoomManager>) {
    let (room_tx, room_rx) = tokio::sync::oneshot::channel::<String>();
    let callback = RoomCallback { room_tx };

    let ws_stream = match accept_hdr_async(socket, callback).await {
        Ok(ws) => ws,
        Err(e) => {
            warn!("Failed to accept WebSocket: {}", e);
            return;
        }
    };

    let Ok(room_name) = room_rx.await else {
        warn!("Failed to get room name from handshake");
        return;
    };

    info!("WebSocket connected to room: {}", room_name);
    let room = room_manager.get_or_create_room(&room_name);
    let (sink, stream) = ws_stream.split();
    match room.subscribe(sink, stream).await {
        Ok(Ok(())) => debug!("WebSocket disconnected from room: {}", room_name),
        Ok(Err(e)) => warn!("WebSocket error in room {}: {}", room_name, e),
        Err(e) => warn!("Task panicked in room {}: {}", room_name, e),
    }
}

#[tauri::command]
pub async fn start_collab_server(
    state: tauri::State<'_, CollabServerState>,
    port: u16,
) -> Result<(), String> {
    if state.abort_handle.lock().unwrap().is_some() {
        return Err("Collaboration server is already running".to_string());
    }

    let room_manager = Arc::clone(&state.room_manager);

    let listener =
        create_listener(port).map_err(|e| format!("Failed to create listener: {}", e))?;
    let mdns = advertise_collab_service(port)
        .map_err(|e| format!("Failed to start mDNS broadcast: {}", e))?;
    *state.mdns_daemon.lock().unwrap() = Some(mdns);

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    *state.abort_handle.lock().unwrap() = Some(shutdown_tx);

    tokio::spawn(async move {
        info!("Collaboration server started on port {}", port);
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((socket, _addr)) => {
                            let room_manager = Arc::clone(&room_manager);
                            tokio::spawn(handle_connection(socket, room_manager));
                        }
                        Err(e) => warn!("Failed to accept connection: {}", e),
                    }
                }
                _ = &mut shutdown_rx => {
                    info!("Shutting down collaboration server");
                    break;
                }
            }
        }
    });
    Ok(())
}

#[tauri::command]
pub async fn stop_collab_server(state: tauri::State<'_, CollabServerState>) -> Result<(), String> {
    if let Some(daemon) = state.mdns_daemon.lock().unwrap().take() {
        let _ = daemon.shutdown();
    }
    if let Some(abort_sender) = state.abort_handle.lock().unwrap().take() {
        let _ = abort_sender.send(());
        Ok(())
    } else {
        return Err("No server is running".to_string());
    }
}

#[tauri::command]
pub async fn is_collab_server_running(
    state: tauri::State<'_, CollabServerState>,
) -> Result<bool, String> {
    Ok(state.abort_handle.lock().unwrap().is_some())
}
