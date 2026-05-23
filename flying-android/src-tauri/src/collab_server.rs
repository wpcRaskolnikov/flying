use crate::utils::{CollabServerState, RoomManager};

use flying::mdns::advertise_collab_service;

use std::sync::Arc;

use futures_util::StreamExt;

use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};

use tokio::net::{TcpListener, TcpStream};

use tokio_tungstenite::tungstenite::handshake::server::{
    Callback, ErrorResponse, Request, Response,
};
use tokio_tungstenite::{WebSocketStream, accept_hdr_async};

use tracing::{debug, info, warn};

struct RoomCallback {
    room_tx: std::sync::mpsc::Sender<String>,
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

pub async fn handle_ws(
    socket: WebSocketStream<TcpStream>,
    room_name: String,
    room_manager: Arc<RoomManager>,
) {
    info!("WebSocket connected to room: {}", room_name);
    let room = room_manager.get_or_create_room(&room_name);
    let (sink, stream) = socket.split();
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
) -> Result<String, String> {
    // Use block scope to release MutexGuard
    {
        let handle_guard = state.server_handle.lock().unwrap();
        if handle_guard.is_some() {
            return Err("Collaboration server is already running".to_string());
        }
    }

    let room_manager = state.room_manager.clone();
    let addr = format!("[::]:{}", port)
        .parse::<std::net::SocketAddr>()
        .map_err(|e| e.to_string())?;
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(SocketProtocol::TCP))
        .map_err(|e| format!("Failed to create socket: {}", e))?;
    socket.set_only_v6(false).map_err(|e| e.to_string())?;
    socket.set_reuse_address(true).map_err(|e| e.to_string())?;
    socket.bind(&addr.into()).map_err(|e| e.to_string())?;
    socket.listen(128).map_err(|e| e.to_string())?;
    let std_listener: std::net::TcpListener = socket.into();
    std_listener
        .set_nonblocking(true)
        .map_err(|e| e.to_string())?;
    let listener = TcpListener::from_std(std_listener)
        .map_err(|e| format!("Failed to create listener: {}", e))?;
    let actual_port = listener.local_addr().map_err(|e| e.to_string())?.port();
    *state.port.lock().unwrap() = actual_port;
    let mdns = advertise_collab_service(actual_port)
        .map_err(|e| format!("Failed to start mDNS broadcast: {}", e))?;
    *state.mdns_daemon.lock().unwrap() = Some(mdns);

    let handle = tokio::spawn(async move {
        info!("Collaboration server started on port {}", actual_port);
        loop {
            let (socket, _addr) = match listener.accept().await {
                Ok(val) => val,
                Err(e) => {
                    warn!("Failed to accept connection: {}", e);
                    continue;
                }
            };

            let room_manager = room_manager.clone();
            tokio::spawn(async move {
                let (room_tx, room_rx) = std::sync::mpsc::channel::<String>();
                let callback = RoomCallback { room_tx };
                match accept_hdr_async(socket, callback).await {
                    Ok(ws_stream) => {
                        if let Ok(room_name) = room_rx.recv() {
                            handle_ws(ws_stream, room_name, room_manager).await;
                        }
                    }
                    Err(e) => {
                        warn!("Failed to accept WebSocket: {}", e);
                    }
                }
            });
        }
    });

    *state.server_handle.lock().unwrap() = Some(handle);
    Ok(format!("Server started on port {}", actual_port))
}

#[tauri::command]
pub async fn stop_collab_server(
    state: tauri::State<'_, CollabServerState>,
) -> Result<String, String> {
    let mut handle_guard = state.server_handle.lock().unwrap();
    if let Some(handle) = handle_guard.take() {
        handle.abort();
        *state.port.lock().unwrap() = 0;
        state.room_manager.clear_rooms();
        if let Some(daemon) = state.mdns_daemon.lock().unwrap().take() {
            let _ = daemon.shutdown();
        }
        Ok("Server stopped".to_string())
    } else {
        Err("No server is running".to_string())
    }
}

#[tauri::command]
pub async fn get_collab_server_status(
    state: tauri::State<'_, CollabServerState>,
) -> Result<serde_json::Value, String> {
    let handle_guard = state.server_handle.lock().unwrap();
    let is_running = handle_guard.is_some();
    let port = *state.port.lock().unwrap();
    let room_count = state.room_manager.room_count();
    Ok(serde_json::json!({
        "running": is_running,
        "port": port,
        "room_count": room_count
    }))
}
