use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, broadcast};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message as TungsteniteMsg;
use tokio_tungstenite::tungstenite::handshake::server::{
    Callback, ErrorResponse, Request, Response,
};
use tokio_tungstenite::{WebSocketStream, accept_hdr_async};
use tracing::{debug, info, warn};
use yrs::Update;
use yrs::encoding::write::Write;
use yrs::sync::protocol::{MSG_SYNC, MSG_SYNC_UPDATE};
use yrs::sync::{Awareness, Error, Message, Protocol, SyncMessage};
use yrs::updates::decoder::Decode;
use yrs::updates::encoder::{Encode, Encoder, EncoderV1};
use yrs::{Doc, Subscription};

const BROADCAST_BUFFER: usize = 64;

// ---------------------------------------------------------------------------
// BroadcastGroup – the pub/sub engine for doc + awareness updates
// ---------------------------------------------------------------------------

pub struct BroadcastGroup {
    #[allow(dead_code)]
    doc_sub: Subscription,
    #[allow(dead_code)]
    awareness_sub: Subscription,
    awareness: Arc<Awareness>,
    sender: broadcast::Sender<Vec<u8>>,
}

impl BroadcastGroup {
    pub fn new(awareness: Arc<Awareness>, buffer_capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(buffer_capacity);

        // Observe document updates
        let sink_tx = sender.clone();
        let doc_sub = awareness
            .doc()
            .observe_update_v1(move |_txn, u| {
                let mut encoder = EncoderV1::new();
                encoder.write_var(MSG_SYNC);
                encoder.write_var(MSG_SYNC_UPDATE);
                encoder.write_buf(&u.update);
                let msg = encoder.to_vec();
                let _ = sink_tx.send(msg);
            })
            .unwrap();

        // Observe awareness changes
        let sink_tx2 = sender.clone();
        let awareness_weak = Arc::downgrade(&awareness);
        let awareness_sub = awareness.on_update(move |_awareness, e, _origin| {
            if let Some(awareness) = awareness_weak.upgrade() {
                let changed: Vec<u64> = e
                    .added()
                    .iter()
                    .chain(e.updated())
                    .chain(e.removed())
                    .copied()
                    .collect();
                if let Ok(update) = awareness.update_with_clients(changed) {
                    let msg = Message::Awareness(update).encode_v1();
                    let _ = sink_tx2.send(msg);
                }
            }
        });

        Self {
            doc_sub,
            awareness_sub,
            awareness,
            sender,
        }
    }

    pub fn awareness(&self) -> &Arc<Awareness> {
        &self.awareness
    }

    pub fn subscribe(
        &self,
        sink: Arc<Mutex<SplitSink<WebSocketStream<tokio::net::TcpStream>, TungsteniteMsg>>>,
        stream: SplitStream<WebSocketStream<tokio::net::TcpStream>>,
    ) -> (JoinHandle<Result<(), Error>>, JoinHandle<Result<(), Error>>) {
        self.subscribe_with(sink, stream, yrs::sync::DefaultProtocol)
    }

    pub fn subscribe_with<P: Protocol + Send + Sync + 'static>(
        &self,
        sink: Arc<Mutex<SplitSink<WebSocketStream<tokio::net::TcpStream>, TungsteniteMsg>>>,
        mut stream: SplitStream<WebSocketStream<tokio::net::TcpStream>>,
        protocol: P,
    ) -> (JoinHandle<Result<(), Error>>, JoinHandle<Result<(), Error>>) {
        // sink_task: forward broadcast channel messages to this client
        let sink_task = {
            let sink = sink.clone();
            let mut receiver = self.sender.subscribe();
            tokio::spawn(async move {
                while let Ok(msg) = receiver.recv().await {
                    let mut s = sink.lock().await;
                    if let Err(e) = s.send(TungsteniteMsg::Binary(msg.into())).await {
                        return Err(Error::Other(Box::new(e)));
                    }
                }
                Ok(())
            })
        };

        // stream_task: handshake + read client messages + send replies
        let stream_task = {
            let awareness = self.awareness().clone();
            let sink_weak = Arc::downgrade(&sink);
            tokio::spawn(async move {
                // initial handshake: SyncStep1 + awareness
                let payload = {
                    let mut encoder = EncoderV1::new();
                    protocol.start(&*awareness, &mut encoder)?;
                    encoder.to_vec()
                };
                if !payload.is_empty() {
                    if let Some(s) = sink_weak.upgrade() {
                        let mut s = s.lock().await;
                        s.send(TungsteniteMsg::Binary(payload.into()))
                            .await
                            .map_err(|e| Error::Other(Box::new(e)))?;
                    }
                }

                while let Some(res) = stream.next().await {
                    let data = match res {
                        Ok(TungsteniteMsg::Binary(data)) => data.to_vec(),
                        Ok(_) => continue,
                        Err(e) => return Err(Error::Other(Box::new(e))),
                    };
                    let msg = Message::decode_v1(&data)?;
                    let reply = Self::handle_msg(&protocol, &awareness, msg).await?;
                    if let Some(reply) = reply {
                        if let Some(sink) = sink_weak.upgrade() {
                            let mut sink = sink.lock().await;
                            sink.send(TungsteniteMsg::Binary(reply.encode_v1().into()))
                                .await
                                .map_err(|e| Error::Other(Box::new(e)))?;
                        } else {
                            return Ok(());
                        }
                    }
                }
                Ok(())
            })
        };

        (sink_task, stream_task)
    }

    async fn handle_msg<P: Protocol>(
        protocol: &P,
        awareness: &Awareness,
        msg: Message,
    ) -> Result<Option<Message>, Error> {
        match msg {
            Message::Sync(msg) => match msg {
                SyncMessage::SyncStep1(sv) => protocol.handle_sync_step1(awareness, sv),
                SyncMessage::SyncStep2(update) => {
                    let update = Update::decode_v1(&update)?;
                    protocol.handle_sync_step2(awareness, update)
                }
                SyncMessage::Update(update) => {
                    let update = Update::decode_v1(&update)?;
                    protocol.handle_update(awareness, update)
                }
            },
            Message::Auth(reason) => protocol.handle_auth(awareness, reason),
            Message::AwarenessQuery => protocol.handle_awareness_query(awareness),
            Message::Awareness(update) => protocol.handle_awareness_update(awareness, update),
            Message::Custom(tag, data) => protocol.missing_handle(awareness, tag, data),
        }
    }
}

// ---------------------------------------------------------------------------
// Room store – multiple documents keyed by room name
// ---------------------------------------------------------------------------

pub struct RoomStore {
    rooms: StdMutex<HashMap<String, Arc<BroadcastGroup>>>,
    doc_counter: AtomicU64,
}

impl RoomStore {
    pub fn get_or_create_room(&self, name: &str) -> Arc<BroadcastGroup> {
        let mut rooms = self.rooms.lock().unwrap();
        if let Some(bcast) = rooms.get(name) {
            return bcast.clone();
        }
        let client_id = self.doc_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let doc = Doc::with_client_id(client_id);
        let awareness = Arc::new(Awareness::new(doc));
        let bcast = BroadcastGroup::new(awareness, BROADCAST_BUFFER);
        let bcast = Arc::new(bcast);
        rooms.insert(name.to_string(), bcast.clone());
        bcast
    }

    pub fn room_count(&self) -> usize {
        self.rooms.lock().unwrap().len()
    }
}

impl Default for RoomStore {
    fn default() -> Self {
        Self {
            rooms: StdMutex::new(HashMap::new()),
            doc_counter: AtomicU64::new(0),
        }
    }
}

// ---------------------------------------------------------------------------
// Tauri state + commands
// ---------------------------------------------------------------------------

struct RoomCallback {
    room_tx: std::sync::mpsc::Sender<String>,
}

impl Callback for RoomCallback {
    fn on_request(
        self,
        request: &Request,
        response: Response,
    ) -> StdResult<Response, ErrorResponse> {
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

use std::result::Result as StdResult;

async fn handle_ws(
    socket: WebSocketStream<tokio::net::TcpStream>,
    room: String,
    store: Arc<RoomStore>,
) {
    info!("WebSocket connected to room: {}", room);
    let bcast = store.get_or_create_room(&room);
    let (write, read) = socket.split();
    let sink = Arc::new(Mutex::new(write));
    let stream = read;
    let (sink_task, stream_task) = bcast.subscribe(sink, stream);
    let res = tokio::select! {
        r1 = sink_task => r1,
        r2 = stream_task => r2,
    };
    match res.map_err(|e| Error::Other(e.into())) {
        Ok(_) => debug!("WebSocket disconnected from room: {}", room),
        Err(e) => warn!("WebSocket error in room {}: {}", room, e),
    }
}

#[tauri::command]
pub async fn start_collab_server(
    state: tauri::State<'_, crate::CollabServerState>,
    port: u16,
) -> Result<String, String> {
    {
        let handle_guard = state.server_handle.lock().unwrap();
        if handle_guard.is_some() {
            return Err("Collaboration server is already running".to_string());
        }
    }

    let store = state.store.clone();
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .map_err(|e| format!("Failed to bind to port {}: {}", port, e))?;
    let actual_port = listener.local_addr().map_err(|e| e.to_string())?.port();
    *state.port.lock().unwrap() = actual_port;
    let mdns = flying::mdns::advertise_collab_service(actual_port)
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

            let store = store.clone();
            tokio::spawn(async move {
                let (room_tx, room_rx) = std::sync::mpsc::channel::<String>();
                let callback = RoomCallback { room_tx };
                match accept_hdr_async(socket, callback).await {
                    Ok(ws_stream) => {
                        if let Ok(room) = room_rx.recv() {
                            handle_ws(ws_stream, room, store).await;
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
    state: tauri::State<'_, crate::CollabServerState>,
) -> Result<String, String> {
    let mut handle_guard = state.server_handle.lock().unwrap();
    if let Some(handle) = handle_guard.take() {
        handle.abort();
        *state.port.lock().unwrap() = 0;
        state.store.rooms.lock().unwrap().clear();
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
    state: tauri::State<'_, crate::CollabServerState>,
) -> Result<serde_json::Value, String> {
    let handle_guard = state.server_handle.lock().unwrap();
    let is_running = handle_guard.is_some();
    let port = *state.port.lock().unwrap();
    let room_count = state.store.room_count();
    Ok(serde_json::json!({
        "running": is_running,
        "port": port,
        "room_count": room_count
    }))
}
