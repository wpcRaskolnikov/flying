use futures_util::stream::SplitSink;
use futures_util::{SinkExt, Stream, StreamExt};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::handshake::server::{Callback, ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::Message as TungsteniteMsg;
use tokio_tungstenite::{accept_hdr_async, WebSocketStream};
use tracing::{debug, info, warn};
#[allow(unused_imports)]
use yrs::encoding::write::Write;
#[allow(unused_imports)]
use yrs::sync::protocol::{MSG_SYNC, MSG_SYNC_UPDATE};
use yrs::sync::{Awareness, Error, Message, Protocol, SyncMessage};
use yrs::updates::decoder::Decode;
use yrs::updates::encoder::{Encode, Encoder, EncoderV1};
use yrs::Update;
use yrs::{Doc, Subscription};

const BROADCAST_BUFFER: usize = 64;

// ---------------------------------------------------------------------------
// TungsteniteSink / TungsteniteStream – adapt tokio-tungstenite WebSocket into futures Sink / Stream
// ---------------------------------------------------------------------------

pub struct TungsteniteSink {
    inner: SplitSink<WebSocketStream<tokio::net::TcpStream>, TungsteniteMsg>,
}

impl TungsteniteSink {
    pub fn new(inner: SplitSink<WebSocketStream<tokio::net::TcpStream>, TungsteniteMsg>) -> Self {
        Self { inner }
    }
}

impl futures_util::Sink<Vec<u8>> for TungsteniteSink {
    type Error = Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        match Pin::new(&mut self.inner).poll_ready(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(Error::Other(Box::new(e)))),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        Pin::new(&mut self.inner)
            .start_send(TungsteniteMsg::Binary(item.into()))
            .map_err(|e| Error::Other(Box::new(e)))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(Error::Other(Box::new(e)))),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
        }
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        match Pin::new(&mut self.inner).poll_close(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(Error::Other(Box::new(e)))),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
        }
    }
}

pub struct TungsteniteStream {
    inner: futures_util::stream::SplitStream<WebSocketStream<tokio::net::TcpStream>>,
}

impl TungsteniteStream {
    pub fn new(inner: futures_util::stream::SplitStream<WebSocketStream<tokio::net::TcpStream>>) -> Self {
        Self { inner }
    }
}

impl Stream for TungsteniteStream {
    type Item = Result<Vec<u8>, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Ok(msg))) => Poll::Ready(Some(Ok(msg.into_data().to_vec()))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(Error::Other(Box::new(e))))),
        }
    }
}

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
    awareness_updater: JoinHandle<()>,
}

unsafe impl Send for BroadcastGroup {}
unsafe impl Sync for BroadcastGroup {}

impl BroadcastGroup {
    pub async fn new(awareness: Arc<Awareness>, buffer_capacity: usize) -> Self {
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

        // Observe awareness changes via mpsc channel -> dedicated task
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u64>>();
        let sink_tx2 = sender.clone();
        let awareness_weak = Arc::downgrade(&awareness);
        let awareness_sub = awareness.on_update(move |_awareness, e, _origin| {
            let changed: Vec<u64> = e
                .added()
                .iter()
                .chain(e.updated())
                .chain(e.removed())
                .copied()
                .collect();
            let _ = tx.send(changed);
        });

        let awareness_updater = tokio::spawn(async move {
            while let Some(changed_clients) = rx.recv().await {
                if let Some(awareness) = awareness_weak.upgrade() {
                    match awareness.update_with_clients(changed_clients) {
                        Ok(update) => {
                            let msg = Message::Awareness(update).encode_v1();
                            let _ = sink_tx2.send(msg);
                        }
                        Err(e) => warn!("awareness update error: {}", e),
                    }
                } else {
                    return;
                }
            }
        });

        Self {
            doc_sub,
            awareness_sub,
            awareness,
            sender,
            awareness_updater,
        }
    }

    pub fn awareness(&self) -> &Arc<Awareness> {
        &self.awareness
    }

    pub fn subscribe(&self, sink: Arc<Mutex<TungsteniteSink>>, stream: TungsteniteStream) -> Subscription_ {
        self.subscribe_with(sink, stream, yrs::sync::DefaultProtocol)
    }

    pub fn subscribe_with<P: Protocol + Send + Sync + 'static>(
        &self,
        sink: Arc<Mutex<TungsteniteSink>>,
        mut stream: TungsteniteStream,
        protocol: P,
    ) -> Subscription_ {
        // sink_task: forward broadcast channel messages to this client
        let sink_task = {
            let sink = sink.clone();
            let mut receiver = self.sender.subscribe();
            tokio::spawn(async move {
                while let Ok(msg) = receiver.recv().await {
                    let mut s = sink.lock().await;
                    if let Err(e) = s.send(msg).await {
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
                        s.send(payload)
                            .await
                            .map_err(|e| Error::Other(Box::new(e)))?;
                    }
                }

                while let Some(res) = stream.next().await {
                    let data = res.map_err(|e| Error::Other(Box::new(e)))?;
                    let msg = Message::decode_v1(&data)?;
                    let reply = Self::handle_msg(&protocol, &awareness, msg).await?;
                    if let Some(reply) = reply {
                        if let Some(sink) = sink_weak.upgrade() {
                            let mut sink = sink.lock().await;
                            sink.send(reply.encode_v1())
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

        Subscription_ {
            sink_task,
            stream_task,
        }
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

impl Drop for BroadcastGroup {
    fn drop(&mut self) {
        self.awareness_updater.abort();
    }
}

pub struct Subscription_ {
    sink_task: JoinHandle<Result<(), Error>>,
    stream_task: JoinHandle<Result<(), Error>>,
}

impl Subscription_ {
    pub async fn completed(self) -> Result<(), Error> {
        let res = tokio::select! {
            r1 = self.sink_task => r1,
            r2 = self.stream_task => r2,
        };
        res.map_err(|e| Error::Other(e.into()))?
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
    pub fn new() -> Self {
        Self {
            rooms: StdMutex::new(HashMap::new()),
            doc_counter: AtomicU64::new(0),
        }
    }

    pub fn get_or_create_room(&self, name: &str) -> Arc<BroadcastGroup> {
        let mut rooms = self.rooms.lock().unwrap();
        if let Some(bcast) = rooms.get(name) {
            return bcast.clone();
        }
        let client_id = self.doc_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let doc = Doc::with_client_id(client_id);
        // Pre-create the "codemirror" text type so y-codemirror.next works
        doc.get_or_insert_text("codemirror");
        let awareness = Arc::new(Awareness::new(doc));
        let bcast = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(BroadcastGroup::new(awareness, BROADCAST_BUFFER))
        });
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
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tauri state + commands
// ---------------------------------------------------------------------------

pub struct CollabServerState {
    pub store: Arc<RoomStore>,
    pub server_handle: StdMutex<Option<JoinHandle<()>>>,
    pub port: StdMutex<u16>,
    pub mdns_daemon: StdMutex<Option<flying::mdns::ServiceDaemon>>,
}

impl CollabServerState {
    pub fn new() -> Self {
        Self {
            store: Arc::new(RoomStore::new()),
            server_handle: StdMutex::new(None),
            port: StdMutex::new(0),
            mdns_daemon: StdMutex::new(None),
        }
    }
}

impl Default for CollabServerState {
    fn default() -> Self {
        Self::new()
    }
}

// Callback that extracts room name from the HTTP request path
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

async fn handle_ws(socket: WebSocketStream<tokio::net::TcpStream>, room: String, store: Arc<RoomStore>) {
    info!("WebSocket connected to room: {}", room);
    let bcast = store.get_or_create_room(&room);
    let (write, read) = socket.split();
    let sink = Arc::new(Mutex::new(TungsteniteSink::new(write)));
    let stream = TungsteniteStream::new(read);
    let sub = bcast.subscribe(sink, stream);
    match sub.completed().await {
        Ok(_) => debug!("WebSocket disconnected from room: {}", room),
        Err(e) => warn!("WebSocket error in room {}: {}", room, e),
    }
}

#[tauri::command]
pub async fn start_collab_server(
    state: tauri::State<'_, CollabServerState>,
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

    // Start mDNS broadcast for collab service
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
    state: tauri::State<'_, CollabServerState>,
) -> Result<String, String> {
    let mut handle_guard = state.server_handle.lock().unwrap();
    if let Some(handle) = handle_guard.take() {
        handle.abort();
        *state.port.lock().unwrap() = 0;
        state.store.rooms.lock().unwrap().clear();
        // Stop mDNS broadcast (ServiceDaemon stops on drop)
        drop(state.mdns_daemon.lock().unwrap().take());
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
    let room_count = state.store.room_count();
    Ok(serde_json::json!({
        "running": is_running,
        "port": port,
        "room_count": room_count
    }))
}
