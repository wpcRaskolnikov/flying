use flying::mdns::ServiceDaemon;
use serde::Serialize;

#[cfg(not(target_os = "android"))]
use tauri::Manager;
use tauri_plugin_store::StoreExt;

use std::collections::HashMap;
use std::sync::{
    Arc, Mutex as StdMutex,
    atomic::{AtomicU64, Ordering},
};

use tokio::net::TcpStream;
use tokio::sync::{broadcast, oneshot::Sender as OneshotSender};
use tokio::task::JoinHandle;

use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message as TungsteniteMsg;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};

use yrs::sync::{Awareness, DefaultProtocol, Error, Message, Protocol, SyncMessage};
use yrs::updates::{
    decoder::Decode,
    encoder::{Encode, Encoder, EncoderV1},
};
use yrs::{Doc, Subscription, Update};

const ROOM_BUFFER: usize = 64;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferStatusPayload {
    pub status: String,
    pub progress: u8,
    pub message: Option<String>,
    pub peer_id: Option<String>,
}

pub struct RoomManager {
    room_map: StdMutex<HashMap<String, Arc<Room>>>,
    next_client_id: AtomicU64,
}

impl Default for RoomManager {
    fn default() -> Self {
        Self {
            room_map: StdMutex::new(HashMap::new()),
            next_client_id: AtomicU64::new(1),
        }
    }
}

impl RoomManager {
    pub fn get_or_create_room(&self, name: &str) -> Arc<Room> {
        let mut room_map = self.room_map.lock().unwrap();
        if let Some(room) = room_map.get(name) {
            return Arc::clone(&room);
        }
        let client_id = self.next_client_id.fetch_add(1, Ordering::Relaxed);
        let doc = Doc::with_client_id(client_id);
        let room = Arc::new(Room::new(doc, ROOM_BUFFER));
        room_map.insert(name.to_string(), Arc::clone(&room));
        room
    }
}

pub struct Room {
    #[allow(dead_code)]
    doc_sub: Subscription,
    #[allow(dead_code)]
    awareness_sub: Subscription,
    #[allow(dead_code)]
    doc: Doc,
    awareness: Arc<Awareness>,
    sender: broadcast::Sender<Vec<u8>>,
}

impl Room {
    pub fn new(doc: Doc, buffer_capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(buffer_capacity);

        let awareness = Arc::new(Awareness::new(doc.clone()));

        // Observe document updates
        let sink_tx = sender.clone();
        let doc_sub = doc
            .observe_update_v1(move |_txn, u| {
                let msg = Message::Sync(SyncMessage::Update(u.update.clone())).encode_v1();
                let _ = sink_tx.send(msg);
            })
            .unwrap();

        // Observe awareness changes
        let sink_tx2 = sender.clone();
        let awareness_sub = awareness.on_update(move |aw, e, _origin| {
            let changed: Vec<u64> = e
                .added()
                .iter()
                .chain(e.updated())
                .chain(e.removed())
                .copied()
                .collect();
            if let Ok(update) = aw.update_with_clients(changed) {
                let msg = Message::Awareness(update).encode_v1();
                let _ = sink_tx2.send(msg);
            }
        });

        Self {
            doc_sub,
            awareness_sub,
            doc,
            awareness,
            sender,
        }
    }

    #[allow(dead_code)]
    pub fn doc(&self) -> &Doc {
        &self.doc
    }

    pub fn awareness(&self) -> Arc<Awareness> {
        Arc::clone(&self.awareness)
    }

    pub fn subscribe(
        &self,
        mut sink: SplitSink<WebSocketStream<TcpStream>, TungsteniteMsg>,
        mut stream: SplitStream<WebSocketStream<TcpStream>>,
    ) -> JoinHandle<Result<(), Error>> {
        let mut broadcast_rx = self.sender.subscribe();
        let awareness = self.awareness();

        tokio::spawn(async move {
            // handshake
            let payload = {
                let mut encoder = EncoderV1::new();
                DefaultProtocol.start(&*awareness, &mut encoder)?;
                encoder.to_vec()
            };
            if !payload.is_empty() {
                sink.send(TungsteniteMsg::Binary(payload.into()))
                    .await
                    .map_err(|e| Error::Other(Box::new(e)))?;
            }

            loop {
                tokio::select! {
                    msg = broadcast_rx.recv() => {
                        let Ok(msg) = msg else { break Ok(()) };
                        sink.send(TungsteniteMsg::Binary(msg.into()))
                            .await
                            .map_err(|e| Error::Other(Box::new(e)))?;
                    }
                    res = stream.next() => {
                        let Some(data) = res else { break Ok(()) };
                        let data = match data {
                            Ok(TungsteniteMsg::Binary(d)) => d.to_vec(),
                            Ok(_) => continue,
                            Err(e) => break Err(Error::Other(Box::new(e))),
                        };
                        let msg = Message::decode_v1(&data)?;
                        let reply = match msg {
                            Message::Sync(msg) => match msg {
                                SyncMessage::SyncStep1(sv) => DefaultProtocol.handle_sync_step1(&*awareness, sv),
                                SyncMessage::SyncStep2(update) => {
                                    let update = Update::decode_v1(&update)?;
                                    DefaultProtocol.handle_sync_step2(&*awareness, update)
                                }
                                SyncMessage::Update(update) => {
                                    let update = Update::decode_v1(&update)?;
                                    DefaultProtocol.handle_update(&*awareness, update)
                                }
                            },
                            Message::Auth(reason) => DefaultProtocol.handle_auth(&*awareness, reason),
                            Message::AwarenessQuery => DefaultProtocol.handle_awareness_query(&*awareness),
                            Message::Awareness(update) => DefaultProtocol.handle_awareness_update(&*awareness, update),
                            Message::Custom(tag, data) => DefaultProtocol.missing_handle(&*awareness, tag, data),
                        }?;
                        if let Some(reply) = reply {
                            sink.send(TungsteniteMsg::Binary(reply.encode_v1().into()))
                                .await
                                .map_err(|e| Error::Other(Box::new(e)))?;
                        }
                    }
                }
            }
        })
    }
}

#[derive(Default, Clone)]
pub struct TransferState {
    pub abort_handle: Arc<StdMutex<Option<OneshotSender<()>>>>,
    pub mdns_daemon: Arc<StdMutex<Option<ServiceDaemon>>>,
}

#[derive(Default)]
pub struct CollabServerState {
    pub room_manager: Arc<RoomManager>,
    pub abort_handle: StdMutex<Option<OneshotSender<()>>>,
    pub mdns_daemon: StdMutex<Option<ServiceDaemon>>,
}

#[tauri::command]
pub fn get_default_folder(app: tauri::AppHandle) -> Result<String, String> {
    let store = app
        .store("settings.json")
        .map_err(|e| format!("Failed to load store: {}", e))?;

    #[cfg(target_os = "android")]
    let path = "/storage/emulated/0/Download".to_string();

    #[cfg(not(target_os = "android"))]
    let path = match store.get("default_folder_path") {
        Some(json_val) => json_val.as_str().unwrap_or("").to_string(),
        None => app
            .path()
            .download_dir()
            .map_err(|e| format!("Failed to get download directory:{}", e))?
            .to_string_lossy()
            .to_string(),
    };
    store.close_resource();
    Ok(path)
}
