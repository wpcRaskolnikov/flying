use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::{
    fs,
    io::{self, Write},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub fn get_key_from_password(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.finalize().into()
}

fn derive_key(session_key: &[u8; 32], context: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"flying"), session_key);
    let mut okm = [0u8; 32];
    hk.expand(context, &mut okm).expect("HKDF expand failed");
    okm
}

pub fn generate_password() -> String {
    petname::petname(3, "-").unwrap_or_else(|| "flying-transfer-secret".to_string())
}

pub fn hash_file(file: &fs::File) -> io::Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file_ref = file;

    file_ref.seek(SeekFrom::Start(0))?;

    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1_000_000]; // 1MB buffer

    loop {
        let bytes_read = file_ref.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    file_ref.seek(SeekFrom::Start(0))?;

    Ok(hasher.finalize().to_vec())
}

pub struct ProgressTracker {
    last_percent: u8,
}

impl ProgressTracker {
    pub fn new() -> Self {
        Self { last_percent: 0 }
    }

    pub fn update(&mut self, bytes_processed: u64, total_bytes: u64) -> io::Result<()> {
        let percent_done = ((bytes_processed as f64 / total_bytes as f64) * 100.0) as u8;
        if percent_done > self.last_percent {
            print!("\rProgress: {}%", percent_done);
            io::stdout().flush()?;
            self.last_percent = percent_done;
        }
        Ok(())
    }

    pub fn finish(&self) -> io::Result<()> {
        println!("\rProgress: 100%");
        Ok(())
    }
}

pub async fn version_handshake(
    stream: &mut TcpStream,
    send_first: bool,
    version: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer_version = if send_first {
        stream.write_u64(version).await?;
        stream.read_u64().await?
    } else {
        let peer = stream.read_u64().await?;
        stream.write_u64(version).await?;
        peer
    };

    if peer_version != version {
        println!(
            "Warning: Version mismatch (local: {}, peer: {})",
            version, peer_version
        );
    }

    Ok(())
}

pub async fn mode_shake(
    stream: &mut TcpStream,
    send_first: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Mode: 1 = send, 0 = receive
    let our_mode = if send_first { 0 } else { 1 };

    if send_first {
        // Receiver sends first, then reads peer's response
        stream.write_u64(our_mode).await?;
        let peer_response = stream.read_u64().await?;
        if peer_response != 1 {
            return Err("Both ends selected the same mode".into());
        }
    } else {
        // Sender reads peer's mode first, then responds
        let peer_mode = stream.read_u64().await?;
        if peer_mode == 1 {
            stream.write_u64(0).await?;
            return Err("Both ends selected send mode".into());
        } else {
            stream.write_u64(1).await?;
        }
    }

    Ok(())
}

fn get_mac(key: &[u8], data: &[u8]) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data);
    mac
}

pub async fn identity_handshake(
    stream: &mut TcpStream,
    password: &str,
    is_receiver: bool,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let our_role = if is_receiver { "receiver" } else { "sender" };
    let peer_role = if is_receiver { "sender" } else { "receiver" };

    // Generate session key using SPAKE2
    let start = if is_receiver {
        Spake2::<Ed25519Group>::start_b
    } else {
        Spake2::<Ed25519Group>::start_a
    };

    let (s1, outbound_msg) = start(
        &Password::new(password),
        &Identity::new(b"sender"),
        &Identity::new(b"receiver"),
    );
    stream.write_all(&outbound_msg).await?;

    let mut inbound_msg = vec![0u8; 33];
    stream.read_exact(&mut inbound_msg).await?;

    let session_key = s1
        .finish(&inbound_msg)
        .map_err(|e| format!("SPAKE2 key exchange failed: {:?}", e))?;
    let session_key = session_key
        .try_into()
        .map_err(|e| format!("Session key conversion failed: {:?}", e))?;

    // Key confirmation
    let hmac_key = derive_key(&session_key, b"hmac key");

    let mac = get_mac(&hmac_key, our_role.as_bytes());
    let our_tag = mac.finalize().into_bytes();
    stream.write_all(&our_tag).await?;

    let mac = get_mac(&hmac_key, peer_role.as_bytes());
    let mut peer_tag = vec![0u8; 32];
    stream.read_exact(&mut peer_tag).await?;

    mac.verify_slice(&peer_tag)
        .map_err(|e| format!("Key confirmation failed: {:?}", e))?;

    // Derive AEC-GCM key
    let aec_key = derive_key(&session_key, b"aec-gcm key");
    Ok(aec_key)
}

pub fn create_listener(port: u16) -> Result<tokio::net::TcpListener, Box<dyn std::error::Error>> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::SocketAddr;

    let addr = format!("[::]:{}", port).parse::<SocketAddr>()?;

    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_only_v6(false)?;
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;

    let std_listener: std::net::TcpListener = socket.into();
    std_listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(std_listener)?;

    Ok(listener)
}
