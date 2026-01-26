use ring::{digest, hkdf, hmac};
use socket2::{Domain, Protocol, Socket, Type};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc::Sender,
};
const CHUNK_SIZE: usize = 1_048_576;
const SPAKE2_MSG_SIZE: usize = 33;
const HMAC_TAG_SIZE: usize = 32;
const KEY_SIZE: usize = 32;
const SHARED_SECRET_SIZE: usize = 32;
const MODE_RECEIVE: u64 = 0;
const MODE_SEND: u64 = 1;

struct MyKeyType(usize);

impl hkdf::KeyType for MyKeyType {
    fn len(&self) -> usize {
        self.0
    }
}

pub async fn hash_file(file: &mut File) -> io::Result<digest::Digest> {
    file.seek(std::io::SeekFrom::Start(0)).await?;

    let mut context = digest::Context::new(&digest::SHA256);
    let mut buffer = vec![0u8; CHUNK_SIZE];

    loop {
        let bytes_read = file.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }
        context.update(&buffer[..bytes_read]);
    }

    file.seek(std::io::SeekFrom::Start(0)).await?;
    Ok(context.finish())
}

#[derive(Default)]
pub struct ProgressTracker {
    last_percent: u8,
    progress_tx: Option<Sender<u8>>,
}

impl ProgressTracker {
    pub fn with_channel(progress_tx: Sender<u8>) -> Self {
        Self {
            progress_tx: Some(progress_tx),
            ..Default::default()
        }
    }

    pub fn update(&mut self, bytes_processed: u64, total_bytes: u64) -> io::Result<()> {
        let percent_done = ((bytes_processed as f64 / total_bytes as f64) * 100.0) as u8;
        if percent_done > self.last_percent {
            print!("\rProgress: {}%", percent_done);
            io::stdout().flush()?;
            self.last_percent = percent_done;

            // Send progress through channel if available
            if let Some(tx) = &self.progress_tx {
                let _ = tx.try_send(percent_done);
            }
        }
        Ok(())
    }

    pub fn finish(&self) -> io::Result<()> {
        println!("\rProgress: 100%");

        if let Some(tx) = &self.progress_tx {
            let _ = tx.try_send(100);
        }

        Ok(())
    }
}

pub async fn version_handshake(stream: &mut TcpStream, version: u64) -> anyhow::Result<()> {
    let (mut read_half, mut write_half) = stream.split();

    let (_, peer_version) = tokio::try_join!(write_half.write_u64(version), read_half.read_u64())?;

    if peer_version != version {
        println!(
            "Warning: Version mismatch (local: {}, peer: {})",
            version, peer_version
        );
    }

    Ok(())
}

pub async fn mode_handshake(stream: &mut TcpStream, mode: u64) -> anyhow::Result<()> {
    let (mut read_half, mut write_half) = stream.split();

    let (_, peer_mode) = tokio::try_join!(write_half.write_u64(mode), read_half.read_u64())?;

    if peer_mode == mode {
        anyhow::bail!("Mode mismatch: both sides in same mode");
    }

    Ok(())
}

pub async fn pake_handshake(
    stream: &mut TcpStream,
    password: &str,
    is_receiver: bool,
) -> anyhow::Result<[u8; SHARED_SECRET_SIZE]> {
    let (state, outbound_msg) = if is_receiver {
        Spake2::<Ed25519Group>::start_b(
            &Password::new(password),
            &Identity::new(b"sender"),
            &Identity::new(b"receiver"),
        )
    } else {
        Spake2::<Ed25519Group>::start_a(
            &Password::new(password),
            &Identity::new(b"sender"),
            &Identity::new(b"receiver"),
        )
    };

    let (mut read_half, mut write_half) = stream.split();
    let mut inbound_msg = vec![0u8; SPAKE2_MSG_SIZE];

    tokio::try_join!(
        write_half.write_all(&outbound_msg),
        read_half.read_exact(&mut inbound_msg)
    )?;

    let shared_secret: [u8; SHARED_SECRET_SIZE] = state
        .finish(&inbound_msg)
        .map_err(|_| anyhow::anyhow!("PAKE failed: incorrect password or protocol error"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid shared secret length"))?;

    // Derive encryption key using HKDF
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"flying-v5");
    let prk = salt.extract(&shared_secret);

    let aead_info: &[&[u8]] = &[b"aead-key"];
    let mut aead_key = [0u8; KEY_SIZE];
    prk.expand(aead_info, MyKeyType(KEY_SIZE))
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?
        .fill(&mut aead_key)
        .map_err(|_| anyhow::anyhow!("HKDF key derivation failed"))?;

    // Key confirmation using HMAC
    let hmac_info: &[&[u8]] = &[b"hmac-key"];
    let mut hmac_key_bytes = [0u8; KEY_SIZE];
    prk.expand(hmac_info, MyKeyType(KEY_SIZE))
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?
        .fill(&mut hmac_key_bytes)
        .map_err(|_| anyhow::anyhow!("HKDF key derivation failed"))?;

    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key_bytes);

    let (our_role, peer_role): (&[u8], &[u8]) = if is_receiver {
        (b"receiver", b"sender")
    } else {
        (b"sender", b"receiver")
    };

    let our_tag = hmac::sign(&hmac_key, our_role);
    let mut peer_tag = vec![0u8; HMAC_TAG_SIZE];
    tokio::try_join!(
        write_half.write_all(our_tag.as_ref()),
        read_half.read_exact(&mut peer_tag)
    )?;

    hmac::verify(&hmac_key, peer_role, &peer_tag)
        .map_err(|_| anyhow::anyhow!("Key confirmation failed: password mismatch"))?;

    Ok(aead_key)
}

pub async fn send_handshake(
    stream: &mut TcpStream,
    version: u64,
    password: &str,
    relative_path: &str,
    is_folder: bool,
) -> anyhow::Result<ring::aead::LessSafeKey> {
    version_handshake(stream, version).await?;
    mode_handshake(stream, MODE_SEND).await?;
    let key_bytes = pake_handshake(stream, password, false).await?;

    stream.write_u64(relative_path.len() as u64).await?;
    stream.write_all(relative_path.as_bytes()).await?;
    stream.write_u64(u64::from(is_folder)).await?;

    let unbound_key = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &key_bytes)
        .map_err(|_| anyhow::anyhow!("Failed to create encryption key"))?;
    Ok(ring::aead::LessSafeKey::new(unbound_key))
}

pub async fn receive_handshake(
    stream: &mut TcpStream,
    version: u64,
    password: &str,
) -> anyhow::Result<(ring::aead::LessSafeKey, String, bool)> {
    version_handshake(stream, version).await?;
    mode_handshake(stream, MODE_RECEIVE).await?;
    let key_bytes = pake_handshake(stream, password, true).await?;

    let len = stream.read_u64().await? as usize;
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes).await?;
    let relative_path = String::from_utf8_lossy(&bytes).to_string();
    let is_folder = stream.read_u64().await? == 1;

    let unbound_key = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &key_bytes)
        .map_err(|_| anyhow::anyhow!("Failed to create decryption key"))?;
    let key = ring::aead::LessSafeKey::new(unbound_key);

    Ok((key, relative_path, is_folder))
}

pub fn create_listener(port: u16) -> anyhow::Result<TcpListener> {
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

pub async fn handle_filename_conflict(mut path: PathBuf) -> PathBuf {
    let mut counter = 1;
    while tokio::fs::metadata(&path)
        .await
        .map(|m| m.is_file())
        .unwrap_or(false)
    {
        let original_name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let extension = path.extension().and_then(|s| s.to_str());

        let new_name = if let Some(ext) = extension {
            format!("{} ({}).{}", original_name, counter, ext)
        } else {
            format!("{} ({})", original_name, counter)
        };
        path.pop();
        path.push(new_name);
        counter += 1;
    }
    path
}
