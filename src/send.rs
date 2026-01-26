use crate::utils;
use humansize::{BINARY, format_size};
use ring::{aead, rand};
use std::{
    path::Path,
    time::{Duration, Instant},
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc::Sender,
};

const CHUNK_SIZE: usize = 1_048_576; // 1 MiB

async fn send_metadata(stream: &mut TcpStream, filename: &str, size: u64) -> anyhow::Result<()> {
    stream.write_u64(filename.len() as u64).await?;
    stream.write_all(filename.as_bytes()).await?;
    stream.write_u64(size).await?;
    Ok(())
}

async fn check_duplicate(stream: &mut TcpStream, file: &mut File) -> anyhow::Result<bool> {
    let has_file = stream.read_u64().await?;
    if has_file == 1 {
        let (mut read_half, mut write_half) = stream.split();
        let local_hash = utils::hash_file(file).await?;
        let mut peer_hash = vec![0; 32];

        tokio::try_join!(
            write_half.write_all(local_hash.as_ref()),
            read_half.read_exact(&mut peer_hash)
        )?;

        let matches = local_hash.as_ref() == &peer_hash[..];
        Ok(matches)
    } else {
        Ok(false)
    }
}

async fn encrypt_and_send(
    stream: &mut TcpStream,
    mut file: File,
    size: u64,
    key: &aead::LessSafeKey,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    let rng = rand::SystemRandom::new();
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut progress = if let Some(tx) = progress_tx {
        utils::ProgressTracker::with_channel(tx)
    } else {
        Default::default()
    };
    let mut bytes_sent = 0u64;

    loop {
        let bytes_read = file.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }

        let plaintext = &buffer[..bytes_read];
        let mut in_out = plaintext.to_vec();

        let nonce_bytes = rand::generate::<[u8; aead::NONCE_LEN]>(&rng)
            .map_err(|_| anyhow::anyhow!("RNG failure"))?;
        let nonce_slice = nonce_bytes.expose();
        let nonce = aead::Nonce::assume_unique_for_key(nonce_slice);

        key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

        // Send nonce + ciphertext
        let mut packet = nonce_slice.to_vec();
        packet.extend_from_slice(&in_out);

        stream.write_u64(packet.len() as u64).await?;
        stream.write_all(&packet).await?;

        bytes_sent += bytes_read as u64;
        progress.update(bytes_sent, size)?;
    }

    stream.write_u64(0).await?; // Signal end of file
    progress.finish()?;

    Ok(())
}

pub async fn send_file(
    stream: &mut TcpStream,
    mut file: File,
    filename: &str,
    size: u64,
    key: &aead::LessSafeKey,
    is_single_file: bool,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    let start = Instant::now();

    println!("Sending file: {}", filename);
    println!("File size: {}", format_size(size, BINARY));

    send_metadata(stream, filename, size).await?;

    if is_single_file && check_duplicate(stream, &mut file).await? {
        println!("Recipient already has this file, skipping.");
        return Ok(());
    }

    encrypt_and_send(stream, file, size, key, progress_tx).await?;

    let elapsed = start.elapsed();
    println!(
        "Sending took {}",
        humantime::format_duration(Duration::from_secs_f64(elapsed.as_secs_f64()))
    );

    let megabits = 8.0 * (size as f64 / 1_000_000.0);
    println!("Speed: {:.2} Mbps", megabits / elapsed.as_secs_f64());

    Ok(())
}

pub async fn send_from_path(
    stream: &mut TcpStream,
    file_path: &Path,
    base_path: &Path,
    key: &aead::LessSafeKey,
    is_single_file: bool,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    let metadata = tokio::fs::metadata(file_path).await?;
    let size = metadata.len();

    // Extract filename: if base_path is empty use only the filename,
    // otherwise use the relative path from base_path (preserves folder structure)
    let filename = if base_path.as_os_str().is_empty() {
        file_path.file_name().unwrap().to_string_lossy().to_string()
    } else {
        file_path
            .strip_prefix(base_path)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string()
    };

    let file = File::open(file_path).await?;
    send_file(
        stream,
        file,
        &filename,
        size,
        key,
        is_single_file,
        progress_tx,
    )
    .await
}
