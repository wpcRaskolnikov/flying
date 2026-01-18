use crate::utils;
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, aead::Aead, aead::OsRng};
use humansize::{BINARY, format_size};
use std::{
    fs::{File, metadata},
    io::Read,
    path::Path,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const CHUNKSIZE: usize = 1_000_000; // 1 MB

pub async fn sender_handshake(
    stream: &mut tokio::net::TcpStream,
    version: u64,
    password: &str,
    num_files: u64,
    is_folder: bool,
    folder_name: Option<&str>,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    utils::version_handshake(stream, false, version).await?;
    utils::mode_shake(stream, false).await?;
    let key = utils::identity_handshake(stream, password, false).await?;

    stream.write_u64(num_files).await?;
    stream.write_u64(if is_folder { 1 } else { 0 }).await?;

    if is_folder {
        let folder_name = folder_name.ok_or("Folder name required when is_folder is true")?;
        stream.write_u64(folder_name.len() as u64).await?;
        stream.write_all(folder_name.as_bytes()).await?;
    }

    Ok(key)
}

async fn send_file_details(
    stream: &mut TcpStream,
    filename: &str,
    size: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    stream.write_u64(filename.len() as u64).await?;
    stream.write_all(filename.as_bytes()).await?;
    stream.write_u64(size).await?;
    Ok(())
}

async fn check_for_file(
    stream: &mut TcpStream,
    file: &File,
) -> Result<bool, Box<dyn std::error::Error>> {
    let has_file = stream.read_u64().await?;
    if has_file == 1 {
        let hash = utils::hash_file(file)?;
        stream.write_all(&hash).await?;
        let hashes_match = stream.read_u64().await?;
        Ok(hashes_match != 1)
    } else {
        Ok(true)
    }
}

async fn send_file_streaming(
    stream: &mut TcpStream,
    mut file: File,
    size: u64,
    cipher: &Aes256Gcm,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = vec![0u8; CHUNKSIZE];

    let mut progress = utils::ProgressTracker::new();
    let mut bytes_sent = 0u64;

    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(bytes_read) => {
                let chunk = &buffer[..bytes_read];

                let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
                let encrypted_chunk = cipher
                    .encrypt(&nonce, chunk)
                    .map_err(|e| format!("Encryption error: {:?}", e))?;

                let mut nonce_and_chunk = nonce.to_vec();
                nonce_and_chunk.extend_from_slice(&encrypted_chunk);

                // Send immediately (streaming)
                stream.write_u64(nonce_and_chunk.len() as u64).await?;
                stream.write_all(&nonce_and_chunk).await?;

                bytes_sent += bytes_read as u64;
                progress.update(bytes_sent, size)?;
            }
            Err(e) => return Err(Box::new(e)),
        }
    }

    // Send chunk size of 0 to signal end of this file
    stream.write_u64(0).await?;
    progress.finish()?;

    Ok(())
}

pub async fn send_file_from_handle(
    stream: &mut TcpStream,
    file: File,
    filename: &str,
    size: u64,
    key: &[u8],
    check_duplicate: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let cipher = Aes256Gcm::new_from_slice(key)?;

    println!("Sending file: {}", filename);
    println!("File size: {}", format_size(size, BINARY));

    send_file_details(stream, filename, size).await?;

    if check_duplicate {
        let need_transfer = check_for_file(stream, &file).await?;
        if !need_transfer {
            println!("Recipient already has this file, skipping.");
            return Ok(());
        }
    }

    // Stream file data
    send_file_streaming(stream, file, size, &cipher).await?;

    let elapsed = Instant::now() - start;
    println!(
        "Sending took {}",
        humantime::format_duration(Duration::from_secs_f64(elapsed.as_secs_f64()))
    );

    let megabits = 8.0 * (size as f64 / 1_000_000.0);
    let mbps = megabits / elapsed.as_secs_f64();
    println!("Speed: {:.2}mbps", mbps);

    Ok(())
}

pub async fn send_file_from_path(
    stream: &mut TcpStream,
    file_path: &Path,
    base_path: &Path,
    key: &[u8],
    check_duplicate: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = metadata(file_path)?;
    let size = metadata.len();

    // Calculate relative path
    let filename = if base_path.as_os_str().is_empty() {
        file_path.file_name().unwrap().to_string_lossy().to_string()
    } else {
        file_path
            .strip_prefix(base_path)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string()
    };

    let file = File::open(file_path)?;
    send_file_from_handle(stream, file, &filename, size, key, check_duplicate).await
}
