use crate::utils;
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, aead::Aead, aead::OsRng};
use std::{
    fs::{File, metadata},
    io::Read,
    path::Path,
    time::Instant,
};
use tokio::{io::AsyncWriteExt, net::TcpStream};

const CHUNKSIZE: usize = 1_000_000; // 1 MB

pub async fn send_file(
    file_path: &Path,
    base_path: &Path,
    key: &[u8],
    stream: &mut TcpStream,
    check_duplicate: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let cipher = Aes256Gcm::new_from_slice(key)?;
    let metadata = metadata(file_path)?;
    let size = metadata.len();

    // Calculate relative path
    let relative_path = if base_path.as_os_str().is_empty() {
        file_path.file_name().unwrap().to_string_lossy().to_string()
    } else {
        file_path
            .strip_prefix(base_path)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string()
    };

    println!("Sending file: {}", relative_path);
    println!("File size: {}", utils::make_size_readable(size));

    // Send file details with relative path
    send_file_details(&relative_path, size, stream).await?;

    // For single file, check if receiver already has it
    if check_duplicate {
        let need_transfer = check_for_file(file_path, stream).await?;
        if !need_transfer {
            println!("Recipient already has this file, skipping.");
            return Ok(());
        }
    }

    // Stream file data immediately without waiting for confirmation
    send_file_streaming(file_path, size, &cipher, stream).await?;

    let elapsed = (Instant::now() - start).as_secs_f64();
    println!("Sending took {}", utils::format_time(elapsed));

    let megabits = 8.0 * (size as f64 / 1_000_000.0);
    let mbps = megabits / elapsed;
    println!("Speed: {:.2}mbps", mbps);

    Ok(())
}

pub async fn send_file_from_handle(
    file_handle: File,
    filename: &str,
    size: u64,
    key: &[u8],
    stream: &mut TcpStream,
    check_duplicate: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let cipher = Aes256Gcm::new_from_slice(key)?;

    println!("Sending file: {}", filename);
    println!("File size: {}", utils::make_size_readable(size));

    // Send file details
    send_file_details(filename, size, stream).await?;

    // For single file, check if receiver already has it
    if check_duplicate {
        // Calculate hash from file handle
        let need_transfer = check_for_file_handle(&file_handle, stream).await?;
        if !need_transfer {
            println!("Recipient already has this file, skipping.");
            return Ok(());
        }
    }

    // Stream file data immediately without waiting for confirmation
    send_file_streaming_from_handle(file_handle, size, &cipher, stream).await?;

    let elapsed = (Instant::now() - start).as_secs_f64();
    println!("Sending took {}", utils::format_time(elapsed));

    let megabits = 8.0 * (size as f64 / 1_000_000.0);
    let mbps = megabits / elapsed;
    println!("Speed: {:.2}mbps", mbps);

    Ok(())
}

async fn send_file_streaming(
    file_path: &Path,
    size: u64,
    cipher: &Aes256Gcm,
    stream: &mut TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let handle = File::open(file_path)?;
    send_file_streaming_from_handle(handle, size, cipher, stream).await
}

async fn send_file_streaming_from_handle(
    mut handle: File,
    size: u64,
    cipher: &Aes256Gcm,
    stream: &mut TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = vec![0u8; CHUNKSIZE];

    let mut progress = utils::ProgressTracker::new();
    let mut bytes_sent = 0u64;

    loop {
        match handle.read(&mut buffer) {
            Ok(0) => break,
            Ok(bytes_read) => {
                let chunk = &buffer[..bytes_read];

                // Encrypt the chunk
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

async fn send_file_details(
    filename: &str,
    size: u64,
    stream: &mut TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    stream.write_u64(filename.len() as u64).await?;
    stream.write_all(filename.as_bytes()).await?;
    stream.write_u64(size).await?;
    Ok(())
}

async fn check_for_file(
    filename: &Path,
    stream: &mut TcpStream,
) -> Result<bool, Box<dyn std::error::Error>> {
    use tokio::io::AsyncReadExt;

    let has_file = stream.read_u64().await?;
    if has_file == 1 {
        let hash = utils::hash_file(filename)?;
        stream.write_all(&hash).await?;
        let hashes_match = stream.read_u64().await?;
        Ok(hashes_match != 1)
    } else {
        Ok(true)
    }
}

async fn check_for_file_handle(
    file_handle: &File,
    stream: &mut TcpStream,
) -> Result<bool, Box<dyn std::error::Error>> {
    use tokio::io::AsyncReadExt;

    let has_file = stream.read_u64().await?;
    if has_file == 1 {
        let hash = utils::hash_file_handle(file_handle)?;
        stream.write_all(&hash).await?;
        let hashes_match = stream.read_u64().await?;
        Ok(hashes_match != 1)
    } else {
        Ok(true)
    }
}
