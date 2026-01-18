use crate::utils;
use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use humansize::{BINARY, format_size};
use std::{
    fs,
    io::Write,
    path::Path,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub async fn receiver_handshake(
    stream: &mut tokio::net::TcpStream,
    version: u64,
    password: &str,
) -> Result<([u8; 32], u64, bool, Option<String>), Box<dyn std::error::Error>> {
    utils::version_handshake(stream, true, version).await?;
    utils::mode_shake(stream, true).await?;
    let key = utils::identity_handshake(stream, password, true).await?;

    // Receive metadata
    let num_files = stream.read_u64().await?;
    let is_folder = stream.read_u64().await? == 1;

    let folder_name = if is_folder {
        let folder_name_len = stream.read_u64().await? as usize;
        let mut folder_name_bytes = vec![0; folder_name_len];
        stream.read_exact(&mut folder_name_bytes).await?;
        Some(String::from_utf8_lossy(&folder_name_bytes).to_string())
    } else {
        None
    };

    Ok((key, num_files, is_folder, folder_name))
}

async fn receive_file_details(
    stream: &mut TcpStream,
) -> Result<(String, u64), Box<dyn std::error::Error>> {
    let filename_size = stream.read_u64().await? as usize;
    let mut filename_bytes = vec![0; filename_size];
    stream.read_exact(&mut filename_bytes).await?;
    let filename = String::from_utf8_lossy(&filename_bytes).to_string();
    let file_size = stream.read_u64().await?;
    Ok((filename, file_size))
}

async fn check_for_file(
    stream: &mut TcpStream,
    file: &fs::File,
) -> Result<bool, Box<dyn std::error::Error>> {
    stream.write_u64(1).await?;
    let local_hash = utils::hash_file(file)?;
    let mut peer_hash = vec![0; 32];
    stream.read_exact(&mut peer_hash).await?;
    let hashes_match = local_hash == peer_hash;
    stream.write_u64(if hashes_match { 1 } else { 0 }).await?;
    Ok(!hashes_match)
}

async fn receive_file_streaming(
    stream: &mut TcpStream,
    file: &mut fs::File,
    size: u64,
    cipher: &Aes256Gcm,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut progress = utils::ProgressTracker::new();
    let mut bytes_received = 0u64;

    loop {
        let chunk_size = stream.read_u64().await? as usize;
        if chunk_size == 0 {
            break;
        }

        let mut chunk = vec![0u8; chunk_size];
        stream.read_exact(&mut chunk).await?;

        let nonce = &chunk[..12];
        let ciphertext = &chunk[12..];
        let nonce = aes_gcm::Nonce::from_slice(nonce);
        let decrypted_chunk = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption error: {:?}", e))?;

        bytes_received += decrypted_chunk.len() as u64;
        file.write_all(&decrypted_chunk)?;
        progress.update(bytes_received, size)?;
    }

    progress.finish()?;

    Ok(())
}

pub async fn receive_file(
    stream: &mut TcpStream,
    folder: &Path,
    key: &[u8],
    check_duplicate: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let cipher = Aes256Gcm::new_from_slice(key)?;
    let start = Instant::now();

    let (filename, file_size) = receive_file_details(stream).await?;
    println!("Receiving: {}", filename);
    println!("File size: {}", format_size(file_size, BINARY));

    let mut full_path = folder.to_path_buf();
    full_path.push(&filename);

    // Check if we already have this file
    if check_duplicate {
        let is_candidate = full_path.is_file() && fs::metadata(&full_path)?.len() == file_size;
        if is_candidate {
            let file = fs::File::open(&full_path)?;
            let need_transfer = check_for_file(stream, &file).await?;

            if !need_transfer {
                println!("Already have this file, skipping.");
                return Ok(());
            }
        } else {
            stream.write_u64(0).await?;
        }
    }

    // Create parent directories if necessary
    if let Some(dirs) = full_path.parent() {
        fs::create_dir_all(dirs)?;
    }
    let mut i = 1;
    while full_path.is_file() {
        let file_name = full_path.file_name().unwrap().to_str().unwrap();
        let new_name = format!("({}) {}", i, file_name);
        full_path.pop();
        full_path.push(new_name);
        i += 1;
    }
    let mut out_file = fs::File::create(&full_path)?;

    receive_file_streaming(stream, &mut out_file, file_size, &cipher).await?;

    let elapsed = Instant::now() - start;
    println!(
        "Receiving took {}",
        humantime::format_duration(Duration::from_secs_f64(elapsed.as_secs_f64()))
    );

    let megabits = 8.0 * (file_size as f64 / 1_000_000.0);
    let mbps = megabits / elapsed.as_secs_f64();
    println!("Speed: {:.2}mbps", mbps);

    Ok(())
}
