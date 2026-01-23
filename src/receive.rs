use crate::utils;
use humansize::{BINARY, format_size};
use ring::aead;
use std::{
    path::Path,
    time::{Duration, Instant},
};
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc::Sender,
};

async fn receive_metadata(stream: &mut TcpStream) -> anyhow::Result<(String, u64)> {
    let filename_len = stream.read_u64().await? as usize;
    let mut filename_bytes = vec![0; filename_len];
    stream.read_exact(&mut filename_bytes).await?;
    let filename = String::from_utf8_lossy(&filename_bytes).to_string();
    let file_size = stream.read_u64().await?;
    Ok((filename, file_size))
}

async fn check_duplicate(stream: &mut TcpStream, file: &mut File) -> anyhow::Result<bool> {
    stream.write_u64(1).await?;
    let local_hash = utils::hash_file(file).await?;
    let mut peer_hash = vec![0; 32];
    stream.read_exact(&mut peer_hash).await?;
    let matches = local_hash.as_ref() == peer_hash.as_slice();
    stream.write_u64(u64::from(matches)).await?;
    Ok(!matches) // need transfer if hashes don't match
}

async fn decrypt_and_save(
    stream: &mut TcpStream,
    file: &mut File,
    size: u64,
    key: &aead::LessSafeKey,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    let mut progress = if let Some(tx) = progress_tx {
        utils::ProgressTracker::with_channel(tx)
    } else {
        Default::default()
    };
    let mut bytes_received = 0u64;

    loop {
        let packet_len = stream.read_u64().await? as usize;
        if packet_len == 0 {
            break; // End of file
        }

        let mut packet = vec![0u8; packet_len];
        stream.read_exact(&mut packet).await?;

        if packet.len() < aead::NONCE_LEN {
            anyhow::bail!("Invalid packet: too short");
        }

        let (nonce_bytes, ciphertext) = packet.split_at(aead::NONCE_LEN);
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce_bytes)
            .map_err(|_| anyhow::anyhow!("Invalid nonce"))?;

        let mut in_out = ciphertext.to_vec();
        let plaintext = key
            .open_in_place(nonce, aead::Aad::empty(), &mut in_out)
            .map_err(|_| anyhow::anyhow!("Decryption failed"))?;

        bytes_received += plaintext.len() as u64;
        file.write_all(plaintext).await?;
        progress.update(bytes_received, size)?;
    }

    progress.finish()?;
    Ok(())
}

pub async fn receive_file(
    stream: &mut TcpStream,
    output_dir: &Path,
    key: &aead::LessSafeKey,
    check_dup: bool,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    let start = Instant::now();

    let (filename, file_size) = receive_metadata(stream).await?;
    println!("Receiving: {}", filename);
    println!("File size: {}", format_size(file_size, BINARY));

    let mut full_path = output_dir.to_path_buf();
    full_path.push(&filename);

    if check_dup {
        if let Ok(metadata) = tokio::fs::metadata(&full_path).await {
            if metadata.is_file() && metadata.len() == file_size {
                let mut file = File::open(&full_path).await?;
                if !check_duplicate(stream, &mut file).await? {
                    println!("Already have this file, skipping.");
                    return Ok(());
                }
            }
        }
    }

    if !check_dup {
        // Only send the "no file" signal if we're not checking duplicates
    } else if tokio::fs::metadata(&full_path).await.is_err()
        || tokio::fs::metadata(&full_path).await?.len() != file_size
    {
        stream.write_u64(0).await?;
    }

    // Create parent directories
    if let Some(parent) = full_path.parent() {
        fs::create_dir_all(parent).await?;
    }

    // Handle filename conflicts
    let mut counter = 1;
    while tokio::fs::metadata(&full_path)
        .await
        .map(|m| m.is_file())
        .unwrap_or(false)
    {
        let file_name = full_path.file_name().unwrap().to_str().unwrap();
        let new_name = format!("({}) {}", counter, file_name);
        full_path.pop();
        full_path.push(new_name);
        counter += 1;
    }

    let mut out_file = File::create(&full_path).await?;
    decrypt_and_save(stream, &mut out_file, file_size, key, progress_tx).await?;

    let elapsed = start.elapsed();
    println!(
        "Receiving took {}",
        humantime::format_duration(Duration::from_secs_f64(elapsed.as_secs_f64()))
    );

    let megabits = 8.0 * (file_size as f64 / 1_000_000.0);
    println!("Speed: {:.2} Mbps", megabits / elapsed.as_secs_f64());

    Ok(())
}
