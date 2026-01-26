use crate::utils;
use humansize::{BINARY, format_size};
use ring::aead;
use std::path::Path;
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

    let (mut read_half, mut write_half) = stream.split();
    let local_hash = utils::hash_file(file).await?;
    let mut peer_hash = vec![0; 32];

    tokio::try_join!(
        write_half.write_all(local_hash.as_ref()),
        read_half.read_exact(&mut peer_hash)
    )?;

    let matches = local_hash.as_ref() == &peer_hash[..];

    Ok(matches)
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
            break;
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
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    let (filename, file_size) = receive_metadata(stream).await?;
    println!(
        "Receiving: {} ({})",
        filename,
        format_size(file_size, BINARY)
    );

    let mut full_path = output_dir.to_path_buf();
    full_path.push(&filename);

    // Check if perform duplicate check
    if let Ok(metadata) = tokio::fs::metadata(&full_path).await
        && metadata.is_file()
    {
        let mut file = File::open(&full_path).await?;
        if check_duplicate(stream, &mut file).await? {
            println!("Already have this file, skipping.");
            return Ok(());
        }
    } else {
        stream.write_u64(0).await?;
    }

    // Create parent directories
    if let Some(parent) = full_path.parent() {
        fs::create_dir_all(parent).await?;
    }

    let mut out_file = File::create(&full_path).await?;
    decrypt_and_save(stream, &mut out_file, file_size, key, progress_tx).await?;

    Ok(())
}

pub async fn receive_folder(
    stream: &mut TcpStream,
    folder_path: &Path,
    key: &aead::LessSafeKey,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    println!(
        "Creating folder: {}",
        folder_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
    );
    if !folder_path.exists() {
        fs::create_dir_all(&folder_path).await?;
    }

    let mut file_count = 0u64;
    loop {
        // Read filename
        let filename_len = stream.read_u64().await? as usize;
        if filename_len == 0 {
            break;
        }
        let mut filename_bytes = vec![0; filename_len];
        stream.read_exact(&mut filename_bytes).await?;
        let filename = String::from_utf8_lossy(&filename_bytes).to_string();

        // Read file
        let file_size = stream.read_u64().await?;
        file_count += 1;
        println!(
            "[{}] {} ({})",
            file_count,
            filename,
            format_size(file_size, BINARY)
        );

        let mut full_path = folder_path.join(&filename);

        // Create parent directories
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Handle filename conflicts
        full_path = utils::handle_filename_conflict(full_path).await;

        let mut out_file = File::create(&full_path).await?;
        decrypt_and_save(stream, &mut out_file, file_size, key, progress_tx.clone()).await?;
    }

    Ok(())
}
