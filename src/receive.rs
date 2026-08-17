use crate::{NetworkStream, utils};
use humansize::{BINARY, format_size};
use ring::aead;
use std::path::Path;
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc::Sender,
};

/// Receive top-level metadata: relative path, is_folder flag, and total size.
async fn receive_metadata(stream: &mut dyn NetworkStream) -> anyhow::Result<(String, bool, u64)> {
    let path_len = stream.read_u64().await? as usize;
    let mut path_bytes = vec![0; path_len];
    stream.read_exact(&mut path_bytes).await?;
    let relative_path = String::from_utf8(path_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in path: {}", e))?;
    let is_folder = stream.read_u64().await? == 1;
    let size = stream.read_u64().await?;
    Ok((relative_path, is_folder, size))
}

async fn check_duplicate(stream: &mut dyn NetworkStream, file: &mut File) -> anyhow::Result<bool> {
    stream.write_u64(1).await?;
    stream.flush().await?;

    let local_hash = utils::hash_file(file).await?;

    stream.write_all(local_hash.as_ref()).await?;
    stream.flush().await?;

    let mut peer_hash = vec![0; 32];
    stream.read_exact(&mut peer_hash).await?;

    let matches = local_hash.as_ref() == &peer_hash[..];

    Ok(matches)
}

async fn decrypt_and_save(
    stream: &mut dyn NetworkStream,
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

/// Top-level receive: reads metadata, dispatches to receive_file or
/// receive_folder.
pub async fn receive(
    stream: &mut dyn NetworkStream,
    output_dir: &Path,
    key: &aead::LessSafeKey,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    let (relative_path, is_folder, file_size) = receive_metadata(stream).await?;
    println!("Receiving: {}", relative_path);

    if is_folder {
        let folder_path = output_dir.join(&relative_path);
        receive_folder(stream, &folder_path, key, progress_tx).await?;
    } else {
        receive_file(
            stream,
            output_dir,
            &relative_path,
            file_size,
            key,
            progress_tx,
        )
        .await?;
    }

    Ok(())
}

pub async fn receive_file(
    stream: &mut dyn NetworkStream,
    output_dir: &Path,
    filename: &str,
    file_size: u64,
    key: &aead::LessSafeKey,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    println!(
        "Receiving: {} ({})",
        filename,
        format_size(file_size, BINARY)
    );

    let mut full_path = output_dir.to_path_buf();
    full_path.push(filename);

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
        stream.flush().await?;
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
    stream: &mut dyn NetworkStream,
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
        // Read relative path
        let path_len = stream.read_u64().await? as usize;
        if path_len == 0 {
            break;
        }
        let mut path_bytes = vec![0; path_len];
        stream.read_exact(&mut path_bytes).await?;
        let relative_path = String::from_utf8_lossy(&path_bytes).to_string();

        file_count += 1;

        let file_size = stream.read_u64().await?;
        println!(
            "[{}] {} ({})",
            file_count,
            relative_path,
            format_size(file_size, BINARY)
        );

        let mut full_path = folder_path.join(&relative_path);

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
