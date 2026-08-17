use crate::{NetworkStream, utils};
use humansize::{BINARY, format_size};
use ring::{aead, rand};
use std::path::Path;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc::Sender,
};

const CHUNK_SIZE: usize = 1_048_576; // 1 MiB

/// Send top-level metadata: relative path, is_folder flag, and file/folder size.
pub async fn send_metadata(
    stream: &mut dyn NetworkStream,
    relative_path: &str,
    is_folder: bool,
    size: u64,
) -> anyhow::Result<()> {
    stream.write_u64(relative_path.len() as u64).await?;
    stream.write_all(relative_path.as_bytes()).await?;
    stream.write_u64(u64::from(is_folder)).await?;
    stream.write_u64(size).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn check_duplicate(
    stream: &mut dyn NetworkStream,
    file: &mut File,
) -> anyhow::Result<bool> {
    let has_file = stream.read_u64().await?;
    if has_file == 1 {
        let local_hash = utils::hash_file(file).await?;

        stream.write_all(local_hash.as_ref()).await?;
        stream.flush().await?;

        let mut peer_hash = vec![0; 32];
        stream.read_exact(&mut peer_hash).await?;

        let matches = local_hash.as_ref() == &peer_hash[..];
        Ok(matches)
    } else {
        Ok(false)
    }
}

pub async fn encrypt_and_send(
    stream: &mut dyn NetworkStream,
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
    stream.flush().await?;
    progress.finish()?;

    Ok(())
}

/// Top-level send: reads file/folder info, sends metadata, dispatches to
/// send_file or send_folder.
pub async fn send(
    stream: &mut dyn NetworkStream,
    file_path: &Path,
    key: &aead::LessSafeKey,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    let is_folder = file_path.is_dir();
    let metadata = tokio::fs::metadata(file_path).await?;
    let size = metadata.len();

    let relative_path = file_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Invalid file/folder name"))?
        .to_string_lossy()
        .to_string();

    println!("Sending: {} ({})", relative_path, format_size(size, BINARY));

    send_metadata(stream, &relative_path, is_folder, size).await?;

    if is_folder {
        send_folder(stream, file_path, key, progress_tx).await?;
    } else {
        let mut file = File::open(file_path).await?;
        if check_duplicate(stream, &mut file).await? {
            println!("Recipient already has this file, skipping.");
            return Ok(());
        }
        encrypt_and_send(stream, file, size, key, progress_tx).await?;
    }

    Ok(())
}

pub async fn send_folder(
    stream: &mut dyn NetworkStream,
    folder_path: &Path,
    key: &aead::LessSafeKey,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    async fn send_recursive(
        stream: &mut dyn NetworkStream,
        current_dir: &Path,
        base_path: &Path,
        key: &aead::LessSafeKey,
        progress_tx: &Option<Sender<u8>>,
    ) -> anyhow::Result<()> {
        let mut entries = tokio::fs::read_dir(current_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let metadata = tokio::fs::metadata(&path).await?;

            if metadata.is_dir() {
                Box::pin(send_recursive(stream, &path, base_path, key, progress_tx)).await?;
            } else {
                let size = metadata.len();
                let filename = path
                    .strip_prefix(base_path)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();

                println!("Sending: {} ({})", filename, format_size(size, BINARY));

                send_metadata(stream, &filename, false, size).await?;

                let file = File::open(&path).await?;
                encrypt_and_send(stream, file, size, key, progress_tx.clone()).await?;
            }
        }
        Ok(())
    }

    send_recursive(stream, folder_path, folder_path, key, &progress_tx).await?;

    // Send end signal (empty path)
    stream.write_u64(0).await?;
    stream.flush().await?;

    Ok(())
}
