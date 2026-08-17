use crate::metadata::Metadata;
use crate::{NetworkStream, progress, utils};
use humansize::{BINARY, format_size};
use ring::{aead, rand};
use std::path::Path;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc::Sender,
};

async fn check_duplicate(stream: &mut dyn NetworkStream, file: &mut File) -> anyhow::Result<bool> {
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

async fn encrypt_and_send(
    stream: &mut dyn NetworkStream,
    mut file: File,
    key: &aead::LessSafeKey,
    progress: &mut progress::Progress,
) -> anyhow::Result<()> {
    const CHUNK_SIZE: usize = 1_048_576; // 1 MiB

    let rng = rand::SystemRandom::new();
    let mut buffer = vec![0u8; CHUNK_SIZE];
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
        progress.update(bytes_sent)?;
    }

    stream.write_u64(0).await?; // Signal end of file
    stream.flush().await?;
    progress.finish()?;

    Ok(())
}

pub async fn send_file(
    stream: &mut dyn NetworkStream,
    file_path: &Path,
    key: &aead::LessSafeKey,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    let meta = Metadata::from_path(file_path, None).await?;

    println!(
        "Sending: {} ({})",
        meta.relative_path,
        format_size(meta.size, BINARY)
    );

    meta.write(stream).await?;

    let mut file = File::open(file_path).await?;
    if check_duplicate(stream, &mut file).await? {
        println!("Recipient already has this file, skipping.");
        return Ok(());
    }
    let mut progress = progress::Progress::new(meta.size, progress_tx);
    encrypt_and_send(stream, file, key, &mut progress).await?;

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
            let meta = Metadata::from_path(&path, Some(base_path)).await?;

            if meta.transfer_type == crate::metadata::Type::Folder {
                Box::pin(send_recursive(stream, &path, base_path, key, progress_tx)).await?;
            } else {
                println!(
                    "Sending: {} ({})",
                    meta.relative_path,
                    format_size(meta.size, BINARY)
                );

                meta.write(stream).await?;

                let file = File::open(&path).await?;
                let mut progress = progress::Progress::new(meta.size, progress_tx.clone());
                encrypt_and_send(stream, file, key, &mut progress).await?;
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

pub async fn send(
    stream: &mut dyn NetworkStream,
    file_path: &Path,
    key: &aead::LessSafeKey,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    let meta = Metadata::from_path(file_path, None).await?;

    if meta.transfer_type == crate::metadata::Type::Folder {
        send_folder(stream, file_path, key, progress_tx).await?;
    } else {
        send_file(stream, file_path, key, progress_tx).await?;
    }

    Ok(())
}
