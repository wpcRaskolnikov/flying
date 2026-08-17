use crate::NetworkStream;
use crate::metadata::{Metadata, Type};
use crate::progress;
use crate::session::Session;
use humansize::{BINARY, format_size};
use ring::{aead, rand};
use std::path::Path;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc::Sender,
};

async fn encrypt_and_send<S: NetworkStream>(
    session: &mut Session<S>,
    mut file: File,
    progress: &mut progress::Progress,
) -> anyhow::Result<()> {
    const CHUNK_SIZE: usize = 1_048_576;
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let key = session.key();
    let rng = rand::SystemRandom::new();
    let mut bytes_sent = 0u64;

    loop {
        let bytes_read = file.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }
        let mut text = buffer[..bytes_read].to_vec();

        let nonce_bytes = rand::generate::<[u8; aead::NONCE_LEN]>(&rng)
            .map_err(|_| anyhow::anyhow!("RNG failure"))?;
        let nonce_slice = nonce_bytes.expose();
        let nonce = aead::Nonce::assume_unique_for_key(nonce_slice);

        key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut text)
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

        let mut packet = nonce_slice.to_vec();
        packet.extend_from_slice(&text);

        session.write_u64(packet.len() as u64).await?;
        session.write_all(&packet).await?;

        bytes_sent += bytes_read as u64;
        progress.update(bytes_sent)?;
    }

    session.write_u64(0).await?;
    session.flush().await?;
    progress.finish()?;
    Ok(())
}

pub async fn send_file<S: NetworkStream>(
    session: &mut Session<S>,
    file_path: &Path,
    base_path: Option<&Path>,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    let meta = Metadata::from_path(file_path, base_path).await?;
    println!(
        "Sending: {} ({})",
        meta.relative_path,
        format_size(meta.size, BINARY)
    );
    meta.write(session).await?;

    let file = File::open(file_path).await?;

    let mut progress = progress::Progress::new(meta.size, progress_tx);
    encrypt_and_send(session, file, &mut progress).await?;

    Ok(())
}

pub async fn send_folder<S: NetworkStream>(
    session: &mut Session<S>,
    folder_path: &Path,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    async fn send_recursive<S: NetworkStream>(
        session: &mut Session<S>,
        current_dir: &Path,
        base_path: &Path,
        progress_tx: &Option<Sender<u8>>,
    ) -> anyhow::Result<()> {
        let mut entries = tokio::fs::read_dir(current_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let meta = Metadata::from_path(&path, Some(base_path)).await?;
            match meta.transfer_type {
                Type::Folder => {
                    Box::pin(send_recursive(session, &path, base_path, progress_tx)).await?;
                }
                Type::File => {
                    send_file(session, &path, Some(base_path), progress_tx.clone()).await?;
                }
            }
        }
        Ok(())
    }

    send_recursive(session, folder_path, folder_path, &progress_tx).await?;
    session.write_u64(0).await?;
    session.flush().await?;
    Ok(())
}

pub async fn send<S: NetworkStream>(
    session: &mut Session<S>,
    path: &Path,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    let meta = Metadata::from_path(path, None).await?;
    match meta.transfer_type {
        Type::Folder => {
            send_folder(session, path, progress_tx).await?;
        }
        Type::File => {
            send_file(session, path, None, progress_tx).await?;
        }
    }
    Ok(())
}
