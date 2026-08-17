use crate::NetworkStream;
use crate::metadata::{Metadata, Type};
use crate::progress;
use crate::session::Session;
use humansize::{BINARY, format_size};
use ring::aead;
use std::path::{Path, PathBuf};
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc::Sender,
};

async fn create_file(file_path: &Path) -> anyhow::Result<File> {
    async fn handle_filename_conflict(mut path: PathBuf) -> PathBuf {
        let mut counter = 1;
        while tokio::fs::metadata(&path)
            .await
            .map(|m| m.is_file())
            .unwrap_or(false)
        {
            let original_name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            path.pop();
            path.push(format!("{}.{}", original_name, counter));
            counter += 1;
        }
        path
    }

    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent).await?;
    }
    let resolved = handle_filename_conflict(file_path.to_path_buf()).await;
    Ok(File::create(resolved).await?)
}

async fn decrypt_and_save<S: NetworkStream>(
    session: &mut Session<S>,
    file: &mut File,
    progress: &mut progress::Progress,
) -> anyhow::Result<()> {
    async fn read_packet<S: NetworkStream>(
        session: &mut Session<S>,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let packet_len = session.read_u64().await? as usize;
        if packet_len == 0 {
            return Ok(None);
        }

        let mut packet = vec![0u8; packet_len];
        session.read_exact(&mut packet).await?;
        Ok(Some(packet))
    }

    let key = session.key();
    let mut bytes_received = 0u64;

    while let Some(packet) = read_packet(session).await? {
        if packet.len() < aead::NONCE_LEN {
            anyhow::bail!("Invalid packet: too short");
        }
        let (nonce_bytes, ciphertext) = packet.split_at(aead::NONCE_LEN);
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce_bytes)
            .map_err(|_| anyhow::anyhow!("Invalid nonce"))?;

        let mut buffer = ciphertext.to_vec();
        let plaintext = key
            .open_in_place(nonce, aead::Aad::empty(), &mut buffer)
            .map_err(|_| anyhow::anyhow!("Decryption failed"))?;

        bytes_received += plaintext.len() as u64;
        file.write_all(plaintext).await?;
        progress.update(bytes_received)?;
    }

    progress.finish()?;
    Ok(())
}

pub async fn receive<S: NetworkStream>(
    session: &mut Session<S>,
    output_dir: &Path,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    let meta = Metadata::read(session).await?;
    match meta.transfer_type {
        Type::Folder => {
            let folder_path = output_dir.join(&meta.relative_path);
            receive_folder(session, &folder_path, progress_tx).await?;
        }
        Type::File => {
            let file_path = output_dir.join(&meta.relative_path);
            receive_file(session, &file_path, meta.size, progress_tx).await?;
        }
    }

    Ok(())
}

pub async fn receive_file<S: NetworkStream>(
    session: &mut Session<S>,
    file_path: &Path,
    file_size: u64,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    println!(
        "Receiving: {} ({})",
        file_path.display(),
        format_size(file_size, BINARY)
    );

    let mut progress = progress::Progress::new(file_size, progress_tx);
    let mut out_file = create_file(file_path).await?;
    decrypt_and_save(session, &mut out_file, &mut progress).await?;

    Ok(())
}

pub async fn receive_folder<S: NetworkStream>(
    session: &mut Session<S>,
    folder_path: &Path,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    async fn read_relative_path<S: NetworkStream>(
        session: &mut Session<S>,
    ) -> anyhow::Result<Option<String>> {
        let path_len = session.read_u64().await? as usize;
        if path_len == 0 {
            return Ok(None);
        }

        let mut path_bytes = vec![0; path_len];
        session.read_exact(&mut path_bytes).await?;
        Ok(Some(String::from_utf8_lossy(&path_bytes).to_string()))
    }

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

    while let Some(relative_path) = read_relative_path(session).await? {
        let file_size = session.read_u64().await?;
        let file_path = folder_path.join(&relative_path);
        receive_file(session, &file_path, file_size, progress_tx.clone()).await?;
    }

    Ok(())
}
