use crate::metadata::Metadata;
use crate::{NetworkStream, progress, utils};
use humansize::{BINARY, format_size};
use ring::aead;
use std::path::Path;
use std::path::PathBuf;
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc::Sender,
};

async fn check_duplicate(stream: &mut dyn NetworkStream, file: &mut File) -> anyhow::Result<bool> {
    let local_hash = utils::hash_file(file).await?;

    stream.write_all(local_hash.as_ref()).await?;
    stream.flush().await?;

    let mut peer_hash = vec![0; 32];
    stream.read_exact(&mut peer_hash).await?;

    let matches = local_hash.as_ref() == &peer_hash[..];

    Ok(matches)
}

async fn create_file(file_path: &Path) -> anyhow::Result<File> {
    async fn handle_filename_conflict(mut path: PathBuf) -> PathBuf {
        let mut counter = 1;
        while tokio::fs::metadata(&path)
            .await
            .map(|m| m.is_file())
            .unwrap_or(false)
        {
            let original_name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let extension = path.extension().and_then(|s| s.to_str());

            let new_name = if let Some(ext) = extension {
                format!("{} ({}).{}", original_name, counter, ext)
            } else {
                format!("{} ({})", original_name, counter)
            };
            path.pop();
            path.push(new_name);
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

async fn decrypt_and_save(
    stream: &mut dyn NetworkStream,
    file: &mut File,
    key: &aead::LessSafeKey,
    progress: &mut progress::Progress,
) -> anyhow::Result<()> {
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
        progress.update(bytes_received)?;
    }

    progress.finish()?;
    Ok(())
}

pub async fn receive(
    stream: &mut dyn NetworkStream,
    output_dir: &Path,
    key: &aead::LessSafeKey,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    let meta = Metadata::read(stream).await?;
    println!("Receiving: {}", meta.relative_path);

    match meta.transfer_type {
        crate::metadata::Type::Folder => {
            let folder_path = output_dir.join(&meta.relative_path);
            receive_folder(stream, &folder_path, key, progress_tx).await?;
        }
        crate::metadata::Type::File => {
            let file_path = output_dir.join(&meta.relative_path);
            receive_file(stream, &file_path, meta.size, key, progress_tx).await?;
        }
    }

    Ok(())
}

pub async fn receive_file(
    stream: &mut dyn NetworkStream,
    file_path: &Path,
    file_size: u64,
    key: &aead::LessSafeKey,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    println!(
        "Receiving: {} ({})",
        file_path.display(),
        format_size(file_size, BINARY)
    );

    // Check if perform duplicate check
    if let Ok(metadata) = tokio::fs::metadata(file_path).await
        && metadata.is_file()
    {
        stream.write_u64(1).await?;
        stream.flush().await?;
        let mut file = File::open(file_path).await?;
        if check_duplicate(stream, &mut file).await? {
            println!("Already have this file, skipping.");
            return Ok(());
        }
    } else {
        stream.write_u64(0).await?;
        stream.flush().await?;
    }

    let mut progress = progress::Progress::new(file_size, progress_tx);
    let mut out_file = create_file(file_path).await?;
    decrypt_and_save(stream, &mut out_file, key, &mut progress).await?;

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

        let file_path = folder_path.join(&relative_path);
        let mut out_file = create_file(&file_path).await?;

        let mut progress = progress::Progress::new(file_size, progress_tx.clone());

        decrypt_and_save(stream, &mut out_file, key, &mut progress).await?;
    }

    Ok(())
}
