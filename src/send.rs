use crate::utils;
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, aead::Aead, aead::OsRng};
use std::{
    fs::{File, metadata},
    io::Read,
    path::Path,
    time::Instant,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const CHUNKSIZE: usize = 1_000_000; // 1 MB

pub async fn send_file(
    file_path: &Path,
    key: &[u8],
    stream: &mut TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let cipher = Aes256Gcm::new_from_slice(key)?;
    let mut handle = File::open(file_path)?;
    let metadata = metadata(file_path)?;
    let size = metadata.len();
    let mut bytes_left = size;

    println!("Sending file: {:?}", file_path.file_name().unwrap());
    println!("File size: {}", utils::make_size_readable(size));

    // Send file details
    let filename = file_path.file_name().unwrap().to_string_lossy().to_string();
    send_file_details(&filename, size, stream).await?;

    // Check if receiving end already has the file
    let need_transfer = check_for_file(file_path, stream).await?;
    if !need_transfer {
        println!("Recipient already has this file, skipping.");
        return Ok(());
    }

    let mut buffer = vec![0u8; CHUNKSIZE];
    let mut last_percent: u8 = 0;

    while bytes_left > 0 {
        tokio::task::yield_now().await;
        match handle.read(&mut buffer) {
            Ok(0) => break,
            Ok(bytes_read) => {
                bytes_left -= bytes_read as u64;
                encrypt_and_send_chunk(&buffer[..bytes_read], &cipher, stream).await?;

                let percent_done = ((size - bytes_left) as f64 / size as f64 * 100.0) as u8;
                if percent_done > last_percent {
                    print!("\rProgress: {}%", percent_done);
                    use std::io::Write;
                    std::io::stdout().flush()?;
                    last_percent = percent_done;
                }
            }
            Err(e) => return Err(Box::new(e)),
        }
    }

    // Send chunk size of 0 to signal end
    stream.write_u64(0).await?;

    println!("\rProgress: 100%");
    let elapsed = (Instant::now() - start).as_secs_f64();
    println!("Sending took {}", utils::format_time(elapsed));

    let megabits = 8.0 * (size as f64 / 1_000_000.0);
    let mbps = megabits / elapsed;
    println!("Speed: {:.2}mbps", mbps);

    // Wait for confirmation
    stream.read_u64().await?;
    stream.write_u64(1).await?;

    Ok(())
}

async fn encrypt_and_send_chunk(
    chunk: &[u8],
    cipher: &Aes256Gcm,
    stream: &mut TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let mut encrypted_chunk = cipher
        .encrypt(&nonce, chunk)
        .map_err(|e| format!("Encryption error: {:?}", e))?;
    let mut nonce_and_chunk = nonce.to_vec();
    nonce_and_chunk.append(&mut encrypted_chunk);

    stream.write_u64(nonce_and_chunk.len() as u64).await?;
    stream.write_all(&nonce_and_chunk).await?;

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
