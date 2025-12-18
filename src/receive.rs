use crate::utils;
use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use std::{
    fs,
    io::Write,
    path::Path,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{sleep, timeout},
};

pub async fn receive_file(
    folder: &Path,
    key: &[u8],
    stream: &mut TcpStream,
    last_file: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let cipher = Aes256Gcm::new_from_slice(key)?;
    let start = Instant::now();

    // Check destination folder
    fs::read_dir(folder)?;

    // Receive file details
    let (filename, file_size) = receive_file_details(stream).await?;
    println!("Receiving: {}", filename);
    println!("File size: {}", utils::make_size_readable(file_size));

    let mut bytes_left = file_size;

    // Check if we already have this file
    let mut full_path = folder.to_path_buf();
    full_path.push(&filename);
    let need_transfer = check_for_file(&full_path, file_size, stream).await?;
    if !need_transfer {
        println!("Already have this file, skipping.");
        return Ok(());
    }

    // Create parent directories if necessary
    utils::make_parent_directories(&full_path)?;

    // Find unique filename if file exists
    let mut i = 1;
    while full_path.is_file() {
        let file_name = full_path.file_name().unwrap().to_str().unwrap();
        let new_name = format!("({}) {}", i, file_name);
        full_path.pop();
        full_path.push(new_name);
        i += 1;
    }

    // Open output file
    let mut out_file = fs::File::create(&full_path)?;

    let mut last_percent: u8 = 0;

    // Receive file
    loop {
        tokio::task::yield_now().await;
        let decrypted_bytes = receive_and_decrypt_chunk(&cipher, stream).await?;
        if decrypted_bytes.is_empty() {
            break;
        }
        bytes_left -= decrypted_bytes.len() as u64;
        out_file.write_all(&decrypted_bytes)?;

        let percent_done = ((file_size - bytes_left) as f64 / file_size as f64 * 100.0) as u8;
        if percent_done > last_percent {
            print!("\rProgress: {}%", percent_done);
            use std::io::Write as _;
            std::io::stdout().flush()?;
            last_percent = percent_done;
        }
    }

    // Tell sending end we're finished
    stream.write_u64(1).await?;

    println!("\rProgress: 100%");
    let elapsed = (Instant::now() - start).as_secs_f64();
    println!("Receiving took {}", utils::format_time(elapsed));

    let megabits = 8.0 * (file_size as f64 / 1_000_000.0);
    let mbps = megabits / elapsed;
    println!("Speed: {:.2}mbps", mbps);

    // Wait for double confirmation
    if last_file {
        match timeout(Duration::from_secs(2), stream.read_u64()).await {
            Ok(res) => {
                res?;
            }
            Err(_) => {
                println!("Didn't receive confirmation");
            }
        };
    } else {
        stream.read_u64().await?;
    }

    Ok(())
}

async fn receive_and_decrypt_chunk(
    cipher: &Aes256Gcm,
    stream: &mut TcpStream,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let chunk_size = stream.read_u64().await? as usize;
    if chunk_size == 0 {
        Ok(vec![])
    } else {
        let mut chunk = vec![0u8; chunk_size];
        stream.read_exact(&mut chunk).await?;

        let nonce = &chunk[..12];
        let ciphertext = &chunk[12..];
        let nonce = aes_gcm::Nonce::from_slice(nonce);
        let decrypted_chunk = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption error: {:?}", e))?;
        Ok(decrypted_chunk)
    }
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
    filename: &Path,
    size: u64,
    stream: &mut TcpStream,
) -> Result<bool, Box<dyn std::error::Error>> {
    if filename.is_file() {
        let metadata = fs::metadata(filename)?;
        let local_size = metadata.len();
        if size == local_size {
            stream.write_u64(1).await?;
            let local_hash = utils::hash_file(filename)?;
            let mut peer_hash = vec![0; 32];
            stream.read_exact(&mut peer_hash).await?;
            let hashes_match = local_hash == peer_hash;
            stream.write_u64(if hashes_match { 1 } else { 0 }).await?;
            Ok(!hashes_match)
        } else {
            stream.write_u64(0).await?;
            sleep(Duration::from_secs(1)).await;
            Ok(true)
        }
    } else {
        stream.write_u64(0).await?;
        sleep(Duration::from_secs(1)).await;
        Ok(true)
    }
}
