use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Write},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub fn get_key_from_password(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.finalize().into()
}

pub fn generate_password() -> String {
    petname::petname(3, "-").unwrap_or_else(|| "flying-transfer-secret".to_string())
}

pub fn hash_file(file: &fs::File) -> io::Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file_ref = file;

    file_ref.seek(SeekFrom::Start(0))?;

    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1_000_000]; // 1MB buffer

    loop {
        let bytes_read = file_ref.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    file_ref.seek(SeekFrom::Start(0))?;

    Ok(hasher.finalize().to_vec())
}

pub struct ProgressTracker {
    last_percent: u8,
}

impl ProgressTracker {
    pub fn new() -> Self {
        Self { last_percent: 0 }
    }

    pub fn update(&mut self, bytes_processed: u64, total_bytes: u64) -> io::Result<()> {
        let percent_done = ((bytes_processed as f64 / total_bytes as f64) * 100.0) as u8;
        if percent_done > self.last_percent {
            print!("\rProgress: {}%", percent_done);
            io::stdout().flush()?;
            self.last_percent = percent_done;
        }
        Ok(())
    }

    pub fn finish(&self) -> io::Result<()> {
        println!("\rProgress: 100%");
        Ok(())
    }
}

pub async fn version_handshake(
    stream: &mut TcpStream,
    send_first: bool,
    version: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer_version = if send_first {
        stream.write_u64(version).await?;
        stream.read_u64().await?
    } else {
        let peer = stream.read_u64().await?;
        stream.write_u64(version).await?;
        peer
    };

    if peer_version != version {
        println!(
            "Warning: Version mismatch (local: {}, peer: {})",
            version, peer_version
        );
    }

    Ok(())
}
