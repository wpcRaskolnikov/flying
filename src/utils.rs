use ring::digest;
use socket2::{Domain, Protocol, Socket, Type};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt},
    net::TcpListener,
    sync::mpsc::Sender,
};

pub async fn hash_file(file: &mut File) -> io::Result<digest::Digest> {
    const CHUNK_SIZE: usize = 1_048_576;
    let mut context = digest::Context::new(&digest::SHA256);
    let mut buffer = vec![0u8; CHUNK_SIZE];

    loop {
        let bytes_read = file.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }
        context.update(&buffer[..bytes_read]);
    }

    file.seek(std::io::SeekFrom::Start(0)).await?;
    Ok(context.finish())
}

#[derive(Default)]
pub struct ProgressTracker {
    last_percent: u8,
    progress_tx: Option<Sender<u8>>,
}

impl ProgressTracker {
    pub fn with_channel(progress_tx: Sender<u8>) -> Self {
        Self {
            progress_tx: Some(progress_tx),
            ..Default::default()
        }
    }

    pub fn update(&mut self, bytes_processed: u64, total_bytes: u64) -> io::Result<()> {
        let percent_done = ((bytes_processed as f64 / total_bytes as f64) * 100.0) as u8;
        if percent_done > self.last_percent {
            print!("\rProgress: {}%", percent_done);
            io::stdout().flush()?;
            self.last_percent = percent_done;

            // Send progress through channel if available
            if let Some(tx) = &self.progress_tx {
                let _ = tx.try_send(percent_done);
            }
        }
        Ok(())
    }

    pub fn finish(&self) -> io::Result<()> {
        println!("\rProgress: 100%");

        if let Some(tx) = &self.progress_tx {
            let _ = tx.try_send(100);
        }

        Ok(())
    }
}

pub fn create_listener(port: u16) -> anyhow::Result<TcpListener> {
    let addr = format!("[::]:{}", port).parse::<SocketAddr>()?;

    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_only_v6(false)?;
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;

    let std_listener: std::net::TcpListener = socket.into();
    std_listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(std_listener)?;

    Ok(listener)
}

pub async fn handle_filename_conflict(mut path: PathBuf) -> PathBuf {
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
