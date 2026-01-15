// Export all modules
pub mod mdns;
pub mod receive;
pub mod send;
pub mod utils;

use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

pub const VERSION: u64 = 4;

#[derive(Debug, Clone)]
pub enum ConnectionMode {
    AutoDiscover,
    Listen,
    Connect(String),
}

impl ConnectionMode {
    pub fn from_params(listen: bool, connect: Option<String>) -> Self {
        if let Some(ip) = connect {
            ConnectionMode::Connect(ip)
        } else if listen {
            ConnectionMode::Listen
        } else {
            ConnectionMode::AutoDiscover
        }
    }
}

fn select_service(services: &[mdns::DiscoveredService]) -> Option<&mdns::DiscoveredService> {
    if services.is_empty() {
        println!("\nNo peers found on the network.");
        println!("Make sure the peer is running and on the same network.");
        return None;
    }

    println!("\nFound {} peer(s):", services.len());
    for (i, service) in services.iter().enumerate() {
        println!(
            "  [{}] {} ({}:{})",
            i + 1,
            service.hostname,
            service.ip,
            service.port
        );
    }

    if services.len() == 1 {
        println!("\nAutomatically selecting the only available receiver.");
        return Some(&services[0]);
    }

    println!("\nSelect a peer (1-{}):", services.len());

    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok()?;

    let selection: usize = input.trim().parse().ok()?;

    if selection > 0 && selection <= services.len() {
        Some(&services[selection - 1])
    } else {
        println!("Invalid selection.");
        None
    }
}

async fn establish_connection(
    mode: &ConnectionMode,
    port: u16,
) -> Result<TcpStream, Box<dyn std::error::Error>> {
    match mode {
        ConnectionMode::AutoDiscover => {
            println!("Searching for peers on the local network...\n");

            let services = mdns::discover_services(3)?;

            if let Some(service) = select_service(&services) {
                let addr = SocketAddr::new(service.ip, service.port);
                println!("\nConnecting to {}...", addr);
                let stream = TcpStream::connect(addr).await?;
                println!("Connected!\n");
                Ok(stream)
            } else {
                Err("No peers found on the local network".into())
            }
        }
        ConnectionMode::Listen => {
            // Create IPv6 socket with dual-stack support
            let addr = format!("[::]:{}", port).parse::<SocketAddr>()?;

            let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
            socket.set_only_v6(false)?;
            socket.set_reuse_address(true)?;
            socket.bind(&addr.into())?;
            socket.listen(128)?;

            // Convert socket2::Socket to std::net::TcpListener, then to tokio::net::TcpListener
            let std_listener: std::net::TcpListener = socket.into();
            std_listener.set_nonblocking(true)?;
            let listener = TcpListener::from_std(std_listener)?;

            let _mdns = mdns::advertise_service(port)?;

            println!("Listening on {} (IPv4/IPv6 dual-stack)...", addr);
            println!("Waiting for peer to connect...\n");
            let (stream, socket_addr) = listener.accept().await?;
            println!("Connection accepted from {}\n", socket_addr);
            Ok(stream)
        }
        ConnectionMode::Connect(ip) => {
            let ip: std::net::IpAddr = ip.parse()?;
            let addr = std::net::SocketAddr::new(ip, port);
            println!("Connecting to {}...", addr);
            let stream = TcpStream::connect(addr).await?;
            println!("Connected!\n");
            Ok(stream)
        }
    }
}

pub async fn run_receiver(
    output_dir: &std::path::PathBuf,
    password: &str,
    connection_mode: ConnectionMode,
) -> Result<(), Box<dyn std::error::Error>> {
    let key = utils::get_key_from_password(password);

    let mut stream = establish_connection(&connection_mode, 3290).await?;

    utils::version_handshake(&mut stream, true, VERSION).await?;

    // Mode confirmation (1 = send, 0 = receive)
    stream.write_u64(0).await?;
    let mode_ok = stream.read_u64().await?;
    if mode_ok != 1 {
        return Err("Both ends selected the same mode".into());
    }

    let num_files = stream.read_u64().await?;
    println!("Receiving {} file(s)...\n", num_files);

    // Receive folder info: 1 if sending a folder, 0 if single file
    let is_folder = stream.read_u64().await? == 1;

    // If receiving a folder, get the folder name and create it
    let final_output_dir = if is_folder {
        let folder_name_len = stream.read_u64().await? as usize;
        let mut folder_name_bytes = vec![0; folder_name_len];
        stream.read_exact(&mut folder_name_bytes).await?;
        let folder_name = String::from_utf8_lossy(&folder_name_bytes).to_string();

        let mut folder_path = output_dir.clone();
        folder_path.push(&folder_name);
        println!("Creating folder: {}\n", folder_name);

        if !folder_path.exists() {
            std::fs::create_dir_all(&folder_path)?;
        }

        folder_path
    } else {
        output_dir.clone()
    };

    // Only check duplicate for single file transfer
    let check_duplicate = num_files == 1;

    for i in 0..num_files {
        println!("===========================================");
        println!("File {} of {}", i + 1, num_files);
        println!("===========================================");
        receive::receive_file(&mut stream, &final_output_dir, &key, check_duplicate).await?;
        println!();
    }

    println!("===========================================");
    println!("Transfer complete!");
    println!("===========================================");

    stream.shutdown().await?;
    Ok(())
}

fn collect_files_recursive(
    dir: &std::path::Path,
    files: &mut Vec<std::path::PathBuf>,
) -> std::io::Result<()> {
    if dir.is_file() {
        files.push(dir.to_path_buf());
        return Ok(());
    }

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files_recursive(&path, files)?;
        } else {
            files.push(path);
        }
    }
    Ok(())
}

pub async fn run_sender(
    file_path: &std::path::PathBuf,
    password: &str,
    connection_mode: ConnectionMode,
    persistent: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let key = utils::get_key_from_password(password);

    // Collect files to send (only once, outside the loop)
    let mut files = Vec::new();
    if file_path.is_dir() {
        collect_files_recursive(file_path, &mut files)?;
    } else {
        files.push(file_path.clone());
    }

    if files.is_empty() {
        return Err("No files to send".into());
    }

    let base_path = if file_path.is_dir() {
        file_path.clone()
    } else {
        file_path
            .parent()
            .unwrap_or(std::path::Path::new(""))
            .to_path_buf()
    };

    let is_folder = file_path.is_dir();

    // If persistent mode, we need to keep a listener alive
    let listener = if persistent && matches!(connection_mode, ConnectionMode::Listen) {
        // Create IPv6 socket with dual-stack support
        let addr = format!("[::]:{}", 3290).parse::<SocketAddr>()?;

        let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_only_v6(false)?;
        socket.set_reuse_address(true)?;
        socket.bind(&addr.into())?;
        socket.listen(128)?;

        let std_listener: std::net::TcpListener = socket.into();
        std_listener.set_nonblocking(true)?;
        Some(TcpListener::from_std(std_listener)?)
    } else {
        None
    };

    let _mdns = if listener.is_some() {
        Some(mdns::advertise_service(3290)?)
    } else {
        None
    };

    let mut transfer_count = 0u32;

    loop {
        transfer_count += 1;

        if persistent {
            println!("\n===========================================");
            println!("Transfer #{}", transfer_count);
            println!("===========================================");
        }

        let mut stream = if let Some(ref listener) = listener {
            println!(
                "Listening on {} (IPv4/IPv6 dual-stack)...",
                format!("[::]:{}", 3290)
            );
            println!("Waiting for peer to connect...\n");
            let (stream, socket_addr) = listener.accept().await?;
            println!("Connection accepted from {}\n", socket_addr);
            stream
        } else {
            establish_connection(&connection_mode, 3290).await?
        };

        // Handle the transfer
        match handle_single_transfer(&mut stream, &files, &base_path, is_folder, file_path, &key)
            .await
        {
            Ok(_) => {
                println!("\n===========================================");
                println!("Transfer complete!");
                println!("===========================================");
            }
            Err(e) => {
                eprintln!("\nTransfer error: {}", e);
                if !persistent {
                    return Err(e);
                }
                // In persistent mode, continue to next connection
                eprintln!("Waiting for next connection...");
            }
        }

        let _ = stream.shutdown().await;

        // If not persistent, break after one transfer
        if !persistent {
            break;
        }

        println!("\nWaiting for next connection...");
    }

    Ok(())
}

pub async fn run_sender_from_file(
    file: std::fs::File,
    filename: &str,
    password: &str,
    connection_mode: ConnectionMode,
    persistent: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let key = utils::get_key_from_password(password);

    // Get file size
    let size = file.metadata()?.len();

    // If persistent mode, we need to keep a listener alive
    let listener = if persistent && matches!(connection_mode, ConnectionMode::Listen) {
        // Create IPv6 socket with dual-stack support
        let addr = format!("[::]:{}", 3290).parse::<SocketAddr>()?;

        let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_only_v6(false)?;
        socket.set_reuse_address(true)?;
        socket.bind(&addr.into())?;
        socket.listen(128)?;

        let std_listener: std::net::TcpListener = socket.into();
        std_listener.set_nonblocking(true)?;
        Some(TcpListener::from_std(std_listener)?)
    } else {
        None
    };

    let _mdns = if listener.is_some() {
        Some(mdns::advertise_service(3290)?)
    } else {
        None
    };

    let mut transfer_count = 0u32;

    loop {
        transfer_count += 1;

        if persistent {
            println!("\n===========================================");
            println!("Transfer #{}", transfer_count);
            println!("===========================================");
        }

        let mut stream = if let Some(ref listener) = listener {
            println!(
                "Listening on {} (IPv4/IPv6 dual-stack)...",
                format!("[::]:{}", 3290)
            );
            println!("Waiting for peer to connect...\n");
            let (stream, socket_addr) = listener.accept().await?;
            println!("Connection accepted from {}\n", socket_addr);
            stream
        } else {
            establish_connection(&connection_mode, 3290).await?
        };

        // Handle the transfer
        match handle_single_file_transfer(&mut stream, &file, filename, size, &key).await {
            Ok(_) => {
                println!("\n===========================================");
                println!("Transfer complete!");
                println!("===========================================");
            }
            Err(e) => {
                eprintln!("\nTransfer error: {}", e);
                if !persistent {
                    return Err(e);
                }
                // In persistent mode, continue to next connection
                eprintln!("Waiting for next connection...");
            }
        }

        let _ = stream.shutdown().await;

        // If not persistent, break after one transfer
        if !persistent {
            break;
        }

        println!("\nWaiting for next connection...");
    }

    Ok(())
}

async fn handle_single_transfer(
    stream: &mut TcpStream,
    files: &[std::path::PathBuf],
    base_path: &std::path::PathBuf,
    is_folder: bool,
    file_path: &std::path::PathBuf,
    key: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    utils::version_handshake(stream, false, VERSION).await?;

    // Mode confirmation (1 = send, 0 = receive)
    let peer_mode = stream.read_u64().await?;
    if peer_mode == 1 {
        stream.write_u64(0).await?;
        return Err("Both ends selected send mode".into());
    } else {
        stream.write_u64(1).await?;
    }

    // Send number of files
    stream.write_u64(files.len() as u64).await?;

    // Send folder info: 1 if sending a folder, 0 if single file
    stream.write_u64(if is_folder { 1 } else { 0 }).await?;

    // If sending a folder, send the folder name
    if is_folder {
        let folder_name = file_path
            .file_name()
            .ok_or("Invalid folder name")?
            .to_string_lossy()
            .to_string();
        stream.write_u64(folder_name.len() as u64).await?;
        stream.write_all(folder_name.as_bytes()).await?;
    }

    // Send each file sequentially
    // Only check duplicate for single file transfer
    let check_duplicate = files.len() == 1;

    for (i, file) in files.iter().enumerate() {
        println!("\n===========================================");
        println!("File {} of {}", i + 1, files.len());
        println!("===========================================");
        send::send_file(stream, file, base_path, key, check_duplicate).await?;
    }

    Ok(())
}

async fn send_file_from_handle(
    file_handle: std::fs::File,
    filename: &str,
    size: u64,
    key: &[u8],
    stream: &mut TcpStream,
    check_duplicate: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, aead::Aead, aead::OsRng};
    use humansize::{BINARY, format_size};
    use std::io::Read;
    use std::time::{Duration, Instant};

    const CHUNKSIZE: usize = 1_000_000; // 1 MB

    let start = Instant::now();
    let cipher = Aes256Gcm::new_from_slice(key)?;

    println!("Sending file: {}", filename);
    println!("File size: {}", format_size(size, BINARY));

    // Send file details
    stream.write_u64(filename.len() as u64).await?;
    stream.write_all(filename.as_bytes()).await?;
    stream.write_u64(size).await?;

    // Check if receiver already has this file
    if check_duplicate {
        let has_file = stream.read_u64().await?;
        if has_file == 1 {
            let hash = utils::hash_file(&file_handle)?;
            stream.write_all(&hash).await?;
            let hashes_match = stream.read_u64().await?;
            if hashes_match == 1 {
                println!("Recipient already has this file, skipping.");
                return Ok(());
            }
        }
    }

    // Stream file data immediately without waiting for confirmation
    let mut file = file_handle;
    let mut buffer = vec![0u8; CHUNKSIZE];
    let mut progress = utils::ProgressTracker::new();
    let mut bytes_sent = 0u64;

    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(bytes_read) => {
                let chunk = &buffer[..bytes_read];

                let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
                let encrypted_chunk = cipher
                    .encrypt(&nonce, chunk)
                    .map_err(|e| format!("Encryption error: {:?}", e))?;

                let mut nonce_and_chunk = nonce.to_vec();
                nonce_and_chunk.extend_from_slice(&encrypted_chunk);

                // Send immediately (streaming)
                stream.write_u64(nonce_and_chunk.len() as u64).await?;
                stream.write_all(&nonce_and_chunk).await?;

                bytes_sent += bytes_read as u64;
                progress.update(bytes_sent, size)?;
            }
            Err(e) => return Err(Box::new(e)),
        }
    }

    // Send chunk size of 0 to signal end of this file
    stream.write_u64(0).await?;
    progress.finish()?;

    let elapsed = Instant::now() - start;
    println!(
        "Sending took {}",
        humantime::format_duration(Duration::from_secs_f64(elapsed.as_secs_f64()))
    );

    let megabits = 8.0 * (size as f64 / 1_000_000.0);
    let mbps = megabits / elapsed.as_secs_f64();
    println!("Speed: {:.2}mbps", mbps);

    Ok(())
}

async fn handle_single_file_transfer(
    stream: &mut TcpStream,
    file: &std::fs::File,
    filename: &str,
    size: u64,
    key: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    utils::version_handshake(stream, false, VERSION).await?;

    // Mode confirmation (1 = send, 0 = receive)
    let peer_mode = stream.read_u64().await?;
    if peer_mode == 1 {
        stream.write_u64(0).await?;
        return Err("Both ends selected send mode".into());
    } else {
        stream.write_u64(1).await?;
    }

    // Send number of files (always 1 for single file transfer)
    stream.write_u64(1).await?;

    // Send folder info: 0 for single file
    stream.write_u64(0).await?;

    // Send the file
    println!("\n===========================================");
    println!("File 1 of 1");
    println!("===========================================");

    // Clone the file handle to allow multiple reads
    let file_clone = file.try_clone()?;
    send_file_from_handle(file_clone, filename, size, key, stream, true).await?;

    Ok(())
}
