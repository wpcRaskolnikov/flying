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

pub fn get_or_prompt_password(
    connection_mode: &ConnectionMode,
    password: Option<String>,
) -> String {
    match connection_mode {
        ConnectionMode::Listen => utils::generate_password(),
        ConnectionMode::AutoDiscover | ConnectionMode::Connect(_) => {
            password.unwrap_or_else(|| {
                println!("Please enter password:");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).unwrap();
                input.trim().to_string()
            })
        }
    }
}

pub fn print_session_info(
    mode: &str,
    password: &str,
    connection_mode: &ConnectionMode,
    output_dir: Option<&std::path::PathBuf>,
) {
    println!("===========================================");
    println!("Flying - File Transfer Tool");
    println!("===========================================");
    println!("Mode: {}", mode);
    println!("Password: {}", password);
    if let Some(dir) = output_dir {
        println!("Output directory: {:?}", dir);
    }
    match connection_mode {
        ConnectionMode::AutoDiscover => {
            println!("Connection: Auto-discovering peers on local network")
        }
        ConnectionMode::Listen => {
            println!("Connection: Listening for incoming connections")
        }
        ConnectionMode::Connect(ip) => println!("Connection: Will connect to {}", ip),
    }
    println!("===========================================\n");
}

pub async fn version_handshake(
    stream: &mut TcpStream,
    send_first: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (local_version, peer_version) = if send_first {
        stream.write_u64(VERSION).await?;
        let peer = stream.read_u64().await?;
        (VERSION, peer)
    } else {
        let peer = stream.read_u64().await?;
        stream.write_u64(VERSION).await?;
        (VERSION, peer)
    };

    if peer_version != local_version {
        println!(
            "Warning: Version mismatch (local: {}, peer: {})",
            local_version, peer_version
        );
    }

    Ok(())
}

pub async fn establish_connection(
    mode: &ConnectionMode,
    port: u16,
) -> Result<TcpStream, Box<dyn std::error::Error>> {
    match mode {
        ConnectionMode::AutoDiscover => {
            println!("Searching for peers on the local network...\n");

            let services = mdns::discover_services(5)?;

            if let Some(service) = mdns::select_service(&services) {
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
            // Create IPv6 socket with dual-stack support (works on Windows too)
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

pub async fn run_sender(
    file_path: &std::path::PathBuf,
    password: &str,
    connection_mode: ConnectionMode,
    _recursive: bool,
    persistent: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let key = utils::get_key_from_password(password);

    // Collect files to send (only once, outside the loop)
    let files = if file_path.is_dir() {
        utils::collect_files_recursive(file_path)?
    } else {
        vec![file_path.clone()]
    };

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
    version_handshake(stream, false).await?;

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
    let check_duplicate = files.len() == 1;

    for (i, file) in files.iter().enumerate() {
        println!("\n===========================================");
        println!("File {} of {}", i + 1, files.len());
        println!("===========================================");
        send::send_file(file, base_path, key, stream, check_duplicate).await?;
    }

    Ok(())
}

async fn handle_single_file_transfer(
    stream: &mut TcpStream,
    file: &std::fs::File,
    filename: &str,
    size: u64,
    key: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    version_handshake(stream, false).await?;

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
    send::send_file_from_handle(file_clone, filename, size, key, stream, true).await?;

    Ok(())
}

pub async fn run_receiver(
    output_dir: &std::path::PathBuf,
    password: &str,
    connection_mode: ConnectionMode,
) -> Result<(), Box<dyn std::error::Error>> {
    let key = utils::get_key_from_password(password);

    let mut stream = establish_connection(&connection_mode, 3290).await?;

    version_handshake(&mut stream, true).await?;

    // Mode confirmation (1 = send, 0 = receive)
    stream.write_u64(0).await?;
    let mode_ok = stream.read_u64().await?;
    if mode_ok != 1 {
        return Err("Both ends selected the same mode".into());
    }

    // Receive number of files
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

        // Create the folder if it doesn't exist
        if !folder_path.exists() {
            std::fs::create_dir_all(&folder_path)?;
        }

        folder_path
    } else {
        output_dir.clone()
    };

    // Receive files
    // For single file transfer, check for duplicates; for multiple files, stream without checking
    let check_duplicate = num_files == 1;

    for i in 0..num_files {
        println!("===========================================");
        println!("File {} of {}", i + 1, num_files);
        println!("===========================================");
        receive::receive_file(&final_output_dir, &key, &mut stream, check_duplicate).await?;
        println!();
    }

    println!("===========================================");
    println!("Transfer complete!");
    println!("===========================================");

    stream.shutdown().await?;
    Ok(())
}
