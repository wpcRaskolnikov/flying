pub mod mdns;
mod receive;
mod send;
pub mod utils;

use std::net::SocketAddr;
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::mpsc};

pub const VERSION: u64 = 5;
const DEFAULT_PORT: u16 = 3290;

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

async fn establish_connection(mode: &ConnectionMode) -> anyhow::Result<TcpStream> {
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
                anyhow::bail!("No peers found on the local network")
            }
        }
        ConnectionMode::Listen => {
            let listener = utils::create_listener(DEFAULT_PORT)?;
            let _mdns = mdns::advertise_service(DEFAULT_PORT)?;

            println!(
                "Listening on [::]:{} (IPv4/IPv6 dual-stack)...",
                DEFAULT_PORT
            );
            println!("Waiting for peer to connect...\n");
            let (stream, socket_addr) = listener.accept().await?;
            println!("Connection accepted from {}\n", socket_addr);
            Ok(stream)
        }
        ConnectionMode::Connect(ip) => {
            let ip: std::net::IpAddr = ip.parse()?;
            let addr = std::net::SocketAddr::new(ip, DEFAULT_PORT);
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
    progress_tx: Option<mpsc::Sender<u8>>,
) -> anyhow::Result<()> {
    let mut stream = establish_connection(&connection_mode).await?;

    let (key, num_files, is_folder, folder_name) =
        utils::receive_handshake(&mut stream, VERSION, password).await?;

    println!("Receiving {} file(s)...\n", num_files);

    let final_output_dir = if is_folder {
        let folder_name = folder_name.ok_or_else(|| anyhow::anyhow!("Folder name missing"))?;
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

    let check_duplicate = num_files == 1;

    for i in 0..num_files {
        println!("===========================================");
        println!("File {} of {}", i + 1, num_files);
        println!("===========================================");
        receive::receive_file(
            &mut stream,
            &final_output_dir,
            &key,
            check_duplicate,
            progress_tx.clone(),
        )
        .await?;
        println!();
    }

    println!("===========================================");
    println!("Transfer complete!");
    println!("===========================================");

    stream.shutdown().await?;
    Ok(())
}

fn collect_files(
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
            collect_files(&path, files)?;
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
    progress_tx: Option<mpsc::Sender<u8>>,
) -> anyhow::Result<()> {
    let mut files = Vec::new();
    collect_files(file_path, &mut files)?;

    if files.is_empty() {
        anyhow::bail!("No files to send");
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
    let folder_name = if is_folder {
        file_path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("Invalid folder name"))?
            .to_string_lossy()
            .to_string()
    } else {
        String::new()
    };

    let listener = if persistent && matches!(connection_mode, ConnectionMode::Listen) {
        let l = utils::create_listener(DEFAULT_PORT)?;
        mdns::advertise_service(DEFAULT_PORT)?;
        Some(l)
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
                "Listening on [::]:{} (IPv4/IPv6 dual-stack)...",
                DEFAULT_PORT
            );
            println!("Waiting for peer to connect...\n");
            let (stream, socket_addr) = listener.accept().await?;
            println!("Connection accepted from {}\n", socket_addr);
            stream
        } else {
            establish_connection(&connection_mode).await?
        };

        let transfer_result = async {
            let folder_name_opt = if is_folder {
                Some(folder_name.as_str())
            } else {
                None
            };

            let key = utils::send_handshake(
                &mut stream,
                VERSION,
                password,
                files.len() as u64,
                is_folder,
                folder_name_opt,
            )
            .await?;

            let check_duplicate = files.len() == 1;
            for (i, file) in files.iter().enumerate() {
                println!("\n===========================================");
                println!("File {} of {}", i + 1, files.len());
                println!("===========================================");
                send::send_from_path(
                    &mut stream,
                    file,
                    &base_path,
                    &key,
                    check_duplicate,
                    progress_tx.clone(),
                )
                .await?;
            }

            Ok::<(), anyhow::Error>(())
        }
        .await;

        match transfer_result {
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
                eprintln!("Waiting for next connection...");
            }
        }

        let _ = stream.shutdown().await;

        if !persistent {
            break;
        }
        println!("\nWaiting for next connection...");
    }

    Ok(())
}

pub async fn run_sender_from_handle(
    file: std::fs::File,
    filename: &str,
    password: &str,
    connection_mode: ConnectionMode,
    progress_tx: Option<mpsc::Sender<u8>>,
) -> anyhow::Result<()> {
    let size = file.metadata()?.len();
    let mut stream = establish_connection(&connection_mode).await?;

    let transfer_result = async {
        let key = utils::send_handshake(&mut stream, VERSION, password, 1, false, None).await?;

        println!("\n===========================================");
        println!("File 1 of 1");
        println!("===========================================");
        send::send_file(&mut stream, file, filename, size, &key, true, progress_tx).await?;

        Ok::<(), anyhow::Error>(())
    }
    .await;

    match transfer_result {
        Ok(_) => {
            println!("\n===========================================");
            println!("Transfer complete!");
            println!("===========================================");
        }
        Err(e) => {
            eprintln!("\nTransfer error: {}", e);
            return Err(e);
        }
    }

    stream.shutdown().await?;
    Ok(())
}
