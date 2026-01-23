pub mod mdns;
mod receive;
mod send;
pub mod utils;
use mdns_sd::ServiceDaemon;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::mpsc::Sender};
pub const VERSION: u64 = 5;

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
) -> anyhow::Result<(TcpStream, Option<ServiceDaemon>)> {
    match mode {
        ConnectionMode::AutoDiscover => {
            println!("Searching for peers on the local network...\n");
            let services = mdns::discover_services(3)?;

            if let Some(service) = select_service(&services) {
                let addr = SocketAddr::new(service.ip, service.port);
                println!("\nConnecting to {}...", addr);
                let stream = TcpStream::connect(addr).await?;
                println!("Connected!\n");
                Ok((stream, None))
            } else {
                anyhow::bail!("No peers found on the local network")
            }
        }
        ConnectionMode::Listen => {
            let listener = utils::create_listener(port)?;
            let mdns = mdns::advertise_service(port)?;

            println!("Listening on [::]:{} (IPv4/IPv6 dual-stack)...", port);
            println!("Waiting for peer to connect...\n");
            let (stream, socket_addr) = listener.accept().await?;
            println!("Connection accepted from {}\n", socket_addr);
            Ok((stream, Some(mdns)))
        }
        ConnectionMode::Connect(ip) => {
            let ip: IpAddr = ip.parse()?;
            let addr = SocketAddr::new(ip, port);
            println!("Connecting to {}...", addr);
            let stream = TcpStream::connect(addr).await?;
            println!("Connected!\n");
            Ok((stream, None))
        }
    }
}

pub async fn run_receiver(
    output_dir: &Path,
    password: &str,
    connection_mode: ConnectionMode,
    port: u16,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    let (mut stream, _mdns) = establish_connection(&connection_mode, port).await?;

    let (key, num_files, is_folder, folder_name) =
        utils::receive_handshake(&mut stream, VERSION, password).await?;

    println!("Receiving {} file(s)...\n", num_files);

    let folder_path;
    let final_output_dir = if is_folder {
        let folder_name = folder_name.ok_or_else(|| anyhow::anyhow!("Folder name missing"))?;
        folder_path = output_dir.join(&folder_name);
        println!("Creating folder: {}\n", folder_name);
        if !folder_path.exists() {
            tokio::fs::create_dir_all(&folder_path).await?;
        }
        folder_path.as_path()
    } else {
        output_dir
    };

    let check_duplicate = num_files == 1;

    for i in 0..num_files {
        println!("===========================================");
        println!("File {} of {}", i + 1, num_files);
        println!("===========================================");
        receive::receive_file(
            &mut stream,
            final_output_dir,
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
    if let Some(mdns) = _mdns {
        let _ = mdns.shutdown();
    }
    Ok(())
}

async fn collect_files(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let metadata = tokio::fs::metadata(dir).await?;
    if metadata.is_file() {
        return Ok(vec![dir.to_path_buf()]);
    }

    let mut files = Vec::new();
    let mut entries = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let metadata = tokio::fs::metadata(&path).await?;
        if metadata.is_dir() {
            let mut sub_files = Box::pin(collect_files(&path)).await?;
            files.append(&mut sub_files);
        } else {
            files.push(path);
        }
    }
    Ok(files)
}

pub async fn run_sender(
    file_path: &Path,
    password: &str,
    connection_mode: ConnectionMode,
    persistent: bool,
    port: u16,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    let files = collect_files(file_path).await?;

    if files.is_empty() {
        anyhow::bail!("No files to send");
    }

    let owned_base_path;
    let base_path: &Path = if file_path.is_dir() {
        file_path
    } else {
        owned_base_path = file_path.parent().unwrap_or(Path::new(""));
        owned_base_path
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

    let (listener, mdns_handle) = if persistent && matches!(connection_mode, ConnectionMode::Listen)
    {
        let l = utils::create_listener(port)?;
        let mdns = mdns::advertise_service(port)?;
        (Some(l), Some(mdns))
    } else {
        (None, None)
    };

    let mut transfer_count = 0u32;
    loop {
        transfer_count += 1;

        if persistent {
            println!("\n===========================================");
            println!("Transfer #{}", transfer_count);
            println!("===========================================");
        }

        let (mut stream, mdns_from_connection) = if let Some(ref listener) = listener {
            println!("Listening on [::]:{} (IPv4/IPv6 dual-stack)...", port);
            println!("Waiting for peer to connect...\n");
            let (stream, socket_addr) = listener.accept().await?;
            println!("Connection accepted from {}\n", socket_addr);
            (stream, None)
        } else {
            establish_connection(&connection_mode, port).await?
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
            if let Some(mdns) = mdns_from_connection {
                let _ = mdns.shutdown();
            }
            break;
        }
        println!("\nWaiting for next connection...");
    }

    if let Some(mdns) = mdns_handle {
        let _ = mdns.shutdown();
    }
    Ok(())
}

pub async fn run_sender_from_handle(
    file: std::fs::File,
    filename: &str,
    password: &str,
    connection_mode: ConnectionMode,
    port: u16,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    let size = file.metadata()?.len();
    let tokio_file = tokio::fs::File::from_std(file);
    let (mut stream, _mdns) = establish_connection(&connection_mode, port).await?;

    let transfer_result = async {
        let key = utils::send_handshake(&mut stream, VERSION, password, 1, false, None).await?;

        println!("\n===========================================");
        println!("File 1 of 1");
        println!("===========================================");
        send::send_file(
            &mut stream,
            tokio_file,
            filename,
            size,
            &key,
            true,
            progress_tx,
        )
        .await?;

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
    if let Some(mdns) = _mdns {
        let _ = mdns.shutdown();
    }
    Ok(())
}
