pub mod mdns;
mod receive;
mod send;
mod utils;
use mdns_sd::ServiceDaemon;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
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
            let mdns_daemon = mdns::advertise_service(port)?;

            println!("Listening on [::]:{} (IPv4/IPv6 dual-stack)...", port);
            println!("Waiting for peer to connect...\n");
            let (stream, socket_addr) = listener.accept().await?;
            println!("Connection accepted from {}\n", socket_addr);
            Ok((stream, Some(mdns_daemon)))
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

pub fn generate_password() -> String {
    petname::petname(3, "-").unwrap_or_else(|| "flying-transfer-secret".to_string())
}

pub async fn run_receiver(
    output_dir: &Path,
    password: &str,
    connection_mode: ConnectionMode,
    port: u16,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    let (mut stream, mdns_daemon) = establish_connection(&connection_mode, port).await?;

    let (key, relative_path, is_folder) =
        utils::receive_handshake(&mut stream, VERSION, password).await?;

    if is_folder {
        let folder_path = output_dir.join(&relative_path);
        receive::receive_folder(&mut stream, &folder_path, &key, progress_tx).await?;
    } else {
        receive::receive_file(&mut stream, output_dir, &key, progress_tx).await?;
    }

    println!("\nTransfer complete!");

    stream.shutdown().await?;
    if let Some(mdns_daemon) = mdns_daemon {
        let _ = mdns_daemon.shutdown();
    }
    Ok(())
}

pub async fn run_sender(
    file_path: &Path,
    password: &str,
    connection_mode: ConnectionMode,
    port: u16,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    let is_folder = file_path.is_dir();

    let relative_path = file_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Invalid file/folder name"))?
        .to_string_lossy()
        .to_string();

    let (mut stream, mdns_daemon) = establish_connection(&connection_mode, port).await?;

    let key =
        utils::send_handshake(&mut stream, VERSION, password, &relative_path, is_folder).await?;

    if is_folder {
        send::send_folder(&mut stream, file_path, &key, progress_tx).await?;
    } else {
        send::send_file(&mut stream, file_path, &key, progress_tx).await?;
    }

    println!("\nTransfer complete!");

    stream.shutdown().await?;
    if let Some(mdns_daemon) = mdns_daemon {
        let _ = mdns_daemon.shutdown();
    }
    Ok(())
}

pub async fn run_sender_persistent(
    file_path: &Path,
    password: &str,
    port: u16,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    let is_folder = file_path.is_dir();

    let relative_path = file_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Invalid file/folder name"))?
        .to_string_lossy()
        .to_string();

    let listener = utils::create_listener(port)?;
    let _mdns_daemon = mdns::advertise_service(port)?;

    let mut transfer_count = 0u32;
    loop {
        transfer_count += 1;

        println!("\n===========================================");
        println!("Transfer #{}", transfer_count);
        println!("===========================================");

        println!("Listening on [::]:{} (IPv4/IPv6 dual-stack)...", port);
        println!("Waiting for peer to connect...\n");
        let (mut stream, socket_addr) = listener.accept().await?;
        println!("Connection accepted from {}\n", socket_addr);

        let result = async {
            let key =
                utils::send_handshake(&mut stream, VERSION, password, &relative_path, is_folder)
                    .await?;

            if is_folder {
                send::send_folder(&mut stream, file_path, &key, progress_tx.clone()).await?;
            } else {
                send::send_file(&mut stream, file_path, &key, progress_tx.clone()).await?;
            }

            println!("\nTransfer complete!");
            stream.shutdown().await?;

            Ok::<(), anyhow::Error>(())
        }
        .await;

        match result {
            Ok(_) => {}
            Err(e) => {
                eprintln!("\nTransfer error: {}", e);
            }
        }

        println!("\nWaiting for next connection...");
    }

    #[allow(unreachable_code)]
    {
        let _ = _mdns_daemon.shutdown();
        Ok(())
    }
}

pub struct FileHandle {
    pub file: std::fs::File,
    pub path: String,
    pub size: u64,
}

pub async fn run_sender_from_handle(
    files: Vec<FileHandle>,
    relative_path: &str,
    password: &str,
    connection_mode: ConnectionMode,
    port: u16,
    progress_tx: Option<Sender<u8>>,
) -> anyhow::Result<()> {
    if files.is_empty() {
        anyhow::bail!("No files to send");
    }

    let (mut stream, _mdns_daemon) = establish_connection(&connection_mode, port).await?;

    let transfer_result = async {
        let is_folder = files.len() > 1;

        let key =
            utils::send_handshake(&mut stream, VERSION, password, relative_path, is_folder).await?;

        let check_duplicate_flag = !is_folder;
        let total_files = files.len();

        for (i, file_handle) in files.into_iter().enumerate() {
            if total_files > 1 {
                println!("[{}] Sending...", i + 1);
            }

            let tokio_file = tokio::fs::File::from_std(file_handle.file);

            let file_progress_tx = if let Some(ref tx) = progress_tx {
                let tx = tx.clone();
                let (file_tx, mut file_rx) = tokio::sync::mpsc::channel::<u8>(32);

                tokio::spawn(async move {
                    while let Some(file_percent) = file_rx.recv().await {
                        let overall = ((i as f64 + file_percent as f64 / 100.0)
                            / total_files as f64
                            * 100.0) as u8;
                        let _ = tx.try_send(overall);
                    }
                });

                Some(file_tx)
            } else {
                None
            };

            // Send file
            println!(
                "Sending: {} ({})",
                file_handle.path,
                humansize::format_size(file_handle.size, humansize::BINARY)
            );

            send::send_metadata(&mut stream, &file_handle.path, file_handle.size).await?;

            if check_duplicate_flag {
                let mut temp_file = tokio_file;
                if send::check_duplicate(&mut stream, &mut temp_file).await? {
                    println!("Recipient already has this file, skipping.");
                    continue;
                }
                send::encrypt_and_send(
                    &mut stream,
                    temp_file,
                    file_handle.size,
                    &key,
                    file_progress_tx,
                )
                .await?;
            } else {
                send::encrypt_and_send(
                    &mut stream,
                    tokio_file,
                    file_handle.size,
                    &key,
                    file_progress_tx,
                )
                .await?;
            }
        }

        // Send end signal if it's a folder
        if is_folder {
            stream.write_u64(0).await?;
        }

        Ok::<(), anyhow::Error>(())
    }
    .await;

    match transfer_result {
        Ok(_) => {
            println!("\nTransfer complete!");
        }
        Err(e) => {
            eprintln!("\nTransfer error: {}", e);
            return Err(e);
        }
    }

    stream.shutdown().await?;
    if let Some(mdns_daemon) = _mdns_daemon {
        let _ = mdns_daemon.shutdown();
    }
    Ok(())
}
