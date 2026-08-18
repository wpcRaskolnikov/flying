mod mdns;
pub mod metadata;
pub mod progress;
pub mod receive;
pub mod relay;
pub mod send;
pub mod session;

use libp2p::{Multiaddr, PeerId};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::{net::TcpStream, sync::mpsc::Sender};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;

pub use mdns::{DiscoveredService, advertise_service, discover_services};
pub use session::NetworkStream;
pub const VERSION: u64 = 5;
const TRANSFER_SERVICE_NAME: &str = "flying-transfer";

#[derive(Debug, Clone)]
pub enum ConnectionMode {
    AutoDiscover,
    Listen,
    Connect(IpAddr),
    RelayListen {
        relay_addr: Multiaddr,
    },
    RelayDial {
        relay_addr: Multiaddr,
        remote_peer_id: PeerId,
    },
}

impl ConnectionMode {
    pub fn from_params(
        listen: bool,
        connect: Option<IpAddr>,
        relay_addr: Option<Multiaddr>,
        remote_peer_id: Option<PeerId>,
    ) -> Self {
        match (relay_addr, remote_peer_id, connect, listen) {
            (Some(relay), Some(peer), _, _) => ConnectionMode::RelayDial {
                relay_addr: relay,
                remote_peer_id: peer,
            },
            (Some(relay), None, _, _) => ConnectionMode::RelayListen { relay_addr: relay },
            (None, _, Some(ip), _) => ConnectionMode::Connect(ip),
            (None, _, None, true) => ConnectionMode::Listen,
            (None, _, None, false) => ConnectionMode::AutoDiscover,
        }
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

fn select_service(services: &[DiscoveredService]) -> Option<&DiscoveredService> {
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

    loop {
        println!("\nSelect a peer (1-{}):", services.len());

        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_err() {
            eprintln!("Failed to read input.");
            return None;
        }

        let selection: usize = match input.trim().parse() {
            Ok(n) => n,
            Err(_) => {
                println!("Invalid input. Please enter a number.");
                continue;
            }
        };

        if selection > 0 && selection <= services.len() {
            return Some(&services[selection - 1]);
        } else {
            println!("Please enter a number between 1 and {}.", services.len());
        }
    }
}

pub async fn establish_connection(
    mode: &ConnectionMode,
    port: u16,
    peer_id_tx: Option<Sender<String>>,
) -> anyhow::Result<Box<dyn NetworkStream>> {
    async fn connect_to(ip: IpAddr, port: u16) -> anyhow::Result<TcpStream> {
        let addr = SocketAddr::new(ip, port);
        println!("Connecting to {}...", addr);
        let stream = TcpStream::connect(addr).await?;
        println!("Connected!\n");
        Ok(stream)
    }

    match mode {
        ConnectionMode::AutoDiscover => {
            println!("Searching for peers on the local network...\n");
            let services = discover_services(TRANSFER_SERVICE_NAME, Duration::from_secs(3))?;

            if let Some(service) = select_service(&services) {
                let stream = connect_to(service.ip, service.port).await?;
                Ok(Box::new(stream) as Box<dyn NetworkStream>)
            } else {
                anyhow::bail!("No peers found on the local network")
            }
        }
        ConnectionMode::Listen => {
            let listener = create_listener(port)?;
            let _mdns_guard = advertise_service(TRANSFER_SERVICE_NAME, port)?;
            println!("Listening on [::]:{} (IPv4/IPv6 dual-stack)...", port);
            let (stream, addr) = listener.accept().await?;
            println!("Connection accepted from {}\n", addr);
            Ok(Box::new(stream) as Box<dyn NetworkStream>)
        }
        ConnectionMode::Connect(ip) => {
            let stream = connect_to(*ip, port).await?;
            Ok(Box::new(stream) as Box<dyn NetworkStream>)
        }
        ConnectionMode::RelayListen { relay_addr } => {
            let stream = relay::relay_listen(relay_addr.clone(), peer_id_tx).await?;
            Ok(Box::new(stream) as Box<dyn NetworkStream>)
        }
        ConnectionMode::RelayDial {
            relay_addr,
            remote_peer_id,
        } => {
            let stream = relay::relay_dial(relay_addr.clone(), *remote_peer_id, peer_id_tx).await?;
            Ok(Box::new(stream) as Box<dyn NetworkStream>)
        }
    }
}
