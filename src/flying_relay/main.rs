use clap::Parser;
use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId,
    core::multiaddr::Protocol,
    identify, identity, noise, ping, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use std::{
    error::Error,
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

#[derive(Parser, Debug)]
#[command(name = "flying-relay")]
#[command(about = "Flying relay server for NAT traversal", long_about = None)]
struct Opts {
    #[arg(long, default_value = "4001")]
    port: u16,

    /// Use IPv6 instead of IPv4
    #[arg(long)]
    use_ipv6: bool,

    #[arg(long)]
    secret_key_seed: Option<u8>,
}

#[derive(NetworkBehaviour)]
struct RelayBehaviour {
    relay: relay::Behaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
}

fn generate_ed25519(secret_key_seed: u8) -> identity::Keypair {
    let mut bytes = [0u8; 32];
    bytes[0] = secret_key_seed;
    identity::Keypair::ed25519_from_bytes(bytes).expect("only errors on wrong length")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let opts = Opts::parse();

    let local_key = if let Some(seed) = opts.secret_key_seed {
        tracing::info!("Using deterministic keypair from seed: {}", seed);
        generate_ed25519(seed)
    } else {
        tracing::info!("Generating random keypair");
        identity::Keypair::generate_ed25519()
    };

    let local_peer_id = PeerId::from_public_key(&local_key.public());

    println!("\n===========================================");
    println!("Flying Relay Server");
    println!("===========================================");
    println!("Relay PeerID: {}", local_peer_id);
    println!("===========================================\n");

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|key| RelayBehaviour {
            relay: relay::Behaviour::new(key.public().to_peer_id(), Default::default()),
            ping: ping::Behaviour::new(ping::Config::new()),
            identify: identify::Behaviour::new(identify::Config::new(
                "/flying-relay/1.0.0".to_string(),
                key.public(),
            )),
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(3600)))
        .build();

    // Listen on all interfaces
    let listen_addr_tcp = Multiaddr::empty()
        .with(match opts.use_ipv6 {
            true => Protocol::from(Ipv6Addr::UNSPECIFIED),
            false => Protocol::from(Ipv4Addr::UNSPECIFIED),
        })
        .with(Protocol::Tcp(opts.port));
    swarm.listen_on(listen_addr_tcp)?;

    let listen_addr_quic = Multiaddr::empty()
        .with(match opts.use_ipv6 {
            true => Protocol::from(Ipv6Addr::UNSPECIFIED),
            false => Protocol::from(Ipv4Addr::UNSPECIFIED),
        })
        .with(Protocol::Udp(opts.port))
        .with(Protocol::QuicV1);
    swarm.listen_on(listen_addr_quic)?;

    println!("Relay server starting...\n");

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                println!("Listening on: {}", address);
                println!("Full relay address: {}/p2p/{}", address, local_peer_id);
            }
            SwarmEvent::Behaviour(event) => {
                if let RelayBehaviourEvent::Identify(identify::Event::Received {
                    info: identify::Info { observed_addr, .. },
                    ..
                }) = &event
                {
                    swarm.add_external_address(observed_addr.clone());
                    tracing::info!("Added external address: {}", observed_addr);
                }

                tracing::debug!("Behaviour event: {:?}", event);
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                tracing::info!(
                    "Connection established with peer: {} at {:?}",
                    peer_id,
                    endpoint
                );
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                tracing::info!(
                    "Connection closed with peer: {} (cause: {:?})",
                    peer_id,
                    cause
                );
            }
            SwarmEvent::IncomingConnection { .. } => {
                tracing::debug!("Incoming connection");
            }
            SwarmEvent::IncomingConnectionError { error, .. } => {
                tracing::warn!("Incoming connection error: {}", error);
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                tracing::warn!("Outgoing connection error to {:?}: {}", peer_id, error);
            }
            _ => {}
        }
    }
}
