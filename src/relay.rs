use anyhow::{Result, anyhow};
use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, Stream, StreamProtocol, dcutr, identify, identity, noise, relay,
    swarm::{NetworkBehaviour, Swarm, SwarmEvent},
    tcp, yamux,
};
use libp2p_stream as stream;
use std::time::Duration;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt};

const STREAM_PROTOCOL: StreamProtocol = StreamProtocol::new("/flying/stream/1.0.0");

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    relay_client: relay::client::Behaviour,
    ping: libp2p::ping::Behaviour,
    identify: identify::Behaviour,
    dcutr: dcutr::Behaviour,
    stream: stream::Behaviour,
}

fn create_swarm() -> Result<Swarm<Behaviour>> {
    let keypair = identity::Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id();

    tracing::info!("Local PeerId: {}", peer_id);

    let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_dns()?
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|keypair, relay_behaviour| Behaviour {
            relay_client: relay_behaviour,
            ping: libp2p::ping::Behaviour::new(libp2p::ping::Config::new()),
            identify: identify::Behaviour::new(identify::Config::new(
                "/flying/5.0.0".to_string(),
                keypair.public(),
            )),
            dcutr: dcutr::Behaviour::new(keypair.public().to_peer_id()),
            stream: stream::Behaviour::new(),
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(15 * 60)))
        .build();

    Ok(swarm)
}

async fn setup_listeners(swarm: &mut Swarm<Behaviour>) -> Result<()> {
    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    let timeout = tokio::time::sleep(Duration::from_secs(1));
    tokio::pin!(timeout);
    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        tracing::info!(%address, "Listening on address");
                    }
                    event => {
                        tracing::debug!(?event, "Unexpected event during listen setup");
                    }
                }
            }
            _ = &mut timeout => {
                break;
            }
        }
    }
    Ok(())
}

async fn connect_to_relay(swarm: &mut Swarm<Behaviour>, relay_addr: Multiaddr) -> Result<()> {
    println!("Connecting to relay server...");
    swarm.dial(relay_addr)?;

    let mut relay_connected = false;
    let mut observed_addr_learned = false;
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::debug!("Listening on: {}", address);
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                tracing::info!("Connected to relay: {}", peer_id);
                relay_connected = true;
            }
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                info: identify::Info { observed_addr, .. },
                ..
            })) => {
                tracing::info!("Observed address: {}", observed_addr);
                swarm.add_external_address(observed_addr.clone());
                observed_addr_learned = true;
            }
            SwarmEvent::Behaviour(BehaviourEvent::RelayClient(event)) => {
                tracing::debug!("Relay client event: {:?}", event);
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                return Err(anyhow!(
                    "Failed to connect to relay {:?}: {}",
                    peer_id,
                    error
                ));
            }
            _ => {}
        }

        if relay_connected && observed_addr_learned {
            break;
        }
    }
    Ok(())
}

pub async fn relay_listen(relay_addr: Multiaddr) -> Result<Compat<Stream>> {
    let mut swarm = create_swarm()?;
    let local_peer_id = *swarm.local_peer_id();

    // Display PeerID for manual exchange
    println!("\n===========================================");
    println!("Your PeerID: {}", local_peer_id);
    println!("Share this with the person you're transferring with");
    println!("===========================================\n");

    setup_listeners(&mut swarm).await?;
    connect_to_relay(&mut swarm, relay_addr.clone()).await?;

    // Listen on relay circuit - this will trigger reservation request
    println!("Requesting relay reservation...");
    swarm.listen_on(relay_addr.with(libp2p::core::multiaddr::Protocol::P2pCircuit))?;

    // Wait for reservation to be accepted
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::Behaviour(BehaviourEvent::RelayClient(
                relay::client::Event::ReservationReqAccepted { .. },
            )) => {
                println!("Relay reservation accepted!");
                break;
            }
            SwarmEvent::Behaviour(BehaviourEvent::RelayClient(event)) => {
                tracing::debug!("Relay client event: {:?}", event);
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::debug!("New listen address: {}", address);
            }
            _ => {}
        }
    }

    println!("Waiting for incoming connection through relay...\n");

    // Set up stream acceptance
    let mut incoming_streams = swarm
        .behaviour()
        .stream
        .new_control()
        .accept(STREAM_PROTOCOL)
        .map_err(|e| anyhow!("Failed to accept stream: {}", e))?;

    // Wait for incoming stream from remote peer
    let stream = loop {
        tokio::select! {
            Some((peer, stream)) = incoming_streams.next() => {
                tracing::info!("Stream received from peer: {}", peer);
                println!("Stream accepted!");
                break stream;
            }
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::ConnectionEstablished {
                        peer_id, endpoint, ..
                    } => {
                        println!("Connection established with peer: {}", peer_id);
                        tracing::info!("Connection endpoint: {:?}", endpoint);
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Dcutr(event)) => {
                        tracing::info!("DCUtR event: {:?}", event);
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Identify(event)) => {
                        tracing::debug!("Identify event: {:?}", event);
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::RelayClient(event)) => {
                        tracing::debug!("Relay client event: {:?}", event);
                    }
                    _ => {}
                }
            }
        }
    };

    // Spawn background task to keep swarm alive
    tokio::spawn(async move {
        loop {
            swarm.select_next_some().await;
        }
    });

    let stream_wrapper = stream.compat();
    Ok(stream_wrapper)
}

pub async fn relay_dial(relay_addr: Multiaddr, remote_peer_id: PeerId) -> Result<Compat<Stream>> {
    let mut swarm = create_swarm()?;

    setup_listeners(&mut swarm).await?;
    connect_to_relay(&mut swarm, relay_addr.clone()).await?;

    // Get stream control before event loop
    let mut stream_control = swarm.behaviour().stream.new_control();

    // Dial remote peer through relay
    println!("Dialing peer {} through relay...", remote_peer_id);
    let relay_dial_addr = relay_addr
        .with(libp2p::core::multiaddr::Protocol::P2pCircuit)
        .with(libp2p::core::multiaddr::Protocol::P2p(remote_peer_id));

    swarm.dial(relay_dial_addr)?;

    // Wait for relay connection first
    let mut relay_connected = false;
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                if peer_id == remote_peer_id {
                    println!("Connected to remote peer through relay!");
                    tracing::info!("Connection endpoint: {:?}", endpoint);
                    relay_connected = true;
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Dcutr(dcutr::Event {
                remote_peer_id: peer_id,
                result,
            })) => {
                if peer_id == remote_peer_id {
                    match result {
                        Ok(connection_id) => {
                            println!("Direct connection established (hole punching succeeded)!");
                            tracing::info!("Direct connection ID: {:?}", connection_id);
                            break;
                        }
                        Err(error) => {
                            tracing::warn!(
                                "DCUtR hole punching failed: {:?}, will use relay connection",
                                error
                            );
                            // Fallback to relay connection
                            if relay_connected {
                                break;
                            }
                        }
                    }
                }
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                if peer_id == Some(remote_peer_id) {
                    return Err(anyhow!("Failed to connect to remote peer: {}", error));
                }
            }
            _ => {}
        }
    }

    // Open stream after connection is ready (either direct or relay)
    println!("Opening file transfer stream...");
    let stream = stream_control
        .open_stream(remote_peer_id, STREAM_PROTOCOL)
        .await
        .map_err(|e| anyhow!("Failed to open stream: {}", e))?;

    println!("Stream established!\n");

    // Spawn background task to keep swarm alive
    tokio::spawn(async move {
        loop {
            swarm.select_next_some().await;
        }
    });

    let stream_wrapper = stream.compat();
    Ok(stream_wrapper)
}
