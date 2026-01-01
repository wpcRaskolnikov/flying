use mdns_sd::{ServiceDaemon, ServiceInfo};
use std::{net::IpAddr, time::Duration};

const SERVICE_TYPE: &str = "_flying._tcp.local.";
const SERVICE_NAME: &str = "flying-transfer";

pub struct DiscoveredService {
    pub hostname: String,
    pub ip: IpAddr,
    pub port: u16,
}

pub fn advertise_service(port: u16) -> Result<ServiceDaemon, Box<dyn std::error::Error>> {
    let mdns = ServiceDaemon::new()?;

    let hostname = hostname::get()?.to_string_lossy().to_string();
    let instance_name = format!("{}-{}", hostname, SERVICE_NAME);
    let service_hostname = format!("{}.local.", hostname);

    let properties = [("version", "2")];
    let service_info = ServiceInfo::new(
        SERVICE_TYPE,
        &instance_name,
        &service_hostname,
        "", // Will be replaced with actual IP addresses
        port,
        &properties[..],
    )?
    .enable_addr_auto();
    mdns.register(service_info)?;

    println!(
        "Broadcasting mDNS service: {}._flying._tcp.local.",
        instance_name
    );

    Ok(mdns)
}

pub fn discover_services(
    timeout_secs: u64,
) -> Result<Vec<DiscoveredService>, Box<dyn std::error::Error>> {
    let mdns = ServiceDaemon::new()?;

    let receiver = mdns.browse(SERVICE_TYPE)?;

    println!("Scanning for peers on the network...");

    let mut services = Vec::new();
    let start_time = std::time::Instant::now();

    // Poll for events continuously during the timeout period
    while start_time.elapsed().as_secs() < timeout_secs {
        use mdns_sd::ServiceEvent;

        // Check for new events
        while let Ok(event) = receiver.try_recv() {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    // Get addresses and convert from ScopedIp to IpAddr
                    for scoped_ip in info.get_addresses() {
                        let ip_addr = match scoped_ip {
                            mdns_sd::ScopedIp::V4(scoped_v4) => IpAddr::V4(*scoped_v4.addr()),
                            mdns_sd::ScopedIp::V6(scoped_v6) => {
                                let addr = *scoped_v6.addr();
                                // Skip link-local IPv6 addresses without proper scope
                                if addr.is_loopback()
                                    || addr.is_unspecified()
                                    || addr.is_unicast_link_local()
                                {
                                    continue;
                                }
                                IpAddr::V6(addr)
                            }
                            _ => continue, // Skip any other address types
                        };

                        // Check if we already have this service
                        let already_exists = services.iter().any(|s: &DiscoveredService| {
                            s.ip == ip_addr && s.port == info.get_port()
                        });
                        if !already_exists {
                            services.push(DiscoveredService {
                                hostname: info.get_hostname().to_string(),
                                ip: ip_addr,
                                port: info.get_port(),
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        // Sleep a bit before polling again
        std::thread::sleep(Duration::from_millis(100));
    }

    Ok(services)
}

pub fn select_service(services: &[DiscoveredService]) -> Option<&DiscoveredService> {
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
