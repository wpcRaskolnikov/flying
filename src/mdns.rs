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

    let properties = [("version", "4")];
    let service_info = ServiceInfo::new(
        SERVICE_TYPE,
        &instance_name,
        &service_hostname,
        "",
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

fn extract_ip(scoped_ip: &mdns_sd::ScopedIp) -> Option<IpAddr> {
    match scoped_ip {
        mdns_sd::ScopedIp::V4(scoped_v4) => Some(IpAddr::V4(*scoped_v4.addr())),
        mdns_sd::ScopedIp::V6(v6) => Some(IpAddr::V6(*v6.addr())),
        _ => None,
    }
}

fn is_valid_ip(ip_addr: IpAddr) -> bool {
    if ip_addr.is_loopback() || ip_addr.is_unspecified() {
        return false;
    }

    let is_link_local = match ip_addr {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_unicast_link_local(),
    };

    !is_link_local
}

pub fn discover_services(
    timeout_secs: u64,
) -> Result<Vec<DiscoveredService>, Box<dyn std::error::Error>> {
    let mdns = ServiceDaemon::new()?;
    let receiver = mdns.browse(SERVICE_TYPE)?;

    println!("Scanning for peers on the network...");

    let mut services = Vec::new();
    let start_time = std::time::Instant::now();

    while start_time.elapsed().as_secs() < timeout_secs {
        use mdns_sd::ServiceEvent;

        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                for scoped_ip in info.get_addresses() {
                    let Some(ip_addr) = extract_ip(&scoped_ip) else {
                        continue;
                    };

                    if !is_valid_ip(ip_addr) {
                        continue;
                    }

                    let already_exists = services
                        .iter()
                        .any(|s: &DiscoveredService| s.ip == ip_addr && s.port == info.get_port());
                    if already_exists {
                        continue;
                    }

                    services.push(DiscoveredService {
                        hostname: info.get_hostname().to_string(),
                        ip: ip_addr,
                        port: info.get_port(),
                    });
                }
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }

    Ok(services)
}
