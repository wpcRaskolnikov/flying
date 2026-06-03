pub use mdns_sd::{ServiceDaemon, ServiceInfo};
use std::{net::IpAddr, time::Duration};

fn get_hostname() -> anyhow::Result<String> {
    #[cfg(target_os = "android")]
    {
        const PROP_VALUE_MAX: usize = 92;
        let mut buf = [0u8; PROP_VALUE_MAX];

        // Read ro.product.brand
        let brand_len = unsafe {
            libc::__system_property_get(
                c"ro.product.brand".as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
            )
        };
        let brand = if brand_len == 0 {
            String::new()
        } else {
            let nul_pos = buf
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(brand_len as usize);
            String::from_utf8_lossy(&buf[..nul_pos]).to_string()
        };

        // Read ro.product.model
        let model_len = unsafe {
            libc::__system_property_get(
                c"ro.product.model".as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
            )
        };
        if model_len == 0 {
            anyhow::bail!("failed to get ro.product.model");
        }
        let nul_pos = buf
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(model_len as usize);
        let model = String::from_utf8_lossy(&buf[..nul_pos]).to_string();

        if brand.is_empty() {
            Ok(model)
        } else {
            Ok(format!("{} {}", brand, model))
        }
    }

    #[cfg(not(target_os = "android"))]
    {
        Ok(hostname::get()?.to_string_lossy().to_string())
    }
}

const SERVICE_TYPE: &str = "_flying._tcp.local.";
const SERVICE_NAME: &str = "flying-transfer";
const COLLAB_SERVICE_TYPE: &str = "_flying-collab._tcp.local.";
const COLLAB_SERVICE_NAME: &str = "flying-collab";

pub struct DiscoveredService {
    pub hostname: String,
    pub ip: IpAddr,
    pub port: u16,
    pub service_type: String,
}

pub fn advertise_service(port: u16) -> anyhow::Result<ServiceDaemon> {
    let mdns = ServiceDaemon::new()?;

    let hostname = get_hostname()?;
    let instance_name = format!("{}-{}", hostname, SERVICE_NAME);
    let service_hostname = format!("{}.local.", hostname);

    let properties = [("version", "5")];
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

pub fn advertise_collab_service(port: u16) -> anyhow::Result<ServiceDaemon> {
    let mdns = ServiceDaemon::new()?;

    let hostname = get_hostname()?;
    let instance_name = format!("{}-{}", hostname, COLLAB_SERVICE_NAME);
    let service_hostname = format!("{}.local.", hostname);

    let properties = [("version", "1")];
    let service_info = ServiceInfo::new(
        COLLAB_SERVICE_TYPE,
        &instance_name,
        &service_hostname,
        "",
        port,
        &properties[..],
    )?
    .enable_addr_auto();
    mdns.register(service_info)?;

    println!(
        "Broadcasting mDNS collab service: {}._flying-collab._tcp.local.",
        instance_name
    );

    Ok(mdns)
}

fn discover_services_by_type(
    mdns: &ServiceDaemon,
    timeout_secs: u64,
    service_type: &str,
) -> anyhow::Result<Vec<DiscoveredService>> {
    let receiver = mdns.browse(service_type)?;

    println!("Scanning for {} services on the network...", service_type);

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
                        service_type: service_type.to_string(),
                    });
                }
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }

    Ok(services)
}

pub fn discover_services(timeout_secs: u64) -> anyhow::Result<Vec<DiscoveredService>> {
    let mdns = ServiceDaemon::new()?;
    discover_services_by_type(&mdns, timeout_secs, SERVICE_TYPE)
}

pub async fn discover_all_services(timeout_secs: u64) -> anyhow::Result<Vec<DiscoveredService>> {
    let mdns = ServiceDaemon::new()?;

    println!("Scanning for all flying services on the network concurrently...");

    let mdns_clone1 = mdns.clone();
    let mdns_clone2 = mdns.clone();

    let ft_handle = tokio::task::spawn_blocking(move || {
        discover_services_by_type(&mdns_clone1, timeout_secs, SERVICE_TYPE)
    });

    let collab_handle = tokio::task::spawn_blocking(move || {
        discover_services_by_type(&mdns_clone2, timeout_secs, COLLAB_SERVICE_TYPE)
    });

    let (ft_res, collab_res) = tokio::join!(ft_handle, collab_handle);

    let ft_services = ft_res
        .map_err(|e| anyhow::anyhow!("File transfer task panicked: {e}"))??;

    let collab_services = collab_res
        .map_err(|e| anyhow::anyhow!("Collab task panicked: {e}"))??;

    let mut services = Vec::new();
    services.extend(ft_services);
    services.extend(collab_services);

    Ok(services)
}
