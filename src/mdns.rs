pub use mdns_sd::{ServiceDaemon, ServiceInfo};
use std::{net::IpAddr, time::Duration};

pub struct MdnsService(pub ServiceDaemon);

impl Drop for MdnsService {
    fn drop(&mut self) {
        let _ = self.0.shutdown();
    }
}
impl MdnsService {
    pub fn shutdown(self) {
        drop(self);
    }
}

fn get_hostname() -> anyhow::Result<String> {
    #[cfg(target_os = "android")]
    {
        const PROP_VALUE_MAX: usize = 92;

        fn get_prop(key: &std::ffi::CStr) -> String {
            let mut buf = [0u8; PROP_VALUE_MAX];

            let len = unsafe {
                libc::__system_property_get(key.as_ptr(), buf.as_mut_ptr() as *mut libc::c_char)
            };
            if len == 0 {
                return String::new();
            }

            let nul_pos = buf.iter().position(|&b| b == 0).unwrap_or(len as usize);
            String::from_utf8_lossy(&buf[..nul_pos]).to_string()
        }

        Ok(format!(
            "{} {}",
            get_prop(c"ro.product.brand"),
            get_prop(c"ro.product.model")
        ))
    }

    #[cfg(not(target_os = "android"))]
    {
        Ok(hostname::get()?.to_string_lossy().to_string())
    }
}

pub struct DiscoveredService {
    pub hostname: String,
    pub ip: IpAddr,
    pub port: u16,
    pub service_type: String,
}

pub fn advertise_service(service_name: &str, port: u16) -> anyhow::Result<MdnsService> {
    let service_type = format!("_{}._tcp.local.", service_name);
    let mdns = ServiceDaemon::new()?;

    let hostname = get_hostname()?;
    let instance_name = format!("{}-{}", hostname, service_name);
    let service_hostname = format!("{}.local.", hostname);

    let properties = [("version", "5")];
    let service_info = ServiceInfo::new(
        &service_type,
        &instance_name,
        &service_hostname,
        "",
        port,
        &properties[..],
    )?
    .enable_addr_auto();
    mdns.register(service_info)?;

    println!("Broadcasting mDNS service: {}", instance_name);

    Ok(MdnsService(mdns))
}

pub fn discover_services(
    service_name: &str,
    timeout: Duration,
) -> anyhow::Result<Vec<DiscoveredService>> {
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

    println!("Scanning for {} services on the network...", service_name);

    let mut result = Vec::new();
    let service_type = format!("_{}._tcp.local.", service_name);
    let mdns = ServiceDaemon::new()?;
    let receiver = mdns.browse(&service_type)?;

    let start_time = std::time::Instant::now();
    while start_time.elapsed() < timeout {
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

                    let already_exists = result
                        .iter()
                        .any(|s: &DiscoveredService| s.ip == ip_addr && s.port == info.get_port());
                    if already_exists {
                        continue;
                    }

                    result.push(DiscoveredService {
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

    Ok(result)
}

