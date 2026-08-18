use flying::mdns::discover_services;
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredHost {
    pub name: String,
    pub ip: String,
    pub port: u16,
    pub service_type: String,
}

#[tauri::command]
pub async fn discover_hosts() -> Result<Vec<DiscoveredHost>, String> {
    let ft_handle =
        tokio::task::spawn_blocking(|| discover_services("flying-transfer", Duration::from_secs(3)));
    let collab_handle =
        tokio::task::spawn_blocking(|| discover_services("flying-collab", Duration::from_secs(3)));

    let (ft_res, collab_res) = tokio::join!(ft_handle, collab_handle);

    let ft_services = ft_res
        .map_err(|e| format!("Discovery task panicked: {e}"))?
        .map_err(|e| format!("Discovery failed: {e}"))?;
    let collab_services = collab_res
        .map_err(|e| format!("Discovery task panicked: {e}"))?
        .map_err(|e| format!("Discovery failed: {e}"))?;

    let mut services = ft_services;
    services.extend(collab_services);

    Ok(services
        .into_iter()
        .map(|s| DiscoveredHost {
            name: s.hostname,
            ip: s.ip.to_string(),
            port: s.port,
            service_type: s.service_type,
        })
        .collect())
}
