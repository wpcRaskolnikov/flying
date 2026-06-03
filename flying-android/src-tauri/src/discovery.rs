use flying::mdns::discover_all_services;

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
    let services = discover_all_services(3)
        .await
        .map_err(|e| format!("Discovery failed: {e}"))?;

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
