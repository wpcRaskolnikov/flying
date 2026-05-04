use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredHost {
    pub name: String,
    pub ip: String,
    pub port: u16,
    pub service_type: String,
}

#[tauri::command]
pub fn generate_password() -> Result<String, String> {
    Ok(flying::generate_password())
}

#[tauri::command]
pub async fn discover_hosts() -> Result<Vec<DiscoveredHost>, String> {
    let services = tokio::task::spawn_blocking(|| {
        flying::mdns::discover_services(3).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))??;

    let discovered: Vec<DiscoveredHost> = services
        .into_iter()
        .map(|service| DiscoveredHost {
            name: service.hostname,
            ip: service.ip.to_string(),
            port: service.port,
            service_type: "file-transfer".to_string(),
        })
        .collect();

    Ok(discovered)
}

#[tauri::command]
pub async fn discover_collab_hosts() -> Result<Vec<DiscoveredHost>, String> {
    let services = tokio::task::spawn_blocking(|| {
        flying::mdns::discover_collab_services(3).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))??;

    let discovered: Vec<DiscoveredHost> = services
        .into_iter()
        .map(|service| DiscoveredHost {
            name: service.hostname,
            ip: service.ip.to_string(),
            port: service.port,
            service_type: "collab".to_string(),
        })
        .collect();

    Ok(discovered)
}
