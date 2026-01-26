use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredHost {
    pub name: String,
    pub ip: String,
}

#[tauri::command]
pub fn generate_password() -> Result<String, String> {
    Ok(flying::utils::generate_password())
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
        })
        .collect();

    Ok(discovered)
}
