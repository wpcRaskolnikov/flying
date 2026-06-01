use flying::mdns::{discover_collab_services, discover_services};

use serde::{Deserialize, Serialize};

use tokio::task::spawn_blocking;

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
    let transfer_handle = spawn_blocking(|| discover_services(3).map_err(|e| e.to_string()));
    let collab_handle = spawn_blocking(|| discover_collab_services(3).map_err(|e| e.to_string()));

    let (transfer_result, collab_result) = tokio::join!(transfer_handle, collab_handle);

    let mut discovered = Vec::new();

    match transfer_result {
        Ok(Ok(services)) => {
            discovered.extend(services.into_iter().map(|service| DiscoveredHost {
                name: service.hostname,
                ip: service.ip.to_string(),
                port: service.port,
                service_type: "file-transfer".to_string(),
            }));
        }
        Ok(Err(e)) => eprintln!("File transfer discovery failed: {}", e),
        Err(e) => eprintln!("File transfer discovery task panicked: {}", e),
    }

    match collab_result {
        Ok(Ok(services)) => {
            discovered.extend(services.into_iter().map(|service| DiscoveredHost {
                name: service.hostname,
                ip: service.ip.to_string(),
                port: service.port,
                service_type: "collab".to_string(),
            }));
        }
        Ok(Err(e)) => eprintln!("Collab discovery failed: {}", e),
        Err(e) => eprintln!("Collab discovery task panicked: {}", e),
    }

    Ok(discovered)
}
