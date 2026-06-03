use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PickedEntity {
    pub path_or_uri: String,
    pub name: String,
}

#[tauri::command]
#[cfg(target_os = "android")]
pub async fn pick_file(app: tauri::AppHandle) -> Result<Option<PickedEntity>, String> {
    use tauri_plugin_android_fs::AndroidFsExt;
    let api = app.android_fs_async();

    let uri = api
        .file_picker()
        .pick_file(
            None,     // Initial location
            &["*/*"], // Target MIME types (all files)
            false,    // If true, only files on local device
        )
        .await
        .map_err(|e| format!("File picker error: {}", e))?;

    let Some(uri) = uri else {
        return Ok(None);
    };

    let name = api
        .get_name(&uri)
        .await
        .map_err(|e| format!("Failed to get file name: {}", e))?;

    let path_or_uri = uri
        .to_json_string()
        .map_err(|e| format!("Failed to serialize URI: {}", e))?;

    Ok(Some(PickedEntity { path_or_uri, name }))
}

#[tauri::command]
#[cfg(not(target_os = "android"))]
pub async fn pick_file(app: tauri::AppHandle) -> Result<Option<PickedEntity>, String> {
    use tauri_plugin_dialog::DialogExt;
    let Some(tauri_plugin_dialog::FilePath::Path(file)) = app.dialog().file().blocking_pick_file()
    else {
        return Ok(None);
    };
    let path_or_uri = file.to_string_lossy().to_string();

    let name = file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Invalid file name")?
        .to_string();

    Ok(Some(PickedEntity { path_or_uri, name }))
}

#[tauri::command]
#[cfg(target_os = "android")]
pub async fn pick_folder(app: tauri::AppHandle) -> Result<Option<PickedEntity>, String> {
    use tauri_plugin_android_fs::AndroidFsExt;
    let api = app.android_fs_async();

    let uri = api
        .file_picker()
        .pick_dir(None, false)
        .await
        .map_err(|e| format!("Dir picker error: {}", e))?;

    let Some(uri) = uri else {
        return Ok(None);
    };

    let name = api
        .get_name(&uri)
        .await
        .map_err(|e| format!("Failed to get folder name: {}", e))?;

    let path_or_uri = uri
        .to_json_string()
        .map_err(|e| format!("Failed to serialize URI: {}", e))?;

    Ok(Some(PickedEntity { path_or_uri, name }))
}

#[tauri::command]
#[cfg(not(target_os = "android"))]
pub async fn pick_folder(app: tauri::AppHandle) -> Result<Option<PickedEntity>, String> {
    use tauri_plugin_dialog::DialogExt;
    let Some(tauri_plugin_dialog::FilePath::Path(file)) =
        app.dialog().file().blocking_pick_folder()
    else {
        return Ok(None);
    };
    let path_or_uri = file.to_string_lossy().to_string();

    let name = file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Invalid folder name")?
        .to_string();

    Ok(Some(PickedEntity { path_or_uri, name }))
}
