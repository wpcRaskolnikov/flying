#[tauri::command]
#[cfg(target_os = "android")]
pub async fn pick_file(app: tauri::AppHandle) -> Result<Option<(String, String)>, String> {
    use tauri_plugin_android_fs::AndroidFsExt;
    let api = app.android_fs_async();

    // Pick files to read
    let uri = api
        .file_picker()
        .pick_file(
            None,     // Initial location
            &["*/*"], // Target MIME types (all files)
            false,    // If true, only files on local device
        )
        .await
        .map_err(|e| format!("File picker error: {}", e))?;

    // Check if user cancelled the file picker
    let Some(uri) = uri else {
        return Ok(None);
    };

    let file_name = api
        .get_name(&uri)
        .await
        .map_err(|e| format!("Failed to get file name: {}", e))?;

    let uri_json = uri
        .to_json_string()
        .map_err(|e| format!("Failed to serialize URI: {}", e))?;

    Ok(Some((uri_json, file_name)))
}

#[tauri::command]
#[cfg(not(target_os = "android"))]
pub async fn pick_file(app: tauri::AppHandle) -> Result<Option<(String, String)>, String> {
    use tauri_plugin_dialog::DialogExt;
    let Some(tauri_plugin_dialog::FilePath::Path(file)) = app.dialog().file().blocking_pick_file()
    else {
        return Ok(None);
    };
    let file_path = file.to_string_lossy().to_string();

    let file_name = file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Invalid file name")?
        .to_string();

    Ok(Some((file_path, file_name)))
}

#[tauri::command]
#[cfg(target_os = "android")]
pub async fn pick_folder(app: tauri::AppHandle) -> Result<Option<(String, String)>, String> {
    use tauri_plugin_android_fs::AndroidFsExt;
    let api = app.android_fs_async();

    let uri = api
        .file_picker()
        .pick_dir(None, false)
        .await
        .map_err(|e| format!("dir picker error: {}", e))?;

    // Check if user cancelled the folder picker
    let Some(uri) = uri else {
        return Ok(None);
    };

    let file_name = api
        .get_name(&uri)
        .await
        .map_err(|e| format!("Failed to get file name: {}", e))?;

    let uri_json = uri
        .to_json_string()
        .map_err(|e| format!("Failed to serialize URI: {}", e))?;

    Ok(Some((uri_json, file_name)))
}

#[tauri::command]
#[cfg(not(target_os = "android"))]
pub async fn pick_folder(app: tauri::AppHandle) -> Result<Option<(String, String)>, String> {
    use tauri_plugin_dialog::DialogExt;
    let Some(tauri_plugin_dialog::FilePath::Path(file)) =
        app.dialog().file().blocking_pick_folder()
    else {
        return Ok(None);
    };
    let file_path = file.to_string_lossy().to_string();

    let file_name = file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Invalid file name")?
        .to_string();

    Ok(Some((file_path, file_name)))
}
