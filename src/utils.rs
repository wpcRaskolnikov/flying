use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

pub fn get_key_from_password(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.finalize().into()
}

pub fn generate_password() -> String {
    petname::petname(3, "-").unwrap_or_else(|| "flying-transfer-secret".to_string())
}

pub fn hash_file(filename: &Path) -> io::Result<Vec<u8>> {
    let mut file = fs::File::open(filename)?;
    hash_file_handle(&mut file)
}

pub fn hash_file_handle(file: &fs::File) -> io::Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};

    // Create a mutable reference we can work with
    let mut file_ref = file;

    // Seek to beginning in case the file was already read
    file_ref.seek(SeekFrom::Start(0))?;

    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1_000_000]; // 1MB buffer

    loop {
        let bytes_read = file_ref.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    // Seek back to beginning for subsequent reads
    file_ref.seek(SeekFrom::Start(0))?;

    Ok(hasher.finalize().to_vec())
}

pub fn make_size_readable(size: u64) -> String {
    let size = size as f64;
    const KB: f64 = 1000.0;
    const MB: f64 = KB * 1000.0;
    const GB: f64 = MB * 1000.0;
    if size < KB {
        format!("{} bytes", size)
    } else if size < MB {
        format!("{:.2}KB", size / KB)
    } else if size < GB {
        format!("{:.2}MB", size / MB)
    } else {
        format!("{:.2}GB", size / GB)
    }
}

pub fn format_time(seconds: f64) -> String {
    if seconds > 60.0 {
        let minutes = seconds as u64 / 60;
        let seconds = seconds % 60.0;
        format!("{} minutes {:.2} seconds", minutes, seconds)
    } else {
        format!("{:.2} seconds", seconds)
    }
}

pub fn make_parent_directories(full_path: &Path) -> io::Result<()> {
    if let Some(dirs) = full_path.parent() {
        fs::create_dir_all(dirs)?;
    }
    Ok(())
}

pub struct ProgressTracker {
    last_percent: u8,
}

impl ProgressTracker {
    pub fn new() -> Self {
        Self { last_percent: 0 }
    }

    pub fn update(&mut self, bytes_processed: u64, total_bytes: u64) -> io::Result<()> {
        let percent_done = ((bytes_processed as f64 / total_bytes as f64) * 100.0) as u8;
        if percent_done > self.last_percent {
            print!("\rProgress: {}%", percent_done);
            io::stdout().flush()?;
            self.last_percent = percent_done;
        }
        Ok(())
    }

    pub fn finish(&self) -> io::Result<()> {
        println!("\rProgress: 100%");
        Ok(())
    }
}

pub fn collect_files_recursive(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_files_recursive_helper(dir, &mut files)?;
    Ok(files)
}

fn collect_files_recursive_helper(dir: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    if dir.is_file() {
        files.push(dir.to_path_buf());
        return Ok(());
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files_recursive_helper(&path, files)?;
        } else {
            files.push(path);
        }
    }
    Ok(())
}
