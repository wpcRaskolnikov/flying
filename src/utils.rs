use rand::Rng;
use sha2::{Digest, Sha256};
use std::{fs, io, path::Path};

pub fn get_key_from_password(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.finalize().into()
}

pub fn generate_password() -> String {
    let mut rng = rand::rng();
    let chars: Vec<char> = "23456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"
        .chars()
        .collect();
    const PASSWORD_LENGTH: usize = 8;
    (0..PASSWORD_LENGTH)
        .map(|_| chars[rng.random_range(0..chars.len())])
        .collect()
}

pub fn hash_file(filename: &Path) -> io::Result<Vec<u8>> {
    let mut file = fs::File::open(filename)?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
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
