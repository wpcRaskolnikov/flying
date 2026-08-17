use crate::NetworkStream;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Copy, PartialEq)]
pub enum Type {
    File,
    Folder,
}

pub struct Metadata {
    pub relative_path: String,
    pub transfer_type: Type,
    pub size: u64,
}

impl Metadata {
    pub async fn from_path(path: &Path, base_path: Option<&Path>) -> anyhow::Result<Self> {
        let fs_meta = tokio::fs::metadata(path).await?;
        let relative_path = match base_path {
            Some(base) => path
                .strip_prefix(base)
                .map_err(|_| anyhow::anyhow!("Path is not under the given base"))?
                .to_string_lossy()
                .to_string(),
            None => path
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("Invalid file/folder name"))?
                .to_string_lossy()
                .to_string(),
        };
        let transfer_type = if fs_meta.is_dir() {
            Type::Folder
        } else {
            Type::File
        };
        let size = fs_meta.len();
        Ok(Self {
            relative_path,
            transfer_type,
            size,
        })
    }

    pub async fn write(&self, stream: &mut dyn NetworkStream) -> anyhow::Result<()> {
        stream.write_u64(self.relative_path.len() as u64).await?;
        stream.write_all(self.relative_path.as_bytes()).await?;
        stream.write_u64(self.transfer_type as u64).await?;
        stream.write_u64(self.size).await?;
        stream.flush().await?;
        Ok(())
    }

    pub async fn read(stream: &mut dyn NetworkStream) -> anyhow::Result<Self> {
        let path_len = stream.read_u64().await? as usize;
        let mut path_bytes = vec![0u8; path_len];
        stream.read_exact(&mut path_bytes).await?;
        let relative_path = String::from_utf8(path_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in path: {}", e))?;
        let transfer_type = match stream.read_u64().await? {
            0 => Type::File,
            1 => Type::Folder,
            other => anyhow::bail!("Unknown transfer type: {other}"),
        };
        let size = stream.read_u64().await?;
        Ok(Self {
            relative_path,
            transfer_type,
            size,
        })
    }
}
