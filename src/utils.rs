use ring::digest;
use socket2::{Domain, Protocol, Socket, Type};
use std::io::{self};
use std::net::SocketAddr;

use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt},
    net::TcpListener,
};

pub async fn hash_file(file: &mut File) -> io::Result<digest::Digest> {
    const CHUNK_SIZE: usize = 1_048_576;
    let mut context = digest::Context::new(&digest::SHA256);
    let mut buffer = vec![0u8; CHUNK_SIZE];

    loop {
        let bytes_read = file.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }
        context.update(&buffer[..bytes_read]);
    }

    file.seek(std::io::SeekFrom::Start(0)).await?;
    Ok(context.finish())
}

pub fn create_listener(port: u16) -> anyhow::Result<TcpListener> {
    let addr = format!("[::]:{}", port).parse::<SocketAddr>()?;

    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_only_v6(false)?;
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;

    let std_listener: std::net::TcpListener = socket.into();
    std_listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(std_listener)?;

    Ok(listener)
}
