use crate::NetworkStream;
use ring::{aead, hkdf, hmac};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Copy)]
pub enum Role {
    Receiver,
    Sender,
}

const SHARED_SECRET_SIZE: usize = 32;
const KEY_SIZE: usize = 32;

pub struct Session<S: NetworkStream> {
    stream: S,
    role: Role,
}

impl<S: NetworkStream> Session<S> {
    pub fn new(stream: S, role: Role) -> Self {
        Self { stream, role }
    }

    async fn exchange_version(&mut self, version: u64) -> anyhow::Result<()> {
        self.stream.write_u64(version).await?;
        let peer_version = self.stream.read_u64().await?;

        if peer_version != version {
            println!(
                "Warning: Version mismatch (local: {}, peer: {})",
                version, peer_version
            );
        }

        Ok(())
    }

    async fn exchange_mode(&mut self) -> anyhow::Result<()> {
        let my_mode = self.role as u64;
        self.stream.write_u64(my_mode).await?;
        let peer_mode = self.stream.read_u64().await?;

        if peer_mode == my_mode {
            anyhow::bail!("Mode mismatch: both sides in same mode");
        }

        Ok(())
    }

    async fn negotiate_key(&mut self, password: &str) -> anyhow::Result<[u8; SHARED_SECRET_SIZE]> {
        const SPAKE2_MSG_SIZE: usize = 33;

        let (state, outbound_msg) = match self.role {
            Role::Sender => Spake2::<Ed25519Group>::start_a(
                &Password::new(password),
                &Identity::new(b"sender"),
                &Identity::new(b"receiver"),
            ),
            Role::Receiver => Spake2::<Ed25519Group>::start_b(
                &Password::new(password),
                &Identity::new(b"sender"),
                &Identity::new(b"receiver"),
            ),
        };

        self.stream.write_all(&outbound_msg).await?;
        self.stream.flush().await?;

        let mut inbound_msg = vec![0u8; SPAKE2_MSG_SIZE];
        self.stream.read_exact(&mut inbound_msg).await?;

        state
            .finish(&inbound_msg)
            .map_err(|_| anyhow::anyhow!("PAKE failed: incorrect password or protocol error"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid shared secret length"))
    }

    fn derive_keys(
        &self,
        shared_secret: &[u8; SHARED_SECRET_SIZE],
    ) -> anyhow::Result<([u8; KEY_SIZE], hmac::Key)> {
        struct MyKeyType(usize);
        impl hkdf::KeyType for MyKeyType {
            fn len(&self) -> usize {
                self.0
            }
        }

        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"flying-v5");
        let prk = salt.extract(shared_secret);

        let aead_info: &[&[u8]] = &[b"aead-key"];
        let mut aead_key = [0u8; KEY_SIZE];
        prk.expand(aead_info, MyKeyType(KEY_SIZE))
            .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?
            .fill(&mut aead_key)
            .map_err(|_| anyhow::anyhow!("HKDF key derivation failed"))?;

        let hmac_info: &[&[u8]] = &[b"hmac-key"];
        let mut hmac_key_bytes = [0u8; KEY_SIZE];
        prk.expand(hmac_info, MyKeyType(KEY_SIZE))
            .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?
            .fill(&mut hmac_key_bytes)
            .map_err(|_| anyhow::anyhow!("HKDF key derivation failed"))?;

        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key_bytes);

        Ok((aead_key, hmac_key))
    }

    async fn confirm_key(&mut self, hmac_key: &hmac::Key) -> anyhow::Result<()> {
        const HMAC_TAG_SIZE: usize = 32;

        let (our_role, peer_role): (&[u8], &[u8]) = match self.role {
            Role::Sender => (b"sender", b"receiver"),
            Role::Receiver => (b"receiver", b"sender"),
        };

        let our_tag = hmac::sign(hmac_key, our_role);
        self.stream.write_all(our_tag.as_ref()).await?;
        self.stream.flush().await?;

        let mut peer_tag = vec![0u8; HMAC_TAG_SIZE];
        self.stream.read_exact(&mut peer_tag).await?;

        hmac::verify(hmac_key, peer_role, &peer_tag)
            .map_err(|_| anyhow::anyhow!("Key confirmation failed: password mismatch"))
    }

    async fn exchange_secret(&mut self, password: &str) -> anyhow::Result<aead::LessSafeKey> {
        let shared_secret = self.negotiate_key(password).await?;

        let (aead_key, hmac_key) = self.derive_keys(&shared_secret)?;

        self.confirm_key(&hmac_key).await?;

        Ok(aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &aead_key)
                .map_err(|_| anyhow::anyhow!("Failed to create encryption key"))?,
        ))
    }

    pub async fn handshake(
        &mut self,
        version: u64,
        password: &str,
    ) -> anyhow::Result<aead::LessSafeKey> {
        self.exchange_version(version).await?;
        self.exchange_mode().await?;
        self.exchange_secret(password).await
    }

    pub async fn finish(&mut self) -> anyhow::Result<()> {
        match self.role {
            Role::Sender => {
                let _ = self.read_u8().await?;
            }
            Role::Receiver => {
                self.write_u8(1).await?;
                self.flush().await?;
            }
        }
        self.shutdown().await?;
        Ok(())
    }
}

impl<S: NetworkStream> AsyncRead for Session<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl<S: NetworkStream> AsyncWrite for Session<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, tokio::io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), tokio::io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), tokio::io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}
