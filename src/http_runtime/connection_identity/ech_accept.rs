//! The optional ECH preflight owns the Acceptor while HPKE runs on the existing
//! bounded CPU lane. The application chooses policy only after it exposes inner SNI.
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Keys = Arc<[Arc<rustls::server::EchServerKey>]>;

#[derive(Debug)]
pub(in crate::http_runtime) struct FixedKeys(pub(in crate::http_runtime) Keys);
impl rustls::server::EchConfigProvider for FixedKeys {
    fn keys(&self) -> Keys { self.0.clone() }
}

pub(in crate::http_runtime) fn snapshot(server: &ActiveServer)
    -> Option<Arc<dyn rustls::server::EchConfigProvider>>
{
    let keys = server.resolver.as_ref()?.provider.as_ref()?.ech_provider()?.keys();
    Some(Arc::new(FixedKeys(keys)))
}

pub(super) async fn accept<I>(inner: &Arc<Inner>, mut io: I, keys: Keys)
    -> Result<tokio_rustls::server::StartHandshake<I>>
where I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static {
    let mut acceptor = rustls::server::Acceptor::default();
    let mut bytes = [0u8; 8192];
    loop {
        let count = io.read(&mut bytes).await?;
        ensure!(count != 0, "EOF before ECH ClientHello");
        let input = bytes[..count].to_vec();
        let snapshot = keys.clone();
        let (next, outcome) = inner.resources.metadata.run(move || {
            let outcome = (|| {
                let mut reader = input.as_slice();
                while !reader.is_empty() {
                    let count = acceptor.read_tls(&mut reader).map_err(|error| (error, Vec::new()))?;
                    if count == 0 {
                        return Err((std::io::Error::new(std::io::ErrorKind::InvalidData,
                            "ECH preflight TLS input buffer full"), Vec::new()));
                    }
                }
                acceptor.accept_with_ech(Some(snapshot)).map_err(|(error, mut alert)| {
                    let mut bytes = Vec::new();
                    // AcceptedAlert is already queued protocol output. Preserve
                    // its bytes; socket I/O still runs asynchronously below.
                    while let Ok(count) = alert.write(&mut bytes) { if count == 0 { break; } }
                    (std::io::Error::new(std::io::ErrorKind::InvalidData, error), bytes)
                })
            })();
            (acceptor, outcome)
        }).await.map_err(|_| anyhow::anyhow!("ECH preflight CPU worker unavailable"))?;
        acceptor = next;
        match outcome {
            Ok(Some(accepted)) => return Ok(tokio_rustls::server::StartHandshake::from_parts(accepted, io)),
            Ok(None) => {},
            Err((error, alert)) => {
                let _ = io.write_all(&alert).await;
                return Err(error.into());
            }
        }
    }
}
