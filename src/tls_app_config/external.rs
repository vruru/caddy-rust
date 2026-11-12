//! Bounded transport for externally owned certificate material. No issuance,
//! certificate storage write, permission decision or global certificate cache.
use crate::{cert_automation::AutomationResources, http_runtime::CertificateHello};
use anyhow::{Result, anyhow, ensure};
use futures_util::StreamExt;
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;
#[derive(Clone)]
pub(super) enum Manager {
    Http(Arc<str>),
    Tailscale,
}
pub(super) const BODY_LIMIT: usize = 2 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(60);
impl Manager {
    pub(super) async fn fetch(
        &self,
        hello: &CertificateHello,
        resources: &Arc<AutomationResources>,
        cancel: CancellationToken,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let caller = cancel;
        let cancel = caller.child_token();
        let operation = async {
            match self {
                Self::Http(endpoint) => {
                    let signatures = hex_list(&hello.signatures);
                    let ciphers = hex_list(&hello.ciphers);
                    let ip = hello.local_ip.to_string();
                    let (request, target) = super::permission::external_request(
                        endpoint,
                        &[
                            ("server_name", &hello.server_name),
                            ("signature_schemes", &signatures),
                            ("cipher_suites", &ciphers),
                            ("local_ip", &ip),
                        ],
                    )?;
                    let (status, body) =
                        fetch_http(request, Some(target), resources, &cancel).await?;
                    if status == 204 {
                        return Ok(None);
                    }
                    ensure!(status == 200, "external certificate HTTP status {status}");
                    // A 200 is a certificate claim, including an empty (invalid) body.
                    Ok(Some(body))
                }
                Self::Tailscale => {
                    if !hello.server_name.to_ascii_lowercase().ends_with(".ts.net") {
                        return Ok(None);
                    }
                    let route = crate::cert_cpu::run(
                        resources.cpu_slots(),
                        cancel.clone(),
                        tailscale_route,
                    )
                    .await?;
                    let permit = resources
                        .admit_permission("tailscale-local-api".into(), &cancel)
                        .await?;
                    let client = route.client()?;
                    let status =
                        local_get(&client, &route, "/localapi/v0/status", resources, &cancel).await;
                    if let Ok((200, body)) = status {
                        if let Ok(status) = serde_json::from_slice::<TailStatus>(&body) {
                            if !status
                                .cert_domains
                                .iter()
                                .any(|pattern| match_wildcard(&hello.server_name, pattern))
                            {
                                return Ok(None);
                            }
                        }
                    }
                    // A status error does not mean this daemon cannot obtain the
                    // certificate. The original manager still tries CertPair.
                    let path = format!("/localapi/v0/cert/{}?type=pair", hello.server_name);
                    let (status, body) =
                        local_get(&client, &route, &path, resources, &cancel).await?;
                    drop(permit);
                    ensure!(status == 200, "Tailscale certificate HTTP status {status}");
                    ensure!(!body.is_empty(), "empty Tailscale certificate pair");
                    Ok(Some(body))
                }
            }
        };
        tokio::pin!(operation);
        tokio::select! {biased;
            _=caller.cancelled()=>{cancel.cancel();let _=operation.await;Err(anyhow!("external certificate request cancelled"))},
            _=tokio::time::sleep(TIMEOUT)=>{cancel.cancel();let _=operation.await;Err(anyhow!("external certificate request timed out"))},
            result=&mut operation=>result,
        }
    }
}
fn hex_list(values: &[u16]) -> String {
    values
        .iter()
        .map(|v| format!("{v:x}"))
        .collect::<Vec<_>>()
        .join(",")
}
#[derive(serde::Deserialize)]
struct TailStatus {
    #[serde(rename = "CertDomains", default)]
    cert_domains: Vec<String>,
}
fn match_wildcard(name: &str, pattern: &str) -> bool {
    let name = name.to_lowercase();
    let pattern = pattern.to_lowercase();
    if name == pattern {
        return true;
    }
    if !pattern.contains('*') {
        return false;
    }
    let mut labels = name.split('.').collect::<Vec<_>>();
    for i in 0..labels.len() {
        if labels[i].is_empty() {
            continue;
        }
        labels[i] = "*";
        if labels.join(".") == pattern {
            return true;
        }
    }
    false
}
async fn read_body(
    response: reqwest::Response,
    resources: &Arc<AutomationResources>,
    cancel: &CancellationToken,
) -> Result<Zeroizing<Vec<u8>>> {
    let gzip = response
        .headers()
        .get(http::header::CONTENT_ENCODING)
        .is_some_and(|v| v == "gzip");
    ensure!(
        response
            .content_length()
            .is_none_or(|n| n <= BODY_LIMIT as u64),
        "external certificate body limit exceeded"
    );
    let mut stream = response.bytes_stream();
    let mut body = Zeroizing::new(Vec::new());
    loop {
        let chunk = tokio::select! {biased;
            _=cancel.cancelled()=>anyhow::bail!("external certificate body cancelled"),
            chunk=stream.next()=>chunk,
        };
        let Some(chunk) = chunk else {
            break;
        };
        let chunk = chunk.map_err(|_| anyhow!("external certificate body unavailable"))?;
        ensure!(
            chunk.len() <= BODY_LIMIT - body.len(),
            "external certificate body limit exceeded"
        );
        body.extend_from_slice(&chunk);
    }
    if gzip {
        crate::cert_cpu::run(resources.cpu_slots(), cancel.clone(), move || {
            use std::io::Read;
            let decoder = flate2::read::MultiGzDecoder::new(body.as_slice());
            let mut output = Zeroizing::new(Vec::new());
            decoder
                .take(BODY_LIMIT as u64 + 1)
                .read_to_end(&mut output)
                .map_err(|_| anyhow!("invalid external certificate gzip body"))?;
            ensure!(
                output.len() <= BODY_LIMIT,
                "external certificate decoded body limit exceeded"
            );
            Ok(output)
        })
        .await
    } else {
        Ok(body)
    }
}
async fn fetch_http(
    mut request: reqwest::Request,
    mut target: Option<http::uri::PathAndQuery>,
    resources: &Arc<AutomationResources>,
    cancel: &CancellationToken,
) -> Result<(u16, Zeroizing<Vec<u8>>)> {
    for redirects in 0..=10 {
        let url = request.url().clone();
        let _permit = resources
            .admit_permission(url.origin().ascii_serialization(), cancel)
            .await?;
        let (tls, proxy) = crate::cert_cpu::run(resources.cpu_slots(), cancel.clone(), move || {
            let proxy = super::permission::external_proxy(&url)?;
            let mut roots = rustls::RootCertStore::empty();
            let _ = roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
            let mut tls = rustls::ClientConfig::builder_with_provider(crate::crypto::provider())
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth();
            tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            Ok((tls, proxy))
        })
        .await?;
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .use_preconfigured_tls(tls)
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none());
        if let Some(proxy) = proxy {
            builder = builder.proxy(
                reqwest::Proxy::all(proxy)
                    .map_err(|_| anyhow!("invalid external certificate proxy"))?,
            );
        }
        let client = builder
            .build()
            .map_err(|_| anyhow!("external certificate HTTP transport unavailable"))?;
        request.headers_mut().insert(
            http::header::USER_AGENT,
            http::HeaderValue::from_static("Go-http-client/1.1"),
        );
        request.headers_mut().insert(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip"),
        );
        let previous_url = if let Some(raw) = target.as_ref() {
            url::Url::parse(&format!(
                "{}{}",
                request.url().origin().ascii_serialization(),
                raw
            ))
            .map_err(|_| anyhow!("invalid external certificate request target"))?
        } else {
            request.url().clone()
        };
        let previous_auth = request.headers().get(http::header::AUTHORIZATION).cloned();
        let sending = async {
            if let Some(target) = target.take() {
                client.execute_with_raw_target(request, target).await
            } else {
                client.execute(request).await
            }
        };
        let response = tokio::select! {biased;
            _=cancel.cancelled()=>anyhow::bail!("external certificate HTTP request cancelled"),
            result=sending=>result.map_err(|_|anyhow!("external certificate HTTP request failed"))?,
        };
        let status = response.status().as_u16();
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            if let Some(location) = response
                .headers()
                .get(http::header::LOCATION)
                .filter(|v| !v.is_empty())
            {
                ensure!(
                    redirects < 10,
                    "external certificate redirect limit exceeded"
                );
                let location = location
                    .to_str()
                    .map_err(|_| anyhow!("invalid external certificate redirect"))?;
                let next = previous_url
                    .join(location)
                    .map_err(|_| anyhow!("invalid external certificate redirect"))?;
                ensure!(
                    matches!(next.scheme(), "http" | "https"),
                    "invalid external certificate redirect scheme"
                );
                let (mut next_request, raw) =
                    super::permission::external_request(next.as_str(), &[])?;
                // Go forwards Authorization only to the same host or a child
                // domain; never send endpoint credentials to an unrelated host.
                if let (Some(auth), Some(old), Some(new)) =
                    (previous_auth, previous_url.host_str(), next.host_str())
                {
                    if new == old || new.ends_with(&format!(".{old}")) {
                        next_request
                            .headers_mut()
                            .insert(http::header::AUTHORIZATION, auth);
                    }
                }
                if previous_url.scheme() != "https" || next.scheme() != "http" {
                    next_request.headers_mut().insert(
                        http::header::REFERER,
                        http::HeaderValue::from_str(previous_url.as_str())
                            .map_err(|_| anyhow!("invalid external certificate redirect source"))?,
                    );
                }
                drop(response);
                request = next_request;
                target = Some(raw);
                continue;
            }
        }
        if status != 200 {
            return Ok((status, Zeroizing::new(Vec::new())));
        }
        let body = read_body(response, resources, cancel).await?;
        return Ok((status, body));
    }
    unreachable!()
}
struct TailRoute {
    socket: Option<std::path::PathBuf>,
    port: u16,
    token: Option<Zeroizing<String>>,
}
impl TailRoute {
    fn client(&self) -> Result<reqwest::Client> {
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5));
        if let Some(socket) = &self.socket {
            builder = builder.unix_socket(socket.clone());
        }
        builder
            .build()
            .map_err(|_| anyhow!("Tailscale local transport unavailable"))
    }
}
async fn local_get(
    client: &reqwest::Client,
    route: &TailRoute,
    path: &str,
    resources: &Arc<AutomationResources>,
    cancel: &CancellationToken,
) -> Result<(u16, Zeroizing<Vec<u8>>)> {
    let url = if route.socket.is_some() {
        format!("http://local-tailscaled.sock{path}")
    } else {
        format!("http://127.0.0.1:{}{path}", route.port)
    };
    let mut request = client
        .get(url)
        .header(http::header::HOST, "local-tailscaled.sock")
        .header(http::header::USER_AGENT, "Go-http-client/1.1")
        .header(http::header::ACCEPT_ENCODING, "gzip");
    if let Some(token) = &route.token {
        request = request.basic_auth("", Some(token.as_str()));
    }
    let response = tokio::select! {biased;
        _=cancel.cancelled()=>anyhow::bail!("Tailscale local API cancelled"),
        result=request.send()=>result.map_err(|_|anyhow!("Tailscale local API unavailable"))?,
    };
    let status = response.status().as_u16();
    let body = read_body(response, resources, cancel).await?;
    Ok((status, body))
}
fn tailscale_route() -> Result<TailRoute> {
    // Explicit socket routing also makes isolated LocalAPI fixtures possible;
    // it must never silently switch to an unrelated system daemon.
    if let Some(path) = std::env::var_os("TS_SOCKET").filter(|s| !s.is_empty()) {
        return Ok(TailRoute {
            socket: Some(path.into()),
            port: 0,
            token: None,
        });
    }
    #[cfg(target_os = "macos")]
    if let Some((port, token)) = macos_token()? {
        return Ok(TailRoute {
            socket: None,
            port,
            token: Some(token),
        });
    }
    let socket = if cfg!(target_os = "macos") {
        std::path::PathBuf::from("/var/run/tailscaled.socket")
    } else if std::path::Path::new("/gokrazy").is_dir() {
        "/perm/tailscaled/tailscaled.sock".into()
    } else if std::path::Path::new("/var/run").is_dir() {
        "/var/run/tailscale/tailscaled.sock".into()
    } else {
        "tailscaled.sock".into()
    };
    Ok(TailRoute {
        socket: Some(socket),
        port: 0,
        token: None,
    })
}
#[cfg(target_os = "macos")]
fn macos_token() -> Result<Option<(u16, Zeroizing<String>)>> {
    // Discovery is only entered by an explicitly configured Tailscale manager.
    if let Some(dir) = std::env::var_os("TS_MACOS_CLI_SHARED_DIR").filter(|s| !s.is_empty()) {
        if std::env::var("HOME")
            .ok()
            .is_some_and(|home| home.contains("/Containers/io.tailscale.ipn.macsys/"))
        {
            if let Some(proof) = macsys_token() {
                return Ok(Some(proof));
            }
        }
        let entries = std::fs::read_dir(dir)
            .map_err(|_| anyhow!("Tailscale shared API directory unavailable"))?;
        let mut entries = entries
            .take(4097)
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|_| anyhow!("Tailscale shared API directory unavailable"))?;
        ensure!(
            entries.len() <= 4096,
            "Tailscale shared API directory limit exceeded"
        );
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            if let Some(value) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.strip_prefix("sameuserproof-"))
            {
                if let Some((port, token)) = value.split_once('-') {
                    if let Ok(port) = port.parse::<u16>() {
                        if port != 0 && !token.is_empty() {
                            return Ok(Some((port, Zeroizing::new(token.into()))));
                        }
                    }
                }
            }
        }
        return Err(anyhow!("Tailscale shared API token unavailable"));
    }
    // The App Store extension exposes the proof name through same-user open
    // files. Match the pinned tscert discovery; cap subprocess time/output and
    // keep the authentication proof out of logs and process arguments.
    use std::io::Read as _;
    if let Ok(mut child) = std::process::Command::new("/usr/sbin/lsof")
        .args([
            "-n",
            "-a",
            &format!("-u{}", rustix::process::getuid().as_raw()),
            "-c",
            "IPNExtension",
            "-F",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let success = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status.success(),
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break false;
                }
                _ if std::time::Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break false;
                }
                _ => std::thread::sleep(Duration::from_millis(5)),
            }
        };
        if success {
            if let Some(stdout) = child.stdout.take() {
                let mut bytes = Zeroizing::new(Vec::new());
                if stdout.take(65537).read_to_end(&mut bytes).is_ok() && bytes.len() <= 65536 {
                    let output = String::from_utf8_lossy(&bytes);
                    for line in output.lines() {
                        if let Some((_, value)) =
                            line.split_once(".tailscale.ipn.macos/sameuserproof-")
                        {
                            if let Some((port, token)) = value.split_once('-') {
                                if let Ok(port) = port.parse::<u16>() {
                                    if port != 0 && !token.is_empty() {
                                        return Ok(Some((port, Zeroizing::new(token.into()))));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(macsys_token())
}

#[cfg(target_os = "macos")]
fn macsys_token() -> Option<(u16, Zeroizing<String>)> {
    // The system-extension install publishes a port symlink plus a secret
    // proof file. Bound the secret and never include it in errors or Debug.
    if let Ok(link) = std::fs::read_link("/Library/Tailscale/ipnport") {
        if let Some(port) = link
            .to_str()
            .and_then(|s| s.parse::<u16>().ok())
            .filter(|p| *p != 0)
        {
            use std::io::Read;
            if let Ok(file) =
                std::fs::File::open(format!("/Library/Tailscale/sameuserproof-{port}"))
            {
                let mut token = Zeroizing::new(String::new());
                if file.take(4097).read_to_string(&mut token).is_ok()
                    && token.len() <= 4096
                    && !token.trim().is_empty()
                {
                    return Some((port, Zeroizing::new(token.trim().into())));
                }
            }
        }
    }
    None
}
pub(super) fn split_bundle(bundle: Zeroizing<Vec<u8>>) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    // The external HTTP module uses pem.Decode, unlike strict persisted
    // material loaders: surrounding prose is ignored and the first private
    // key wins. Keep those Go-valid bundles without weakening storage parsing.
    let decoded = pem::parse_many(bundle.as_slice())
        .map_err(|_| anyhow!("invalid external certificate PEM"))?;
    let mut blocks = decoded
        .into_iter()
        .map(|block| {
            (
                block.tag().to_owned(),
                Zeroizing::new(block.into_contents()),
            )
        })
        .collect::<Vec<_>>();
    ensure!(
        blocks.len() <= 64,
        "external certificate PEM block limit exceeded"
    );
    let mut certificate = Vec::new();
    let mut key = None;
    let mut count = 0;
    use zeroize::Zeroize;
    let result = (|| {
        let mut index = 0;
        while index < blocks.len() {
            let (label, der) = &blocks[index];
            if label == "CERTIFICATE" {
                count += 1;
                ensure!(count <= 32, "external certificate chain limit exceeded");
                certificate.extend_from_slice(&encode_pem(label, der));
            } else if label == "EC PARAMETERS" {
                if key.is_none() {
                    index += 1;
                    let (label, der) = blocks.get(index).ok_or_else(|| {
                        anyhow!("external EC parameters require an immediately following key")
                    })?;
                    ensure!(
                        label == "EC PRIVATE KEY",
                        "external EC parameters require an immediately following key"
                    );
                    key = Some(normalize_private_key(der)?);
                }
            } else if label == "PRIVATE KEY" || label.ends_with(" PRIVATE KEY") {
                if key.is_none() {
                    key = Some(normalize_private_key(der)?);
                }
            } else {
                anyhow::bail!("unexpected external certificate PEM block");
            }
            index += 1;
        }
        ensure!(count > 0, "external certificate chain missing");
        Ok((
            certificate,
            key.ok_or_else(|| anyhow!("external certificate private key missing"))?,
        ))
    })();
    for (_, der) in &mut blocks {
        der.zeroize();
    }
    result
}

fn encode_pem(label: &str, der: &[u8]) -> Zeroizing<Vec<u8>> {
    use base64::Engine;
    let encoded = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(der));
    let mut output = Zeroizing::new(Vec::with_capacity(encoded.len() + 128));
    output.extend_from_slice(format!("-----BEGIN {label}-----\n").as_bytes());
    for line in encoded.as_bytes().chunks(64) {
        output.extend_from_slice(line);
        output.push(b'\n');
    }
    output.extend_from_slice(format!("-----END {label}-----\n").as_bytes());
    output
}

fn normalize_private_key(der: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use rustls::pki_types::PrivateKeyDer;
    ensure!(
        der.len() <= 128 * 1024,
        "external private key limit exceeded"
    );
    let private = PrivateKeyDer::try_from(der.to_vec())
        .map_err(|_| anyhow!("invalid external private key DER"))?;
    let label = match &private {
        PrivateKeyDer::Pkcs1(_) => "RSA PRIVATE KEY",
        PrivateKeyDer::Pkcs8(_) => "PRIVATE KEY",
        PrivateKeyDer::Sec1(_) => "EC PRIVATE KEY",
        _ => anyhow::bail!("unsupported external private key DER"),
    };
    Ok(encode_pem(label, private.secret_der()))
}
