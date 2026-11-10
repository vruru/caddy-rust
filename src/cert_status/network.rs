//! Bounded background-only HTTP transport for OCSP and issuer AIA retrieval.
use anyhow::{Result, anyhow, ensure};
use reqwest::{Client, Method, StatusCode, Url, header};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub struct OcspTransport {
    client: Client,
    max_body: usize,
    timeout: Duration,
}

impl OcspTransport {
    pub fn new(
        timeout: Duration,
        max_body: usize,
        proxy: Option<&str>,
        extra_ca_pem: &[Vec<u8>],
    ) -> Result<Self> {
        ensure!(
            (1..=4 * 1024 * 1024).contains(&max_body),
            "OCSP body limit out of range"
        );
        ensure!(
            (Duration::from_secs(1)..=Duration::from_secs(120)).contains(&timeout),
            "OCSP timeout out of range"
        );
        let mut builder = Client::builder()
            .connect_timeout(timeout.min(Duration::from_secs(10)))
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none());
        if let Some(proxy) = proxy {
            builder = builder
                .proxy(reqwest::Proxy::all(proxy).map_err(|_| anyhow!("invalid OCSP proxy"))?);
        }
        for ca in extra_ca_pem {
            builder = builder.add_root_certificate(reqwest::Certificate::from_pem(ca)?);
        }
        Ok(Self {
            client: builder.build()?,
            max_body,
            timeout,
        })
    }

    pub async fn get(&self, url: &str, cancel: &CancellationToken) -> Result<Vec<u8>> {
        self.fetch(Method::GET, url, &[], cancel).await
    }

    pub async fn post(
        &self,
        url: &str,
        body: &[u8],
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>> {
        ensure!(body.len() <= self.max_body, "OCSP request exceeds limit");
        self.fetch(Method::POST, url, body, cancel).await
    }

    async fn fetch(
        &self,
        method: Method,
        url: &str,
        body: &[u8],
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>> {
        let operation = async {
            let mut current = checked_url(url)?;
            let mut method = method;
            let ocsp_request = method == Method::POST;
            for redirects in 0..=10 {
                let mut request = self.client.request(method.clone(), current.clone());
                if method == Method::POST {
                    request = request
                        .header(header::ACCEPT, "application/ocsp-response")
                        .header(header::CONTENT_TYPE, "application/ocsp-request")
                        .body(body.to_vec());
                } else {
                    request = request.header(
                        header::ACCEPT,
                        if ocsp_request {
                            "application/ocsp-response"
                        } else {
                            "application/pkix-cert"
                        },
                    );
                }
                let mut response = request
                    .send()
                    .await
                    .map_err(|_| anyhow!("OCSP HTTP request failed"))?;
                let status = response.status();
                if matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308) {
                    ensure!(redirects < 10, "OCSP redirect limit exceeded");
                    if method == Method::POST && matches!(status.as_u16(), 301..=303) {
                        method = Method::GET;
                    }
                    let location = response
                        .headers()
                        .get(header::LOCATION)
                        .and_then(|v| v.to_str().ok())
                        .ok_or_else(|| anyhow!("OCSP redirect has no valid location"))?;
                    let joined = current
                        .join(location)
                        .map_err(|_| anyhow!("invalid OCSP redirect URL"))?;
                    let next = checked_url(joined.as_str())?;
                    current = next;
                    continue;
                }
                ensure!(
                    status == StatusCode::OK,
                    "OCSP HTTP status {}",
                    status.as_u16()
                );
                if let Some(length) = response.content_length() {
                    ensure!(
                        length <= self.max_body as u64,
                        "OCSP response exceeds limit"
                    );
                }
                let mut output = Vec::new();
                while let Some(chunk) = response
                    .chunk()
                    .await
                    .map_err(|_| anyhow!("OCSP response body failed"))?
                {
                    ensure!(
                        chunk.len() <= self.max_body.saturating_sub(output.len()),
                        "OCSP response exceeds limit"
                    );
                    output.extend_from_slice(&chunk);
                }
                return Ok(output);
            }
            Err(anyhow!("OCSP redirect limit exceeded"))
        };
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(anyhow!("OCSP request cancelled")),
            result = tokio::time::timeout(self.timeout, operation) => result.map_err(|_| anyhow!("OCSP request timed out"))?,
        }
    }
}

fn checked_url(value: &str) -> Result<Url> {
    let url = Url::parse(value).map_err(|_| anyhow!("invalid OCSP URL"))?;
    ensure!(
        matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
        "unsupported OCSP URL"
    );
    ensure!(
        url.username().is_empty() && url.password().is_none() && url.fragment().is_none(),
        "OCSP URL contains credentials or fragment"
    );
    Ok(url)
}
