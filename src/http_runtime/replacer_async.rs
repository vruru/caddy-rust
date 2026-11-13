//! The same placeholder scanner with an asynchronous, demand-driven provider.
//! Each buffer reservation precedes allocation and follows the final Bytes owner.
use anyhow::{Result, ensure};
use bytes::Bytes;
use native_write_policy::{Lease, Pool};
use std::future::Future;
pub(super) trait Lookup: Sync {
    fn lookup<'a>(
        &'a self,
        name: &'a str,
    ) -> impl Future<Output = Result<Option<Bytes>>> + Send + 'a;
}
const CAP: usize = 4 << 20;
struct Output {
    bytes: Vec<u8>,
    credits: Vec<Lease>,
    limit: usize,
    _base: Lease,
}
impl AsRef<[u8]> for Output {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
impl Output {
    fn new(input: usize, pool: &Pool, limit: usize) -> Result<Self> {
        let base = pool.reserve(8192)?;
        let mut credits = Vec::with_capacity(64);
        credits.push(
            pool.reserve(
                input
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(256))
                    .ok_or_else(|| anyhow::anyhow!("replacement capacity overflow"))?,
            )?,
        );
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(input.min(limit))?;
        Ok(Self {
            bytes,
            credits,
            limit,
            _base: base,
        })
    }
    async fn append(&mut self, text: &[u8], pool: &Pool) -> Result<()> {
        let required = self
            .bytes
            .len()
            .checked_add(text.len())
            .filter(|n| *n <= self.limit)
            .ok_or_else(|| anyhow::anyhow!("replacement output exceeds limit"))?;
        if required > self.bytes.capacity() {
            let cap = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .max(required)
                .min(self.limit);
            ensure!(
                self.credits.len() < 64,
                "replacement allocation count exceeded"
            );
            let lease = pool.reserve(
                cap.checked_mul(2)
                    .and_then(|n| n.checked_add(256))
                    .ok_or_else(|| anyhow::anyhow!("replacement capacity overflow"))?,
            )?;
            self.bytes.try_reserve_exact(cap - self.bytes.len())?;
            self.credits.push(lease);
        }
        for chunk in text.chunks(4096) {
            self.bytes.extend_from_slice(chunk);
            if chunk.len() == 4096 {
                tokio::task::yield_now().await;
            }
        }
        Ok(())
    }
}
pub(super) async fn expand<L: Lookup + ?Sized>(
    input: &str,
    unknown_empty: bool,
    lookup: &L,
    pool: &Pool,
) -> Result<Bytes> {
    expand_limited(input, unknown_empty, lookup, pool, CAP).await
}
pub(super) async fn expand_limited<L: Lookup + ?Sized>(
    input: &str,
    unknown_empty: bool,
    lookup: &L,
    pool: &Pool,
    limit: usize,
) -> Result<Bytes> {
    ensure!(input.len() <= 1 << 20, "replacement input exceeds limit");
    ensure!(limit <= CAP, "replacement output limit exceeds maximum");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let bytes = input.as_bytes();
    let mut out = Output::new(input.len(), pool, limit)?;
    let (mut cursor, mut i, mut unclosed, mut steps, mut calls) = (0, 0, 0, 0usize, 0usize);
    while i < bytes.len() {
        steps += 1;
        if steps.is_multiple_of(4096) {
            ensure!(
                std::time::Instant::now() < deadline,
                "replacement deadline exceeded"
            );
            tokio::task::yield_now().await;
        }
        if i > 0 && bytes[i - 1] == b'\\' && matches!(bytes[i], b'{' | b'}') {
            out.append(&bytes[cursor..i - 1], pool).await?;
            cursor = i;
            i += 1;
            continue;
        }
        if bytes[i] != b'{' {
            i += 1;
            continue;
        }
        ensure!(unclosed <= 100, "too many unclosed placeholders");
        let mut end = i + 1;
        while end < bytes.len()
            && (bytes[end] != b'}' || (end > 0 && bytes[end - 1] == b'\\' && end < bytes.len() - 1))
        {
            end += 1;
            steps += 1;
            if steps.is_multiple_of(4096) {
                tokio::task::yield_now().await;
            }
        }
        if end == bytes.len() {
            unclosed += 1;
            i += 1;
            continue;
        }
        out.append(&bytes[cursor..i], pool).await?;
        calls += 1;
        if calls.is_multiple_of(128) {
            tokio::task::yield_now().await;
        }
        ensure!(
            std::time::Instant::now() < deadline,
            "replacement deadline exceeded"
        );
        let resolved = lookup.lookup(&input[i + 1..end]).await?;
        ensure!(
            std::time::Instant::now() < deadline,
            "replacement deadline exceeded"
        );
        match resolved {
            Some(value) => out.append(&value, pool).await?,
            None if !unknown_empty => {
                cursor = i;
                i += 1;
                continue;
            }
            None => {}
        }
        i = end + 1;
        cursor = i;
    }
    out.append(&bytes[cursor..], pool).await?;
    Ok(Bytes::from_owner(out))
}
