//! A PKI pair checkpoint over the existing safe store. No alternate filesystem
//! writer: readers hold the CA lease; original Caddy resumes only after recovery.
use super::material::{self, Pair};
use crate::certstore::{FsStore, StorageLease};
use anyhow::{Result, anyhow, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

struct SecretRecord(Value);
struct AbandonedWrite {
    lost: CancellationToken,
    armed: bool,
}
impl Drop for AbandonedWrite {
    fn drop(&mut self) {
        if self.armed {
            self.lost.cancel();
        }
    }
}
impl Drop for SecretRecord {
    fn drop(&mut self) {
        fn clear(value: &mut Value) {
            match value {
                Value::String(value) => value.zeroize(),
                Value::Array(values) => values.iter_mut().for_each(clear),
                Value::Object(values) => values.values_mut().for_each(clear),
                _ => {}
            }
        }
        clear(&mut self.0);
    }
}
pub(super) fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
pub(super) fn job_name(prefix: &str, kind: &str) -> String {
    format!("localpki-{}", hash(format!("{prefix}\0{kind}").as_bytes()))
}
pub(super) struct PairStore<'a> {
    pub store: &'a FsStore,
    pub prefix: &'a str,
    pub kind: &'a str,
    pub root: Option<&'a Pair>,
    pub now: i64,
    pub lease: &'a StorageLease,
    pub cpu: Arc<Semaphore>,
    pub cancel: CancellationToken,
}
impl PairStore<'_> {
    async fn root_settled(&self) -> Result<()> {
        if self.kind != "intermediate" {
            return Ok(());
        }
        let root_job = job_name(self.prefix, "root");
        if let Some(value) = self.store.journal_load(&root_job).await? {
            let record = SecretRecord(value);
            ensure!(
                record.0["version"] == 1
                    && record.0["scope"].as_str() == Some(self.prefix)
                    && record.0["kind"] == "root"
                    && record.0["lease_name"].as_str() == Some(self.lease.name())
                    && record.0["phase"] == "done",
                "intermediate cannot proceed before root checkpoint is settled"
            );
        }
        Ok(())
    }
    fn paths(&self) -> Result<(String, String, String)> {
        ensure!(
            matches!(self.kind, "root" | "intermediate"),
            "invalid PKI pair kind"
        );
        let suffix = self
            .prefix
            .strip_prefix("pki/authorities/")
            .ok_or_else(|| anyhow!("invalid PKI scope"))?;
        ensure!(
            !suffix.is_empty()
                && !matches!(suffix, "." | "..")
                && !suffix.contains('/')
                && suffix == crate::certstore::safe(suffix),
            "invalid PKI authority scope"
        );
        ensure!(
            self.lease.name() == format!("local_pki_{}", hash(self.prefix.as_bytes())),
            "PKI lease scope mismatch"
        );
        let job = job_name(self.prefix, self.kind);
        Ok((
            format!("{}/{}.crt", self.prefix, self.kind),
            format!("{}/{}.key", self.prefix, self.kind),
            job,
        ))
    }
    pub async fn load(&self) -> Result<Option<Pair>> {
        let (crt, key, job) = self.paths()?;
        self.root_settled().await?;
        let checkpoint = self.store.journal_load(&job).await?.map(SecretRecord);
        if let Some(checkpoint) = &checkpoint {
            ensure!(
                checkpoint.0["version"] == 1
                    && checkpoint.0["lease_name"].as_str() == Some(self.lease.name())
                    && checkpoint.0["scope"].as_str() == Some(self.prefix)
                    && checkpoint.0["kind"].as_str() == Some(self.kind)
                    && checkpoint.0["phase"].as_str() == Some("done"),
                "PKI pair has unresolved checkpoint"
            );
        }
        let crt = self.store.load(&crt).await?;
        let key = self.store.load(&key).await?;
        if let Some(checkpoint) = &checkpoint {
            ensure!(
                crt.as_ref().is_some_and(
                    |v| checkpoint.0["new_crt_sha256"].as_str() == Some(hash(v).as_str())
                ) && key.as_ref().is_some_and(
                    |v| checkpoint.0["new_key_sha256"].as_str() == Some(hash(v).as_str())
                ),
                "completed PKI pair encountered external material change"
            );
        }
        match (crt, key) {
            (None, None) => Ok(None),
            (Some(crt), Some(key)) => Ok(Some(Pair {
                explicit_anchor: false,
                chain_pem: crt.to_vec(),
                private_key_pem: Some(key),
            })),
            _ => Err(anyhow!(
                "incomplete PKI pair; refusing identity replacement"
            )),
        }
    }
    async fn validate(&self, pair: &Pair, allow_expired: bool) -> Result<()> {
        let permit = tokio::select! {
            _ = self.cancel.cancelled() => return Err(anyhow!("PKI operation cancelled")),
            permit = self.cpu.clone().acquire_owned() => permit.map_err(|_| anyhow!("PKI crypto pool closed"))?,
        };
        let pair = pair.clone();
        let root = self.root.cloned();
        let now = self.now;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            material::validate(&pair, root.as_ref(), now, allow_expired)
        })
        .await?
    }
    fn root_hash(&self) -> Result<Option<String>> {
        if self.kind == "root" {
            return Ok(None);
        }
        let root = self
            .root
            .ok_or_else(|| anyhow!("intermediate transaction requires root"))?;
        Ok(Some(hash(&material::chain(&root.chain_pem)?[0])))
    }
    async fn done(&self, pair: &Pair, job: &str) -> Result<()> {
        let value = json!({"version":1,"scope":self.prefix,"kind":self.kind,
            "lease_name":self.lease.name(),"phase":"done","root_sha256":self.root_hash()?,
            "new_crt_sha256":hash(&pair.chain_pem),
            "new_key_sha256":hash(pair.private_key_pem.as_ref().ok_or_else(||anyhow!("PKI key missing"))?) });
        self.store
            .journal_store_fenced(job, &value, self.lease)
            .await
    }
    pub async fn recover(&self) -> Result<()> {
        let (crt, key, job) = self.paths()?;
        self.root_settled().await?;
        let Some(value) = self.store.journal_load(&job).await? else {
            return Ok(());
        };
        let record = SecretRecord(value);
        let value = &record.0;
        ensure!(
            value["version"] == 1
                && value["scope"].as_str() == Some(self.prefix)
                && value["kind"].as_str() == Some(self.kind)
                && value["lease_name"].as_str() == Some(self.lease.name()),
            "PKI checkpoint scope mismatch"
        );
        match value["phase"].as_str() {
            Some("done") => {
                ensure!(
                    value.get("new_key").is_none() && value.get("new_crt").is_none(),
                    "completed PKI journal retains private material"
                );
                return Ok(());
            }
            Some("pending") => {}
            _ => return Err(anyhow!("invalid PKI checkpoint phase")),
        }
        ensure!(
            value["root_sha256"] == serde_json::to_value(self.root_hash()?)?,
            "PKI checkpoint root changed"
        );
        fn decode(value: &Value, field: &str, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
            let encoded = value[field]
                .as_str()
                .ok_or_else(|| anyhow!("invalid PKI checkpoint material"))?;
            ensure!(
                encoded.len() <= limit.div_ceil(3) * 4,
                "PKI checkpoint size limit exceeded"
            );
            let bytes = Zeroizing::new(
                STANDARD
                    .decode(encoded)
                    .map_err(|_| anyhow!("invalid PKI checkpoint encoding"))?,
            );
            ensure!(
                !bytes.is_empty() && bytes.len() <= limit,
                "PKI checkpoint material size exceeded"
            );
            Ok(bytes)
        }
        let pair = Pair {
            explicit_anchor: false,
            chain_pem: decode(value, "new_crt", 1024 * 1024)?.to_vec(),
            private_key_pem: Some(decode(value, "new_key", 128 * 1024)?),
        };
        self.validate(&pair, true).await?;
        for (path, field, new) in [
            (&crt, "old_crt_sha256", pair.chain_pem.as_slice()),
            (
                &key,
                "old_key_sha256",
                pair.private_key_pem
                    .as_ref()
                    .expect("validated key")
                    .as_slice(),
            ),
        ] {
            let old = &value[field];
            ensure!(
                old.is_null()
                    || old
                        .as_str()
                        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())),
                "invalid PKI prior digest"
            );
            let current = self.store.load(path).await?;
            match current {
                None => ensure!(old.is_null(), "PKI prior material unexpectedly missing"),
                Some(bytes) => {
                    let actual = hash(&bytes);
                    ensure!(
                        old.as_str() == Some(actual.as_str()) || actual == hash(new),
                        "PKI checkpoint encountered external material change"
                    );
                }
            }
        }
        let mut abandoned = AbandonedWrite {
            lost: self.lease.lost(),
            armed: true,
        };
        self.lease.check().await?;
        self.store
            .store_fenced(&crt, &pair.chain_pem, self.lease)
            .await?;
        self.store
            .store_fenced(
                &key,
                pair.private_key_pem.as_ref().expect("validated key"),
                self.lease,
            )
            .await?;
        self.done(&pair, &job).await?;
        abandoned.armed = false;
        Ok(())
    }
    pub async fn save(&self, pair: &Pair, expected_old_crt: Option<&str>) -> Result<()> {
        self.recover().await?;
        let key = pair
            .private_key_pem
            .as_ref()
            .ok_or_else(|| anyhow!("PKI key missing"))?;
        ensure!(
            pair.chain_pem.len() <= 1024 * 1024 && key.len() <= 128 * 1024,
            "PKI material size limit exceeded"
        );
        self.validate(pair, false).await?;
        let old = self.load().await?;
        ensure!(
            old.as_ref().map(|p| hash(&p.chain_pem)).as_deref() == expected_old_crt,
            "PKI identity changed since issuance decision"
        );
        if let Some(old) = &old {
            self.validate(old, true).await?;
        }
        let (_, _, job) = self.paths()?;
        let value = SecretRecord(json!({"version":1,"scope":self.prefix,"kind":self.kind,
            "lease_name":self.lease.name(),"phase":"pending","root_sha256":self.root_hash()?,
            "old_crt_sha256":old.as_ref().map(|p|hash(&p.chain_pem)),
            "old_key_sha256":old.as_ref().and_then(|p|p.private_key_pem.as_ref().map(|key|hash(key))),
            "new_crt":STANDARD.encode(&pair.chain_pem),"new_key":STANDARD.encode(key)}));
        let mut abandoned = AbandonedWrite {
            lost: self.lease.lost(),
            armed: true,
        };
        self.store
            .journal_store_fenced(&job, &value.0, self.lease)
            .await?;
        self.recover().await?;
        abandoned.armed = false;
        Ok(())
    }
}
