//! Generation-owned subjects: raw configuration stays raw, while provisioning
//! resolves global providers once and rollback restores accepted values.
use super::model::{CertificatePlan, Issuer};
use crate::acme_wire::chain_memory::{Lease, Pool, Scratch};
use crate::cert_transient::{self, ResourceDenied};
use anyhow::{Result, anyhow, ensure};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, sync::{Arc, OnceLock}};
use tokio::sync::{OnceCell, Semaphore};
use tokio_util::sync::CancellationToken;
#[path = "subject_values/environment.rs"]
pub(super) mod environment;
const FIELD: usize = 1 << 20;
const SCRATCH: usize = 16 * FIELD + 16384;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind { Policy, Automate }

pub(super) struct Prepared {
    names: Vec<String>,
    _memory: Option<Lease>,
}
impl Prepared {
    pub(super) fn names(&self) -> &[String] { &self.names }
}

pub(super) struct Input {
    raw: Vec<String>,
    kind: Kind,
    id: [u8; 32],
    ready: OnceCell<Arc<Prepared>>,
    _metadata: Option<Scratch>,
}
fn identity(kind: Kind, raw: &[String]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"certificate-subject-values-v1");
    hash.update([match kind { Kind::Policy => 0, Kind::Automate => 1 }]);
    hash.update((raw.len() as u64).to_be_bytes());
    for value in raw {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    hash.finalize().into()
}
impl Input {
    pub(super) fn empty(kind: Kind) -> Arc<Self> {
        // Fixed empty constants are not a cache of resolved provider values.
        static POLICY: OnceLock<Arc<Input>> = OnceLock::new();
        static AUTOMATE: OnceLock<Arc<Input>> = OnceLock::new();
        let slot = match kind { Kind::Policy => &POLICY, Kind::Automate => &AUTOMATE };
        slot.get_or_init(|| Arc::new(Self {
            raw: Vec::new(), kind, id: identity(kind, &[]),
            ready: OnceCell::new_with(Some(Arc::new(Prepared {
                names: Vec::new(), _memory: None,
            }))), _metadata: None,
        })).clone()
    }
    pub(super) fn new(kind: Kind, raw: Vec<String>) -> Result<Arc<Self>> {
        ensure!(raw.len() <= 65536 && raw.iter().all(|s| s.len() <= FIELD),
            "certificate subject input exceeds limit");
        if raw.is_empty() { return Ok(Self::empty(kind)); }
        // Raw typed strings move from the existing parse owner; only the new
        // descriptor is allocated here. No second raw string copy is made.
        let memory = cert_transient::reserve(std::mem::size_of::<Self>() + 128)?;
        Ok(Arc::new(Self { id: identity(kind, &raw), raw, kind,
            ready: OnceCell::new(), _metadata: Some(memory) }))
    }
    pub(super) fn raw(&self) -> &[String] { &self.raw }
    pub(super) fn get(&self) -> Result<&Arc<Prepared>> {
        self.ready.get().ok_or_else(|| anyhow!("certificate subjects are not prepared"))
    }
    // Synthetic implicit Tailscale policies already have a canonical subject;
    // they never run providers and are not part of raw-plan rollback snapshots.
    pub(super) fn literal(subject: &str, pool: &Arc<Pool>) -> Result<Arc<Self>> {
        ensure!(subject.len() <= FIELD, "certificate subject exceeds limit");
        let bytes = subject.len().checked_mul(2)
            .and_then(|n| n.checked_add(std::mem::size_of::<Prepared>() + std::mem::size_of::<String>() + 256))
            .ok_or(ResourceDenied)?;
        let memory = pool.reserve(bytes)?;
        let metadata = cert_transient::reserve(std::mem::size_of::<Self>() + 128)?;
        let mut text = String::new();
        text.try_reserve_exact(subject.len()).map_err(|_| ResourceDenied)?;
        text.push_str(subject);
        let mut names = Vec::new();
        names.try_reserve_exact(1).map_err(|_| ResourceDenied)?;
        names.push(text);
        Ok(Arc::new(Self { raw: Vec::new(), kind: Kind::Policy,
            id: identity(Kind::Policy, &[]), ready: OnceCell::new_with(Some(Arc::new(Prepared {
                names, _memory: Some(memory),
            }))), _metadata: Some(metadata) }))
    }
    async fn prepare(self: &Arc<Self>, cpu: Arc<Semaphore>, pool: Arc<Pool>, cancel: CancellationToken) -> Result<()> {
        self.ready.get_or_try_init(|| {
            let input = self.clone();
            crate::cert_cpu::run(cpu, cancel.clone(), move || {
                // Covers one provider result/copy, replacement growth old+new,
                // and IDNA intermediates. List output has its own resident lease.
                let _scratch = cert_transient::reserve(SCRATCH)?;
                let metadata = input.raw.len().checked_mul(2 * std::mem::size_of::<String>())
                    .and_then(|n| n.checked_add(std::mem::size_of::<Prepared>() + 256))
                    .ok_or(ResourceDenied)?;
                let mut memory = pool.reserve(metadata)?;
                let mut names = Vec::new();
                names.try_reserve_exact(input.raw.len()).map_err(|_| ResourceDenied)?;
                ensure!(names.capacity() * std::mem::size_of::<String>() <= metadata,
                    "certificate subject memory limit");
                let mut resident = names.capacity() * std::mem::size_of::<String>()
                    + std::mem::size_of::<Prepared>() + 256;
                for raw in &input.raw {
                    ensure!(!cancel.is_cancelled(), "certificate preparation cancelled");
                    let expanded = expand(raw)?;
                    let value = match input.kind {
                        Kind::Policy => pattern_to_ascii(&expanded)?,
                        Kind::Automate => {
                            ensure!(!expanded.is_empty(), "automated certificate identifier is empty");
                            let mut normalized=crate::cert_automation::normalize_managed_names(&[expanded])
                                .map_err(|_| anyhow!("automated certificate identifier is invalid"))?;
                            normalized.pop().ok_or_else(||anyhow!("automated certificate identifier is invalid"))?
                        }
                    };
                    ensure!(value.len() <= FIELD, "certificate subject exceeds limit");
                    resident = resident.checked_add(value.capacity()).ok_or(ResourceDenied)?;
                    // The temporary value is covered by scratch until transfer;
                    // grow resident admission before it enters retained output.
                    memory.resize(resident)?;
                    names.push(value);
                }
                ensure!(!cancel.is_cancelled(), "certificate preparation cancelled");
                Ok(Arc::new(Prepared { names, _memory: Some(memory) }))
            })
        }).await?;
        Ok(())
    }
}

fn lookup(name: &str) -> Result<Option<String>> {
    if let Some(key) = name.strip_prefix("env.") {
        let value = environment::bounded_environment(key)?;
        // The outer worker scratch prepays this bridge copy; the reader owns
        // its independent original buffer until this synchronous copy finishes.
        return Ok(Some(value.as_str().to_owned()));
    }
    if let Some(path) = name.strip_prefix("file.") {
        use std::io::Read;
        let Ok(mut file) = crate::http_config::helpers::open_regular_file(path) else {
            return Ok(Some(String::new()));
        };
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(FIELD).map_err(|_| ResourceDenied)?;
        ensure!(bytes.capacity() <= 2 * FIELD, "certificate subject memory limit");
        bytes.resize(FIELD, 0);
        let mut len = 0;
        while len < FIELD {
            match file.read(&mut bytes[len..]) {
                Ok(0) => break,
                Ok(n) => len += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Ok(Some(String::new())),
            }
        }
        if len > 0 && bytes[len - 1] == b'\n' { len -= 1; }
        if len > 0 && bytes[len - 1] == b'\r' { len -= 1; }
        let text = std::str::from_utf8(&bytes[..len])
            .map_err(|_| anyhow!("certificate subject file contains unsupported non-UTF8 bytes"))?;
        return Ok(Some(text.to_owned()));
    }
    // Remaining native global values have fixed OS/time bounds; opaque system
    // library allocations are not an allocator-wide admission claim.
    Ok(crate::http_config::helpers::global_lookup(name))
}
fn expand(raw: &str) -> Result<String> {
    let failed = RefCell::new(None);
    let output = crate::http_config::helpers::replace_accounted(raw, true,
        |name| match lookup(name) {
            Ok(value) => value,
            Err(error) => { if failed.borrow().is_none() { *failed.borrow_mut() = Some(error); } None }
        },
        |bytes| { ensure!(bytes <= 2 * FIELD, "certificate subject expansion exceeds limit"); Ok(()) });
    if let Some(error) = failed.into_inner() { return Err(error); }
    let output = output.map_err(|_| anyhow!("certificate subject expansion failed"))?;
    ensure!(output.len() <= FIELD, "certificate subject expansion exceeds limit");
    Ok(output)
}

// Caddy uses the minimal Punycode profile for policy patterns, not the URL/UTS46
// lookup profile. Do not lowercase/map/full-stop-normalize ASCII pattern syntax.
fn pattern_to_ascii(value: &str) -> Result<String> {
    let mut output = String::new();
    for (index, original) in value.split('.').enumerate() {
        if index != 0 { output.push('.'); }
        let decoded;
        let label = if let Some(encoded) = original.strip_prefix("xn--") {
            decoded = idna::punycode::decode_to_string(encoded)
                .ok_or_else(|| anyhow!("certificate subject IDNA conversion failed"))?;
            ensure!(decoded.is_empty() || !decoded.is_ascii(), "certificate subject IDNA conversion failed");
            decoded.as_str()
        } else { original };
        if label.is_ascii() {
            output.push_str(label);
        } else {
            ensure!(label.chars().count() <= FIELD / 16, "certificate subject IDNA input exceeds limit");
            let encoded = idna::punycode::encode_str(label)
                .ok_or_else(|| anyhow!("certificate subject IDNA conversion failed"))?;
            output.push_str("xn--"); output.push_str(&encoded);
        }
        ensure!(output.len() <= FIELD, "certificate subject IDNA output exceeds limit");
    }
    Ok(output)
}

pub(crate) struct ExplicitSubjects {
    lists: Vec<Arc<Prepared>>,
    _memory: Option<Lease>,
}
impl Default for ExplicitSubjects {
    fn default() -> Self { Self { lists: Vec::new(), _memory: None } }
}
impl ExplicitSubjects {
    pub(crate) fn contains(&self, name: &str) -> bool {
        self.lists.iter().any(|list| list.names.iter().any(|subject| subject == name))
    }
}
fn inputs(plan: &CertificatePlan) -> impl Iterator<Item = &Arc<Input>> {
    plan.policies.iter().map(|p| &p.subjects).chain(std::iter::once(&plan.automate))
}
pub(super) async fn prepare_all(plan: Arc<CertificatePlan>, cpu: Arc<Semaphore>, pool: Arc<Pool>, cancel: CancellationToken) -> Result<Arc<ExplicitSubjects>> {
    for input in inputs(&plan) {
        input.prepare(cpu.clone(), pool.clone(), cancel.clone()).await?;
    }
    explicit(plan, cpu, pool, cancel).await
}
pub(super) async fn explicit(plan: Arc<CertificatePlan>, cpu: Arc<Semaphore>, pool: Arc<Pool>, cancel: CancellationToken) -> Result<Arc<ExplicitSubjects>> {
    crate::cert_cpu::run(cpu, cancel, move || {
        for policy in &plan.policies {
            let subjects = policy.subjects.get()?.names();
            ensure!(!(policy.on_demand && policy.managers.is_empty() && plan.permission.is_none()
                && (subjects.is_empty() || subjects.iter().any(|s| s.contains('*')))
                && !(!policy.issuers.is_empty() && policy.issuers.iter().all(|i| matches!(i, Issuer::Internal { .. })))),
                "on-demand certificate permission is required");
        }
        let bytes = plan.policies.len().checked_mul(2 * std::mem::size_of::<Arc<Prepared>>())
            .and_then(|n| n.checked_add(std::mem::size_of::<ExplicitSubjects>() + 256))
            .ok_or(ResourceDenied)?;
        let memory = pool.reserve(bytes)?;
        let mut lists = Vec::new();
        lists.try_reserve_exact(plan.policies.len()).map_err(|_| ResourceDenied)?;
        for policy in &plan.policies { lists.push(policy.subjects.get()?.clone()); }
        Ok(Arc::new(ExplicitSubjects { lists, _memory: Some(memory) }))
    }).await
}
struct Snapshot { id: [u8; 32], kind: Kind, value: Arc<Prepared> }
pub(super) struct Retained { values: Vec<Snapshot>, _memory: Lease }
pub(super) fn retain(plan: &CertificatePlan, pool: &Arc<Pool>) -> Result<Arc<Retained>> {
    let count = inputs(plan).count();
    let bytes = count.checked_mul(2 * std::mem::size_of::<Snapshot>())
        .and_then(|n| n.checked_add(std::mem::size_of::<Retained>() + 256)).ok_or(ResourceDenied)?;
    let memory = pool.reserve(bytes)?;
    let mut values = Vec::new();
    values.try_reserve_exact(count).map_err(|_| ResourceDenied)?;
    for input in inputs(plan) { values.push(Snapshot { id: input.id, kind: input.kind, value: input.get()?.clone() }); }
    Ok(Arc::new(Retained { values, _memory: memory }))
}
pub(super) fn restore(plan: &CertificatePlan, saved: &Retained) -> Result<()> {
    ensure!(inputs(plan).count() == saved.values.len(), "retained certificate subject count changed");
    // Validate the whole graph before installing any nonempty candidate cell.
    for (input, value) in inputs(plan).zip(&saved.values) {
        ensure!(input.kind == value.kind && input.id == value.id, "retained certificate subject identity changed");
        if let Some(current) = input.ready.get() {
            ensure!(input.raw.is_empty() && Arc::ptr_eq(current, &value.value), "certificate subjects already prepared");
        }
    }
    for (input, value) in inputs(plan).zip(&saved.values) {
        if input.ready.get().is_none() {
            input.ready.set(value.value.clone()).map_err(|_| anyhow!("certificate subjects already prepared"))?;
        }
    }
    Ok(())
}
