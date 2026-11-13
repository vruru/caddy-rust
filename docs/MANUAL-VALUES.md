# Provisioned manual certificate values

The native certificate app preserves raw JSON while resolving global placeholders
once per successful manual source preparation. Normal retries reuse completed
values; restore-only compensation uses already accepted Material and performs no
manual provider/source reads. Files and Storage validate the expanded format.
Unknown placeholders stay literal. PEM provider values retain bytes; non-UTF8
storage keys or tags are rejected because those downstream APIs require strings.

ManualCertificateInfo.tags is now Arc<CertificateTags>, sharing its actual label
allocation and memory lease across inventories and retained material. External
Rust callers can construct a nonempty inventory without exposing memory pools:

```rust
use caddy_compat_native::certificate_tags::CertificateTags;
let tags = CertificateTags::try_from_slice(&["production".to_owned()])?;
// ManualCertificateInfo { identity, names, tags }
# Ok::<(), anyhow::Error>(())
```

Construction is fallible and charges the existing process payload aggregate before
copying. Arc cloning shares bytes and admission; labels are readable as a string
slice and cannot be extracted as an unleased mutable vector. The project does not
promise a stable Rust type ABI.
