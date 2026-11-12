//! Owned, read-only exporter capability captured after a completed handshake.
//! It retains no stream, traffic keys, record layer or connection lock.
pub(crate) mod sealed {
    pub trait Sealed {}
}
/// An immutable exporter secret. The final owner dropping it clears its secret.
/// A capability can outlive its connection; it cannot read or write TLS traffic.
pub trait NativeExporter: sealed::Sealed + Send + Sync {
    /// Export with Go-compatible empty-output and TLS 1.2 EMS/label semantics.
    /// Invalid inputs return an error before changing `output`.
    fn export_keying_material(&self, output: &mut [u8], label: &[u8],
        context: Option<&[u8]>) -> Result<(), crate::Error>;
}
