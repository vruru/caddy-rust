//! Shared validated X509 key handling for local PKI and leaf CSRs.
pub(super) use crate::crypto::x509_signer::{X509Signer as CaSigner, X509PublicKey as SubjectKey};
