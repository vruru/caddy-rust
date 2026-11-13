// Constants ported from Smallstep certificates v0.30.2 acme/errors.go.
// Copyright Smallstep Authors. Apache-2.0.
pub(super) fn metadata(kind: &str) -> Option<(&'static str, u16)> {
    Some(match kind {
        "accountDoesNotExist" => ("Account does not exist", 400),
        "alreadyRevoked" => ("Certificate already revoked", 400),
        "badAttestationStatement" => ("Attestation statement cannot be verified", 400),
        "badCSR" => ("The CSR is unacceptable", 400),
        "badNonce" => ("Unacceptable anti-replay nonce", 400),
        "badPublicKey" => (
            "The jws was signed by a public key the server does not support",
            400,
        ),
        "badRevocationReason" => (
            "The revocation reason provided is not allowed by the server",
            400,
        ),
        "badSignatureAlgorithm" => (
            "The JWS was signed with an algorithm the server does not support",
            400,
        ),
        "caa" => (
            "Certification Authority Authorization (CAA) records forbid the CA from issuing a certificate",
            400,
        ),
        "compound" => (
            "Specific error conditions are indicated in the “subproblems” array",
            400,
        ),
        "connection" => ("The server could not connect to validation target", 400),
        "dns" => (
            "There was a problem with a DNS query during identifier validation",
            400,
        ),
        "externalAccountRequired" => (
            "The request must include a value for the \"externalAccountBinding\" field",
            400,
        ),
        "malformed" => ("The request message was malformed", 400),
        "notImplemented" => ("The requested operation is not implemented", 501),
        "orderNotReady" => (
            "The request attempted to finalize an order that is not ready to be finalized",
            400,
        ),
        "rateLimited" => ("The request exceeds a rate limit", 400),
        "rejectedIdentifier" => (
            "The server will not issue certificates for the identifier",
            400,
        ),
        "serverInternal" => ("The server experienced an internal error", 500),
        "tls" => ("The server received a TLS error during validation", 400),
        "unauthorized" => ("The client lacks sufficient authorization", 401),
        "unsupportedContact" => (
            "A contact URL for an account used an unsupported protocol scheme",
            400,
        ),
        "unsupportedIdentifier" => ("An identifier is of an unsupported type", 400),
        "userActionRequired" => (
            "Visit the “instance” URL and take actions specified there",
            400,
        ),
        _ => return None,
    })
}
