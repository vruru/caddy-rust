# Certificate URI SAN syntax admission

Certificate material and peer certificate chains apply a shared URI SAN syntax
guard before accepting the certificate's URI facts. It checks each presented
certificate, including intermediates, without rewriting DER, changing signatures,
or replacing the existing trust, purpose, name, time, chain or proof-of-possession
verifier. This is a finite syntax compatibility layer, not a claim of complete
PKIX equivalence.

The guard follows the pinned Go certificate parser: raw URI SAN bytes must be
IA5/ASCII, `net/url.Parse` component rules apply, and a nonempty decoded full Host
must pass the certificate parser's domain gate. Relative and opaque URIs remain
valid where that parser accepts them. RawQuery is not percent-decoded during this
check. ASCII controls in a fragment are accepted and escaped by URL output;
controls in preceding components are rejected. Escaped path bytes are not forced
to UTF-8. Certificate view mutations still remain isolated from original DER and
are not subjected to SAN admission again.

Incoming fresh client-certificate verification and explicit outgoing server
verification share the guard, including outgoing skip-trust modes. Raw-public-key
verifiers bypass X.509 inspection and retain their original behavior. Original
signature algorithms, root hints and verification policy are delegated. ACME and
OCSP/AIA reqwest construction use an optional fixed, fallible wrapper after the
existing TLS configuration is complete; roots, proxies, identities, providers and
transport settings are retained. The generic reqwest default remains unwrapped.

Root-source contracts are distinct. File/inline/deprecated CA providers retain
strict certificate parsing. ACME trusted-root PEM files use their documented
Append contract: unusable certificates are skipped, usable certificates retained,
and a file with none usable is rejected. Existing append-style system, proxy PEM,
metrics and loader roots retain their own skip behavior. Resource admission errors
are always propagated, and do not become silently skipped roots or a cached empty
system root store. OCSP's independent explicit root API remains strict.

The borrowed DER walk allocates no certificate AST. It finds the largest URI
before admitting temporary parsing scratch: `32 * maximum_URI_bytes + 65536`, with
checked arithmetic, from the existing certificate scratch pool. URI-less chains
avoid that scratch reservation. Parsing proceeds one certificate and URI at a
time. Each outgoing verifier wrapper prepays its resident allocation (its concrete
size plus 256 bytes) from the existing atomic certificate payload pool until its
last owner drops. No new process pool is introduced.

A narrow Rustls client-verifier hook additionally checks syntax in nonempty saved
client chains before existing resumption binding checks. A syntax error declines
that resume attempt and requires a fresh handshake; it does not reverify trust or
fabricate a verified-chain observation. Native server policy currently disables
client-authenticated session caching/tickets. This patch leaves that independent
resumption limitation in place; it does not enable that feature.
