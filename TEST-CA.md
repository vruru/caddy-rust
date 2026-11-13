# ACME test CA stages

`test_ca` is an ACME backend stage, not another configured fallback issuer. The Caddyfile `test_dir` option supplies the same field. It does not change the status of the separate ZeroSSL issuer API, ACME IP identifiers or other remaining issuer features.

An omitted or empty value preserves the Let's Encrypt production directory's default staging directory. For another primary directory, an empty value disables the test stage. Explicit directory values use the same generation preparation and retained-value rules as the primary directory: expansion and URL normalization happen once for that prepared configuration. These rules do not promise that every other client setting, such as a proxy provider, has gained a new preparation contract.

When the two normalized directory URLs are equal, the backend makes one primary request path. It retains the test-endpoint disposition, including its effect on renewal `replaces`; it does not create an auxiliary issuer or publish an intermediate test result.

## Issuance operations

The first actual attempt of an operation uses the primary CA. A later attempt can first complete a separate test issuance and then try the primary CA. A successful separate test stage gives the following primary attempt effective ordinal zero. Existing orders retain their actual account, CSR, order URL and captured order parameters; changing the retry ordinal does not rewrite them.

The retry ordinal belongs to one actual issuance operation. It is shared by the configured backends in that round and is independent of backend rank, persistent journal counts, ARI refresh failures and a maintenance task's lifetime. Success closes the operation. NoRetry or the operation's 30-day limit closes that operation; a later eligible maintenance event can begin a new operation after the existing renewal scan interval. It does not permanently disable recovery for that leaf.

Native background obtain/renew maintenance retains its existing backoff and uses an operation across its actual failed issuance attempts. This is an intentional scheduler difference: the pinned Go implementation's ordinary periodic renewal calls a one-attempt renewal path, while its asynchronous warm/forced paths use their own retrying operations. Native does not claim to reproduce that complete Go scheduler timeline.

An asynchronous warm operation belongs to its existing Flight and keeps that Flight's original 300-second absolute deadline. Its retries do not redo the outer authorization or reset that deadline. Proof listeners are released before sleeping, and the target receipt is rechecked. NoRetry cooldown is carried back to the existing resident entry, preventing an immediate new Flight from pretending to be operation zero. A synchronous/public single ensure and a cold on-demand Miss remain single-attempt ordinal zero.

**Remaining boundary:** operation-local retry state has not yet been connected to the physical Name0 forced-renewal scan. That path retains its existing one-attempt behavior. Complete forced-renewal test-CA support requires operation-owned transport/physical retirement receipts; an async guard being dropped is not evidence that a detached CPU worker, TLS operation or IO owner has retired. This stage is not complete test-CA compatibility.

## Private probe state and publication

A probe downloads and checks its candidate before any production asset save, winner claim, resolver publication, production obtained event or ARI success update. Its certificate and checkpoint remain in a dedicated versioned job/reservation namespace. A phase-bearing attempt uses a new protocol version that an old binary rejects. Ordinary attempts that have never entered the test protocol retain their earlier format. A version-3 attempt is not silently downgraded when its active stage changes or its test configuration is removed.

One operation receives a fresh 32-byte CSPRNG identity, persisted as part of its phase and probe job identity. Active persisted state takes precedence over a newly started caller's in-memory operation seed. Missing or malformed identities fail closed; they are not repaired with a new random value, and an already retired probe is not revived.

A completed receipt is bound to the actual primary backend, ACME index, original probe endpoint and test policy, input/CSR/SPKI, operation and probe job. Recovery reparses the actual material and checks the available adjacent certificate signatures, names, private-key/SPKI agreement, stored leaf fingerprint and current key veto. A chain tail is not required to be self-signed: standard ACME chains may omit an anchor. A single leaf or missing issuer does not create an independent issuer-signature or trust assertion. These checks do not claim a new complete PKIX trust policy.

The completion timestamp must lie inside the leaf's validity and must not be in the future; this protocol adds no clock-skew tolerance. Natural expiry after that historical completion can remain evidence of a completed probe. It never makes that test leaf eligible for serving, and it does not require the probe to be repeated. Current key compromise still rejects the receipt.

The durable PendingPrimary phase allows an already completed probe to survive a restart without replay. A test-policy-only change can still allow its original primary to finish if that primary's endpoint, credentials and production identity are unchanged. An active probe requires its original test policy and endpoint. Known primary orders keep their original parameters even when the test configuration changes.

A failed probe is not a separate production certificate failure event. The existing overall operation failure notification remains when the complete business operation fails; a later successful configured fallback does not retain an overall final failure. Test-endpoint errors retain their actual origin. Unknown outcomes, local/resource/key-veto errors and missing physical completion receipts do not become availability evidence merely because another backend exists.

## Ownership and limits

Prepared test directory values and their actual configuration copies retain the existing shared issuer-control credit. Additional constructor copies and temporaries use the existing certificate budgets, not a newly enlarged pool. The private fixed-name Group bound derives from the actual initialized certificate CPU capacity: abandoned physical builder Inputs plus one current initializer are counted before cloning. This is not a bound promised for arbitrary public multi-name or standalone callers.

The current initializer's normalized URL and trusted-origin text, policy vector cells, callback cells and the auxiliary identity JSON temporary are accounted separately. JSON escaping permits six output bytes per input byte; constructor prepayment also covers Vec growth's old/new buffer overlap. Identity and cooldown encoders run sequentially. The existing backend identity algorithm is unchanged.

Large acquisition futures cross a concrete Box boundary. The existing scratch budget is acquired before the Box allocation using the actual future size, alignment and bounded allocation overhead. The actual future is destroyed before that credit, including caller abort. This credit covers the acquisition frame; independently retained outputs, configured client settings, native workers and IO keep their own ownership. It is not a total heap, native allocator or RSS bound.

Directory transport keeps the existing authorization boundaries. A configured internal HTTP directory grants its own origin, not arbitrary HTTP endpoints. An HTTPS directory gains no HTTP permission from that internal-origin grant; the standalone explicit loopback option retains its prior contract. No directory or probe option bypasses signature checks or changes production trust material.
