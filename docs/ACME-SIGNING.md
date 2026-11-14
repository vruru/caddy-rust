# ACME signature work ownership and recovery

Root-managed ACME clients prepare one persistent native signing driver using the
existing certificate CPU semaphore. Eligible jobs run oldest first. Input,
unconsumed output and errors reside in owned cells; asynchronous callers carry
small handles. Standalone public ACME constructors retain their existing path.

Before copying the closed JSON payload, URL or account identifier, the native
path reserves their checked allocation bound and the moved nonce capacity from
the existing 64 MiB scratch pool. Credit remains with queued input, including
input whose caller has never polled or has been aborted. The CPU producer
preflights JSON and base64 sizes and reserves simultaneous intermediate storage
before encoding. After those intermediates are destroyed, only the actual body
capacity remains charged. Exhaustion returns an explicit resource error.
This is not a bound on provider-internal allocations or process RSS.

The producer supports the existing account signer algorithms. Differential
wire verification covers P-256, P-384, Ed25519 and RSA keys of 2048, 4096 and
8192 bits, including public-JWK registration and account-KID POST-as-GET.
This does not replace certificate-chain or full PKIX compatibility acceptance.

Caller cancellation does not release a running CPU permit or declare physical
completion. The driver retains actual queued/running work and unconsumed
results until execution or cleanup finishes. Retained error views keep the
resident error alive; releasing a view schedules retirement on the same CPU
lane. Generation and parent scope fences prevent new work after closure.
The concrete scope primitive permits one generation-to-issuer-leg edge; its
existence is not proof of end-to-end issuer-fallback retirement.

The Tokio extension `Handle::try_wake_blocking_queue` attempts to start or wake
an existing blocking queue without enqueueing another task. Public
`spawn_blocking` behavior is unchanged. If an OS thread-creation failure occurs
after enqueue, the existing envelope retains ownership. A bounded 10–250 ms
backoff retries the queue wake. Two panic slots and the real cleanup state bound
opaque unwind staging. A known submission failure abandons only its cell;
recovery permits new work through the same process resources. Unrelated driver
invariant panics close admission. Idle recovery polling stops after retirement.

At successful handoff, the result becomes owned HTTP bytes. Subsequent byte
retirement belongs to the HTTP lifetime; it is not promised to occur on the
signing CPU lane. Shutdown waits for actual signing and cleanup retirement.
This does not establish a unified physical receipt for every network, storage
or issuer-leg operation. All verification remains isolated development
acceptance; full compatibility and the production rollout gates still apply.
