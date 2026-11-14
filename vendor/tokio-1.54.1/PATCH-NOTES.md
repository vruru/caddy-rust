# Tokio 1.54.1 startup rollback

Source: tokio 1.54.1 crates.io source, MIT license retained unchanged.

The threaded builder owns Runtime before launching workers. Launch retains all worker Arcs until success and uses a fallible internal blocking submission, returning the original OS io::Error. Failure closes the scheduler, uniquely takes unstarted cores for pre_shutdown/shutdown_core, and lets Runtime shut down and join its blocking pool. A zero-worker locked pool drains queued work outside its mutex, matching the sharded implementation. Normal CPU selection and public spawn_blocking contracts remain unchanged.

This local source package omits upstream independent tests/examples/benches and development-only Cargo target/dependency declarations. Runtime sources and required build metadata remain unchanged apart from the startup fix and optional queue recovery extension described here. Verification materials are kept outside this package.

## Optional existing-queue recovery

`Handle::try_wake_blocking_queue` forwards to the locked or sharded blocking
pool without enqueueing a task. It preserves the pool cap, idle notification,
shutdown fence and original OS thread-creation error. After a public
`spawn_blocking` panic following enqueue, an explicit caller can retry waking
the actual existing task. Normal `spawn_blocking` code and its contract remain
unchanged. The native certificate signing driver uses bounded retry backoff;
this API does not add an automatic global runtime retry loop or another pool.
