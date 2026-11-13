# Tokio 1.54.1 startup rollback

Source: tokio 1.54.1 crates.io source, MIT license retained unchanged.

The threaded builder owns Runtime before launching workers. Launch retains all worker Arcs until success and uses a fallible internal blocking submission, returning the original OS io::Error. Failure closes the scheduler, uniquely takes unstarted cores for pre_shutdown/shutdown_core, and lets Runtime shut down and join its blocking pool. A zero-worker locked pool drains queued work outside its mutex, matching the sharded implementation. Normal CPU selection and public spawn_blocking contracts remain unchanged.

This local source package omits upstream independent tests/examples/benches and development-only Cargo target/dependency declarations. Runtime sources and required build metadata remain unchanged apart from the three-file fix described above. Verification materials are kept outside this package.
