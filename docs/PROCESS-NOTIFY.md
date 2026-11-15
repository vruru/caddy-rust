# Native process-manager notifications

On Linux, `run` captures its inherited `NOTIFY_SOCKET` once before constructing
its runtime. Filesystem paths, non-UTF8 Unix paths and Linux abstract addresses
are supported without a Go helper or libsystemd dependency. Library users and
short-lived reload/stop clients do not initialize a notifier.

The serving process sends `RELOADING=1` before initial preparation and accepted
configuration work, `READY=1` after successful startup/publication, and
`STOPPING=1` when an authorized Admin stop or process signal begins shutdown.
A failed reload publishes a fixed `STATUS=config_reload_failed` category while
the working predecessor remains ready. A failed initial startup never claims
readiness. Once stopping begins, no later ready notification is sent.

Each datagram is atomic, nonblocking and bounded to 100 ms. A missing endpoint,
full manager queue, invalid address or delivery error cannot block ordinary
requests indefinitely, roll back a committed configuration, or prevent shutdown.
Failures log only a fixed category, without environment values, configuration
contents or endpoint paths. macOS and other non-Linux builds are no-ops.

This implements the process-state protocol used by `Type=notify` services. It
does not add a watchdog, socket activation, installation or self-upgrade system.
The production unit's authorization, timeouts and CPU policy remain operator
configuration. Datagram/credential validation is separate from final acceptance
under the target machine's actual service manager.

An explicit force signal also cancels the real HTTP/1 and HTTP/2 connection
future, including after graceful drain has started. This closes the owned IO
even when the peer has stopped reading or no longer grants flow-control credit;
it does not depend on another response-body poll. Ordinary shutdown and reload
continue to drain accepted work. Connection and request credit is released by
actual IO/body destruction; retained workers keep their own ownership until
they finish. Force does not synthesize completion or refund permits early.
