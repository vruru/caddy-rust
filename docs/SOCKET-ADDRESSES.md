# Socket address identity

Accepted TCP and QUIC addresses retain the operating system's IPv6 scope and
flow information. Only IPv4-mapped IPv6 endpoints are canonicalized to IPv4.
The connection's original local endpoint remains an actual socket fact across
configuration reloads and listener hostname changes.

Address and host placeholders, template connection addresses and FastCGI
address output retain a numeric `%scope_id` on scoped IPv6 endpoints. Numeric
interface identifiers are used; no interface-name lookup runs on the request
path. IP-only HTTP matching continues to use its existing IP representation.
TLS policy selection separately retains the scoped-address distinction, so a
scoped endpoint is not accidentally admitted by an unscoped prefix match.

These are address-preservation guarantees. They do not claim that every
platform has an available link-local route, or that numeric interface indexes
are stable across machines or network interface changes.
