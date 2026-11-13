# Global TLS DNS resolver defaults

`apps.tls.resolvers` stores the default resolver list for TLS DNS consumers.
The native ACME server selects a nonempty handler-local `resolvers` list first,
otherwise this global list; an empty result uses the system resolver. Missing,
null and empty arrays therefore have the same fallback behavior. A JSON null
inside a string array becomes an empty string, as in Go; a consumed empty
Internet host dials the family's wildcard/local endpoint, with default port53.

The ACME server uses this selection for DNS-01 TXT validation. It does not
change HTTP-01 or TLS-ALPN-01 address resolution, reverse proxy DNS, outbound
HTTP clients, OCSP or every process-wide lookup. Resolver configuration uses the
existing UDP/TCP IPv4/IPv6 and Unix transport implementation. Values are checked
when the ACME server consumes them; unused or locally shadowed global values
are preserved rather than eagerly dialed or rejected. Unsupported transport
networks fail staging explicitly, where the Go reference accepts them and later
fails to dial. Multi-port ranges are refused by both implementations.

Configuration retains one shared resolver-array owner. A controller clones
that owner without copying its strings or retaining CertificateServices/Root.
Its metadata lifetime is distinct from an in-flight worker retirement token.
Resolver arrays remain shared configuration owners throughout the lookup;
async DNS producers do not deep-copy the complete list. Expansion and peer
validation use the existing bounded metadata worker, with per-item cancellation
and prepayment. Unselected peer temporaries retire on that worker; only the
small selected peer returns to async code. Controlled lookup copies remain
owned by the actual DNS future, transport, blocking closure or result. Configuration retirement does not return credit
beneath a still-running lookup. The existing ACME queues and memory/work/time
bounds remain unchanged; this is not a whole-process heap guarantee.

Concurrent validations can exhaust their shared material budget before any
DNS packet is sent, and then return overload responses. The limits do not
promise that one maximum-size validation must succeed in every simultaneous
burst. This refusal is distinct from a DNS transport failure and does not
increase the unrelated HTTP resource budgets.

The existing `tls_resolvers` Caddyfile option emits the TLS app field and DNS
issuer options according to the original adapter. DNS-provider certificate
issuance remains explicitly unsupported by the issuer runtime; setting these
defaults does not create a DNS provider or silently enable that capability.
The pinned Go JSON ACME issuer does not separately inherit the TLS-app field
inside its provisioner. Supported native ACME server validation is independent
of that remaining issuer capability.
