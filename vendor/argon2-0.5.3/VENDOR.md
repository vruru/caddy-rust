# Argon2 compatibility backend

RustCrypto argon2 0.5.3, original MIT/Apache-2.0 licenses retained.
Registry package SHA-256: `3c3610892ee6e0cbce8ae2700349fcf8f98adb0dbfbee85aec3c9179d29cc072`.

Only functional source is included; development dependencies and two trailing
unit-test modules are omitted. The opt-in `go-compat` feature preserves the
Go Argon2id v19 algorithm input for existing stored hashes: short or empty
salts, positive output lengths below four bytes, and requested memory below
eight blocks per lane. The existing segment layout already clamps physical
memory to eight blocks per lane while keeping the requested cost in the
initial hash. Zero iterations/lanes and an empty derived key remain rejected.
Without this feature, original parameter validation is unchanged.

The HTTP authentication host validates its PHC record, bounds total work,
reserves aggregate memory before allocating blocks, and zeroizes scratch
memory. It never falls back to a different algorithm on verification errors.
