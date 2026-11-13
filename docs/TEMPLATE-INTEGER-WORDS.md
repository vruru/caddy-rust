# Template integer word views

The native text-template `*big.Int` projection exposes `Bits` as `[]big.Word`
and accepts `SetBits` from an admitted word view or nil. Words use the actual
64-bit scalar backing of that template-private integer. `SetBits` adopts its
visible header, removes high zero words and makes the receiver nonnegative.
It does not silently copy the supplied words into an unrelated integer.
Mutations through receivers sharing a backing are visible in both directions;
slices retain their own length and capacity. An allocation that exceeds an old
view's capacity gives the receiver a new backing while the old view remains
valid.

Word indexing and range variables retain addressable element references until
the normal template observation or function-argument boundary. A subsequent
integer write can therefore change a previously selected element. Interface
copies, including collection and ordinary formatting inputs, retain the Go
value-copy rules at their respective boundaries. Only this concrete word
factory opts into the element-reference hook. Persistent collection storage
continues to reject retained field references, and generic Values mutations
continue to accept only proven edge-free scalars. No other X.509, TLS or
arbitrary host object gains a dynamic-field interpretation from its type name.

ASN.1 initialization accounts for the actual encoded INTEGER length, including
its positive sign byte and the complement/add-one path for negative values.
RSA magnitude, fixed-width elliptic coordinates and the pinned named-curve
constant constructors keep their corresponding initial capacities. Spare words
are initialized safely. Prefix writes retain actual initialized tail words;
negative bit operations and bounded Binomial history commit the actual staged
intermediate prefix before a backing detaches. This does not promise every
unexported scratch-allocation choice or spare-capacity byte of every Go release.
The documented aliasing and numerical results are the supported contract;
unknown internal workspace is never fabricated or read from uninitialized or
cross-request storage.

All number reads reconstruct the magnitude from the current word view. A cached
number cannot conceal a write through another receiver. Multi-output operations
stage their numeric results, word writes and metadata before acquiring the
actual receiver locks in canonical order. Every owner, epoch and backing
version is validated before the first write. The shared atomic ticket may reuse
an allocation only after all locks are held and the entire old backing is
edge-free, exclusive and has no Weak observer. Retained snapshots or opaque old
values select prepaid COW. Old graph-bearing payloads and tickets retire after
the number locks are released. A stale version, invalid argument, rejected
budget or retired owner cannot partially update the outputs.

The existing render work allowance, deadline, cancellation, value/output limits
and memory account remain in force. Internal flat limb storage validates every
actual scalar and type without applying the unrelated recursive object-graph
node limit. Exposing a large `Bits` value still incurs the normal evaluator
value limits. Unsigned method parameters use an explicit unsigned signature;
negative or overflowing ideal constants and typed int/big.Word arguments are
not silently converted to uint. A huge right shift and a huge left shift of
zero can finish without allocating the nominal shift width. A nonzero left
shift that exceeds the existing resource allowance fails before allocation.
The no_std atomic mutation entry point explicitly rejects nonempty writes.

The word registry belongs to the same closed request-template factory and keeps
real cells alive until that factory retires. Its backing budget gates and
addressable-element producers retain only Weak owner links. Nested `include`
frames share the admitted render owner and preserve passed word aliases. The
actual worker and response Tree retain their existing resource lifetime; a
client disconnect does not manufacture a successful mutation or detach work
from its owner. Public arbitrary host callbacks and raw Value escape outside
this closed online factory set are not covered by a whole-engine memory bound.

Additional actual TLS 1.3 HTTP/2 and HTTP/3 checks use required, verified client certificates. Repeated requests and eight overlapping streams on one connection retain independent integer views, while original DER, signature verification and verified chains remain unchanged. These protocol checks supplement the TLS 1.2/1.3 HTTP/1 template cases; they do not establish every protocol/receiver combination.

These values deliberately remain private to the current template render.
They cannot mutate the authenticated connection snapshot, original certificate
DER, trust facts or the next request on the same TLS connection. This isolation
can differ from Go's connection-wide mutable projections. Existing numerical
repairs for decoded negative zero and negative modular exponents remain
intentional differences; word-view support does not undo them. Complete Go
standard-library receiver coverage and the optional vendor HTML-template
feature are separate compatibility work.
