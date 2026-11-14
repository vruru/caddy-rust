# File server status overrides

The native `file_server` handler accepts `status_code` using Caddy's WeakString JSON decoding. The original JSON remains unchanged in admin configuration exports. Strings containing placeholders are expanded for each request using the existing request replacer; the value is not expanded during configuration preparation.

For an opened file, the override is selected after method and MIME handling, before conditional and range processing. It overrides every content response status, including 304, 412 and 416. Missing files, pass-through, directory redirects, directory browsing and the earlier method rejection keep their existing behavior and do not evaluate this field.

An empty or omitted value inherits the actual error-handler context status. A nonempty value takes priority: signed decimal zero and negative values clear that inherited override. Parsing follows native-width signed decimal rules, including overflow checks; whitespace, non-decimal text and an empty expansion fail the request with 500. A mutable variable named `http.error.status_code` does not create an error-handler context.

Positive values from 100 through 999 are accepted. Invalid positive values fail safely with 500 instead of reproducing Go's `WriteHeader` panic. Informational values other than 101 produce an interim head followed by a final 200, preserving shared writer headers and the existing header/encoding wrapper order. The existing informational count and byte limits still apply. Status 101 uses the existing HTTP/1.1-only switch policy; other HTTP versions fail safely with 500.

This field reuses the existing request placeholder providers. It does not add the globally unsupported `{file.*}` provider. Gzip encoders and transport framing need not produce identical compressed bytes or choose the same legal Content-Length/chunked framing as Go. A HEAD response may omit Content-Length; any native length it supplies must describe the corresponding selected representation.
