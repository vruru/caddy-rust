# URLPattern 0.6.0

Source: denoland/rust-urlpattern, crates.io urlpattern 0.6.0.
Crate checksum: df16f50ef4cc145211879a3867ba757076b25dfee812040dcb0658bd9ae7904b.
MIT license retained. Only runtime source, manifest and upstream README are included; upstream tests and benchmarks are kept outside the project.

Local change: case-insensitive components use the complete generated expression. The optimized upstream prefix/suffix comparisons did not honor ignore_case; using the configured bounded regexp preserves capture casing without allocating lowercase request copies. Case-sensitive matching keeps its existing optimized path.

Native-regexp expression generation also preserves Go URLPattern's whole-expression noncapturing enclosure with absolute anchors. Case flags stay outside that enclosure; ECMAScript generation is unchanged.
