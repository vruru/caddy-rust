# Functional source scope

Public source excludes upstream unit-test-only Rust items and external test
modules. Removal evaluates cfg with only `test=false`; unknown feature/platform
conditions and mixed functional branches are preserved. No normal feature is
assumed false. Original complete sources and private validation remain outside
the repository. Development-only targets/dependencies are excluded.
