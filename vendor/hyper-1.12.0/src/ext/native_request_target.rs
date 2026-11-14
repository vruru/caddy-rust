//! Native HTTP/1 raw request-target provenance, separate from normalized Uri.
use bytes::Bytes;
/// Exact request-target bytes admitted by the Native HTTP/1 parser.
#[derive(Clone)]
pub struct NativeRequestTarget(pub Bytes);
impl std::fmt::Debug for NativeRequestTarget{
 fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.debug_struct("NativeRequestTarget").field("bytes",&self.0.len()).finish_non_exhaustive()}
}
