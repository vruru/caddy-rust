//! URI SANs enter the same render-private Go *url.URL factory as request URLs.
//! Initial certificate admission stays separate from later ordinary URL methods.
use super::{Factory, RenderResult};
use gotmpl::Value;
use std::sync::Arc;

pub(super) fn value(factory: &Arc<Factory>, raw: &str) -> RenderResult<Value> {
    super::super::super::request_url::certificate_value(raw.as_bytes(), &factory.owner()?)
}
