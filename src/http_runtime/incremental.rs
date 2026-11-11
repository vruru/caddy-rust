// Shared RFC 10036 request/response flag detection.
pub(super) fn is_enabled(headers: &http::HeaderMap) -> bool {
    let mut entries = headers.get_all("incremental").iter();
    let Some(value) = entries.next() else {
        return false;
    };
    if entries.next().is_some() {
        return false;
    }
    if value.as_bytes() == b"?1" {
        return true;
    }
    struct TrueItem(bool);
    impl<'de> sfv::visitor::ParameterVisitor<'de> for TrueItem {
        type Out = bool;
        type Error = std::convert::Infallible;
        fn parameter(
            &mut self,
            _: &'de sfv::KeyRef,
            _: sfv::BareItemFromInput<'de>,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
        fn finish(self) -> Result<Self::Out, Self::Error> {
            Ok(self.0)
        }
    }
    sfv::Parser::new(value.as_bytes())
        .parse_item_with_visitor(|bare| {
            Ok::<_, std::convert::Infallible>(TrueItem(matches!(
                bare,
                sfv::BareItemFromInput::Boolean(true)
            )))
        })
        .unwrap_or(false)
}
