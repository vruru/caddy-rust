//! Closed record views. The controller prepays URL/vector upper bounds before
//! calling these constructors; unknown persisted record fields stay private.
use super::records::{DbAuthz, DbChallenge, DbOrder, Identifier};
use serde::Serialize;
use serde_json::Value;
#[derive(Serialize)]
pub(super) struct IdentifierView<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    value: &'a str,
}
fn identifier(value: &Identifier) -> IdentifierView<'_> {
    IdentifierView {
        kind: &value.kind,
        value: &value.value,
    }
}
#[derive(Serialize)]
pub(super) struct OrderView<'a> {
    id: &'a str,
    status: &'a str,
    expires: &'a str,
    identifiers: Option<Vec<IdentifierView<'a>>>,
    #[serde(rename = "notBefore")]
    not_before: &'a str,
    #[serde(rename = "notAfter")]
    not_after: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a Value>,
    authorizations: Vec<String>,
    finalize: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate: Option<String>,
}
#[derive(Serialize)]
pub(super) struct ChallengeView<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    status: &'a str,
    token: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    validated: &'a str,
    url: String,
    #[serde(skip_serializing_if = "str::is_empty")]
    target: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a Value>,
}
#[derive(Serialize)]
pub(super) struct AuthzView<'a> {
    identifier: IdentifierView<'a>,
    status: &'a str,
    challenges: Vec<ChallengeView<'a>>,
    wildcard: bool,
    expires: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a Value>,
}
pub(super) fn order<'a>(value: &'a DbOrder, base: &str) -> OrderView<'a> {
    OrderView {
        id: &value.id,
        status: &value.status,
        expires: &value.expires_at,
        identifiers: value
            .identifiers
            .as_ref()
            .map(|v| v.iter().map(identifier).collect()),
        not_before: &value.not_before,
        not_after: &value.not_after,
        error: (!value.error.is_null()).then_some(&value.error),
        authorizations: value
            .authorization_ids
            .iter()
            .flatten()
            .map(|id| format!("{base}/authz/{id}"))
            .collect(),
        finalize: format!("{base}/order/{}/finalize", value.id),
        certificate: (!value.certificate.is_empty())
            .then(|| format!("{base}/certificate/{}", value.certificate)),
    }
}
pub(super) fn challenge<'a>(value: &'a DbChallenge, authz: &str, base: &str) -> ChallengeView<'a> {
    ChallengeView {
        kind: &value.kind,
        status: &value.status,
        token: &value.token,
        validated: &value.validated_at,
        url: format!("{base}/challenge/{authz}/{}", value.id),
        target: &value.target,
        error: (!value.error.is_null()).then_some(&value.error),
    }
}
pub(super) fn authz<'a>(
    value: &'a DbAuthz,
    challenges: &'a [DbChallenge],
    base: &str,
) -> AuthzView<'a> {
    AuthzView {
        identifier: identifier(&value.identifier),
        status: &value.status,
        challenges: challenges
            .iter()
            .map(|c| challenge(c, &value.id, base))
            .collect(),
        wildcard: value.wildcard,
        expires: &value.expires_at,
        error: (!value.error.is_null()).then_some(&value.error),
    }
}
