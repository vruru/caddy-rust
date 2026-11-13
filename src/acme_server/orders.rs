use super::{
    bolt::Budget,
    config::Config,
    controller::{ResponseData, json, now, problem, random_id},
    records::{DbAccount, DbAuthz, DbChallenge, DbOrder, Identifier, OrderIndex},
    resources::Meter,
    store::{self, Database, Transaction},
    views,
};
use anyhow::{Result, anyhow};
use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeMap, net::IpAddr};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub(super) enum Action {
    Validate {
        authorization: DbAuthz,
        challenge: DbChallenge,
        key_authorization: String,
    },
    Finalize {
        order: DbOrder,
        csr: crate::cert_cpu::RetainedBytes,
        profile: crate::local_pki::AcmeProfile,
    },
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct NewOrder {
    identifiers: Option<Vec<Identifier>>,
    #[serde(rename = "notBefore")]
    not_before: Option<String>,
    #[serde(rename = "notAfter")]
    not_after: Option<String>,
}
fn parse_time(value: &str) -> store::Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| store::Error::Record("invalid record timestamp"))
}
fn formatted(value: OffsetDateTime) -> Result<String> {
    Ok(value.format(&Rfc3339)?)
}
pub(super) fn authorize_state<B: Budget>(
    tx: &mut Transaction<'_, B>,
    authz: &mut DbAuthz,
    at: OffsetDateTime,
) -> store::Result<()> {
    if matches!(
        authz.status.as_str(),
        "valid" | "invalid" | "deactivated" | "expired" | "revoked"
    ) {
        return Ok(());
    }
    if authz.status != "pending" {
        return Err(store::Error::Record("invalid authorization status"));
    }
    if at > parse_time(&authz.expires_at)? {
        authz.status = "invalid".into();
    } else {
        let mut valid = false;
        for id in authz.challenge_ids.iter().flatten() {
            let challenge = tx
                .get::<DbChallenge>(b"acme_challenges", id.as_bytes())?
                .ok_or(store::Error::Record("missing authorization challenge"))?;
            if challenge.status == "valid" {
                valid = true;
                break;
            }
        }
        if !valid {
            return Ok(());
        }
        authz.status = "valid".into();
        authz.error = Value::Null;
    }
    tx.put(b"acme_authzs", authz.id.as_bytes(), authz)
}
pub(super) fn order_state<B: Budget>(
    tx: &mut Transaction<'_, B>,
    order: &mut DbOrder,
    at: OffsetDateTime,
) -> store::Result<()> {
    if order.status == "valid" || order.status == "invalid" {
        return Ok(());
    }
    if order.status != "pending" && order.status != "ready" {
        return Err(store::Error::Record("invalid order status"));
    }
    if at > parse_time(&order.expires_at)? {
        order.status = "invalid".into();
        order.error = serde_json::json!({"type":"urn:ietf:params:acme:error:malformed","detail":"order has expired","status":400});
    } else {
        let mut pending = false;
        let mut invalid = false;
        for id in order.authorization_ids.iter().flatten() {
            let mut authorization = tx
                .get::<DbAuthz>(b"acme_authzs", id.as_bytes())?
                .ok_or(store::Error::Record("missing order authorization"))?;
            authorize_state(tx, &mut authorization, at)?;
            match authorization.status.as_str() {
                "pending" => pending = true,
                "invalid" | "deactivated" | "expired" | "revoked" => invalid = true,
                "valid" => {}
                _ => return Err(store::Error::Record("invalid authorization status")),
            }
        }
        if invalid || (pending && order.status == "ready") {
            order.status = "invalid".into();
        } else if pending || order.status == "ready" {
            return Ok(());
        } else {
            order.status = "ready".into();
        }
    }
    tx.put(b"acme_orders", order.id.as_bytes(), order)
}
pub(super) fn fresh<B: Budget>(tx: &mut Transaction<'_, B>, table: &[u8]) -> store::Result<String> {
    for _ in 0..8 {
        let id = random_id().map_err(|_| store::Error::Record("random source unavailable"))?;
        if !tx.contains(table, id.as_bytes())? {
            return Ok(id);
        }
    }
    Err(store::Error::Record("identifier collisions"))
}
fn identifiers_valid(values: &[Identifier]) -> bool {
    !values.is_empty()
        && values.len() <= 100
        && values.iter().all(|id| match id.kind.as_str() {
            "ip" => id.value.parse::<IpAddr>().is_ok(),
            "dns" => crate::local_pki::canonical_acme_dns(&id.value).is_ok(),
            _ => false,
        })
}
pub(super) fn process(
    db: &mut Database,
    meter: &mut Meter,
    config: &Config,
    endpoint: &str,
    payload: &[u8],
    account: &DbAccount,
    thumbprint: &str,
    base: &str,
    response: &mut ResponseData,
) -> Result<bool> {
    let at = OffsetDateTime::now_utc().replace_nanosecond(0)?;
    if endpoint == "new-order" {
        let request = match serde_json::from_slice::<NewOrder>(payload) {
            Ok(request) => request,
            Err(_) => {
                problem(response, meter, "malformed", 400, "invalid order request")?;
                return Ok(true);
            }
        };
        let Some(mut identifiers) = request.identifiers.filter(|ids| identifiers_valid(ids)) else {
            problem(
                response,
                meter,
                "malformed",
                400,
                "invalid order identifiers",
            )?;
            return Ok(true);
        };
        for identifier in &mut identifiers {
            identifier.unknown.clear();
        }
        let before = match request.not_before.as_deref() {
            None | Some("0001-01-01T00:00:00Z") => at,
            Some(value) => match OffsetDateTime::parse(value, &Rfc3339) {
                Ok(at) => at,
                Err(_) => {
                    problem(response, meter, "malformed", 400, "invalid notBefore")?;
                    return Ok(true);
                }
            },
        };
        let after = match request.not_after.as_deref() {
            None | Some("0001-01-01T00:00:00Z") => before
                .checked_add(time::Duration::try_from(config.lifetime)?)
                .ok_or_else(|| anyhow!("order time overflow"))?,
            Some(value) => match OffsetDateTime::parse(value, &Rfc3339) {
                Ok(at) => at,
                Err(_) => {
                    problem(response, meter, "malformed", 400, "invalid notAfter")?;
                    return Ok(true);
                }
            },
        };
        let not_before = formatted(
            if request
                .not_before
                .as_deref()
                .is_none_or(|s| s == "0001-01-01T00:00:00Z")
            {
                before - time::Duration::minutes(1)
            } else {
                before
            },
        )?;
        let not_after = formatted(after)?;
        for identifier in &identifiers {
            if !super::policy::allows(config.policy.as_ref(), identifier, meter)? {
                problem(
                    response,
                    meter,
                    "rejectedIdentifier",
                    400,
                    "identifier is not authorized by policy",
                )?;
                return Ok(true);
            }
        }
        let expires = formatted(at + time::Duration::days(1))?;
        let created = now()?;
        meter.charge(
            identifiers
                .len()
                .checked_mul(base.len() * 8 + 16384)
                .ok_or_else(|| anyhow!("order capacity exceeded"))?,
        )?;
        let order = db.transaction(meter, |tx| {
            let id = fresh(tx, b"acme_orders")?;
            let mut authorization_ids = Vec::with_capacity(identifiers.len());
            for identifier in &identifiers {
                let auth_id = fresh(tx, b"acme_authzs")?;
                let token =
                    random_id().map_err(|_| store::Error::Record("random source unavailable"))?;
                let wildcard = identifier.kind == "dns" && identifier.value.starts_with("*.");
                let value = identifier
                    .value
                    .strip_prefix("*.")
                    .unwrap_or(&identifier.value);
                let kinds: &[&str] = if identifier.kind == "ip" {
                    &["http-01", "tls-alpn-01"]
                } else if wildcard {
                    &["dns-01"]
                } else {
                    &["dns-01", "http-01", "tls-alpn-01"]
                };
                let mut challenges = Vec::with_capacity(kinds.len());
                for kind in kinds {
                    if !config.challenges.is_empty()
                        && !config.challenges.iter().any(|ch| ch.name() == *kind)
                    {
                        continue;
                    }
                    let id = fresh(tx, b"acme_challenges")?;
                    let challenge = DbChallenge {
                        id: id.clone(),
                        account_id: account.id.clone(),
                        kind: (*kind).into(),
                        status: "pending".into(),
                        token: token.clone(),
                        value: value.into(),
                        target: String::new(),
                        validated_at: String::new(),
                        created_at: created.clone(),
                        error: Value::Null,
                        unknown: BTreeMap::new(),
                    };
                    tx.put(b"acme_challenges", id.as_bytes(), &challenge)?;
                    challenges.push(id);
                }
                let authorization = DbAuthz {
                    id: auth_id.clone(),
                    account_id: account.id.clone(),
                    identifier: Identifier {
                        kind: identifier.kind.clone(),
                        value: value.into(),
                        unknown: BTreeMap::new(),
                    },
                    status: "pending".into(),
                    token,
                    fingerprint: String::new(),
                    challenge_ids: Some(challenges),
                    wildcard,
                    created_at: created.clone(),
                    expires_at: expires.clone(),
                    error: Value::Null,
                    unknown: BTreeMap::new(),
                };
                tx.put(b"acme_authzs", auth_id.as_bytes(), &authorization)?;
                authorization_ids.push(auth_id);
            }
            let order = DbOrder {
                id: id.clone(),
                account_id: account.id.clone(),
                provisioner_id: format!("acme/{}", config.ca),
                identifiers: Some(identifiers),
                authorization_ids: Some(authorization_ids),
                status: "pending".into(),
                not_before,
                not_after,
                created_at: created,
                expires_at: expires,
                certificate: String::new(),
                error: Value::Null,
                unknown: BTreeMap::new(),
            };
            let old = tx
                .get::<OrderIndex>(b"acme_account_orders_index", account.id.as_bytes())?
                .unwrap_or_default()
                .0
                .unwrap_or_default();
            if old.len() >= 4096 {
                return Err(super::bolt::Error::Limit.into());
            }
            let mut index = Vec::with_capacity(old.len() + 1);
            for old_id in old {
                let mut previous = tx
                    .get::<DbOrder>(b"acme_orders", old_id.as_bytes())?
                    .ok_or(store::Error::Record("missing indexed order"))?;
                if previous.account_id != account.id {
                    return Err(store::Error::Record("foreign indexed order"));
                }
                order_state(tx, &mut previous, at)?;
                if previous.status == "pending" {
                    index.push(old_id);
                }
            }
            index.push(id);
            tx.put(b"acme_orders", order.id.as_bytes(), &order)?;
            tx.put(
                b"acme_account_orders_index",
                account.id.as_bytes(),
                &OrderIndex(Some(index)),
            )?;
            Ok(order)
        })?;
        response.status = 201;
        response.location = Some(format!("{base}/order/{}", order.id));
        response.body = json(&views::order(&order, base), meter)?;
        return Ok(true);
    }
    let parts = endpoint.split('/').collect::<Vec<_>>();
    if parts.len() == 3 && parts[0] == "order" && parts[2] == "finalize" {
        return super::finalize::prepare(
            db, meter, config, parts[1], payload, account, base, response,
        )
        .map(|()| true);
    }
    if parts.len() == 2 && parts[0] == "certificate" {
        return super::finalize::certificate(db, meter, parts[1], payload, account, response)
            .map(|()| true);
    }
    if parts.len() == 3 && parts[0] == "account" && parts[2] == "orders" {
        if parts[1] != account.id {
            problem(
                response,
                meter,
                "unauthorized",
                401,
                "account does not own order list",
            )?;
            return Ok(true);
        }
        if !payload.is_empty() {
            problem(
                response,
                meter,
                "malformed",
                400,
                "POST-as-GET payload must be empty",
            )?;
            return Ok(true);
        }
        let ids = db.transaction(meter, |tx| {
            let mut ids = tx
                .get::<OrderIndex>(b"acme_account_orders_index", account.id.as_bytes())?
                .unwrap_or_default()
                .0
                .unwrap_or_default();
            if ids.len() > 4096 {
                return Err(super::bolt::Error::Limit.into());
            }
            let mut keep = Vec::with_capacity(ids.len());
            for id in ids.drain(..) {
                let mut order = tx
                    .get::<DbOrder>(b"acme_orders", id.as_bytes())?
                    .ok_or(store::Error::Record("missing indexed order"))?;
                order_state(tx, &mut order, at)?;
                if order.status == "pending" {
                    keep.push(id);
                }
            }
            if keep.is_empty() {
                tx.delete(b"acme_account_orders_index", account.id.as_bytes())?;
            } else {
                tx.put(
                    b"acme_account_orders_index",
                    account.id.as_bytes(),
                    &OrderIndex(Some(keep.clone())),
                )?;
            }
            Ok(keep)
        })?;
        meter.charge(ids.len() * (base.len() + 256) + 4096)?;
        let urls = ids
            .iter()
            .map(|id| format!("{base}/order/{id}"))
            .collect::<Vec<_>>();
        response.body = json(&serde_json::json!({"orders":urls}), meter)?;
        return Ok(true);
    }
    if parts.len() == 2 && parts[0] == "order" {
        if !payload.is_empty() {
            problem(
                response,
                meter,
                "malformed",
                400,
                "POST-as-GET payload must be empty",
            )?;
            return Ok(true);
        }
        let order = db.transaction(meter, |tx| {
            let Some(mut order) = tx.get::<DbOrder>(b"acme_orders", parts[1].as_bytes())? else {
                return Ok(None);
            };
            if order.account_id != account.id
                || order.provisioner_id != format!("acme/{}", config.ca)
            {
                return Ok(Some((order, false)));
            }
            order_state(tx, &mut order, at)?;
            Ok(Some((order, true)))
        })?;
        match order {
            None => problem(response, meter, "malformed", 400, "order not found")?,
            Some((_, false)) => problem(
                response,
                meter,
                "unauthorized",
                401,
                "account does not own order",
            )?,
            Some((order, true)) => {
                meter.charge(
                    order.authorization_ids.as_ref().map_or(0, Vec::len) * (base.len() + 256)
                        + 4096,
                )?;
                response.location = Some(format!("{base}/order/{}", order.id));
                response.body = json(&views::order(&order, base), meter)?;
            }
        }
        return Ok(true);
    }
    if parts.len() == 2 && parts[0] == "authz" {
        #[derive(Deserialize)]
        struct Deactivate {
            status: String,
        }
        let deactivate = if payload.is_empty() {
            false
        } else {
            match serde_json::from_slice::<Deactivate>(payload) {
                Ok(request) if request.status == "deactivated" => true,
                _ => {
                    problem(
                        response,
                        meter,
                        "malformed",
                        400,
                        "authorization update must deactivate",
                    )?;
                    return Ok(true);
                }
            }
        };
        let authorization = db.transaction(meter, |tx| {
            let Some(mut auth) = tx.get::<DbAuthz>(b"acme_authzs", parts[1].as_bytes())? else {
                return Ok(None);
            };
            if auth.account_id != account.id {
                return Ok(Some((auth, Vec::new(), false)));
            }
            authorize_state(tx, &mut auth, at)?;
            if deactivate && matches!(auth.status.as_str(), "pending" | "valid") {
                auth.status = "deactivated".into();
                tx.put(b"acme_authzs", auth.id.as_bytes(), &auth)?;
            }
            let mut challenges =
                Vec::with_capacity(auth.challenge_ids.as_ref().map_or(0, Vec::len));
            for id in auth.challenge_ids.iter().flatten() {
                challenges.push(
                    tx.get::<DbChallenge>(b"acme_challenges", id.as_bytes())?
                        .ok_or(store::Error::Record("missing authorization challenge"))?,
                );
            }
            Ok(Some((auth, challenges, true)))
        })?;
        match authorization {
            None => problem(response, meter, "malformed", 400, "authorization not found")?,
            Some((_, _, false)) => problem(
                response,
                meter,
                "unauthorized",
                401,
                "account does not own authorization",
            )?,
            Some((auth, challenges, true)) => {
                meter.charge(challenges.len() * (base.len() + 256) + 4096)?;
                response.body = json(&views::authz(&auth, &challenges, base), meter)?;
            }
        }
        return Ok(true);
    }
    if parts.len() == 3 && parts[0] == "challenge" {
        let pair = db.transaction(meter, |tx| {
            let Some(auth) = tx.get::<DbAuthz>(b"acme_authzs", parts[1].as_bytes())? else {
                return Ok(None);
            };
            let Some(challenge) = tx.get::<DbChallenge>(b"acme_challenges", parts[2].as_bytes())?
            else {
                return Ok(None);
            };
            Ok(Some((auth, challenge)))
        })?;
        let Some((authorization, challenge)) = pair else {
            problem(response, meter, "malformed", 400, "challenge not found")?;
            return Ok(true);
        };
        if authorization.account_id != account.id
            || challenge.account_id != account.id
            || !authorization
                .challenge_ids
                .iter()
                .flatten()
                .any(|id| id == parts[2])
            || challenge.value != authorization.identifier.value
        {
            problem(
                response,
                meter,
                "unauthorized",
                401,
                "account does not own challenge",
            )?;
            return Ok(true);
        }
        if !matches!(authorization.status.as_str(), "pending" | "valid") {
            problem(
                response,
                meter,
                "unauthorized",
                401,
                "authorization is no longer active",
            )?;
            return Ok(true);
        }
        if !payload.is_empty()
            && serde_json::from_slice::<BTreeMap<String, Value>>(payload).is_err()
        {
            problem(
                response,
                meter,
                "malformed",
                400,
                "invalid challenge payload",
            )?;
            return Ok(true);
        }
        if challenge.status == "pending" {
            let key_authorization = format!("{}.{}", challenge.token, thumbprint);
            response.action = Some(Action::Validate {
                authorization,
                challenge,
                key_authorization,
            });
        } else {
            meter.charge(base.len() + 4096)?;
            response.body = json(
                &views::challenge(&challenge, &authorization.id, base),
                meter,
            )?;
        }
        return Ok(true);
    }
    Ok(false)
}
