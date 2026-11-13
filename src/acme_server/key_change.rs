//! RFC8555 account-key rollover. Both signatures are verified before one
//! transaction swaps the key/index; the upstream501 is not copied.
use super::{
    bolt::Budget,
    controller::{ResponseData, account_view, json, problem},
    jws::{self, Signed, VerificationKey},
    records::DbAccount,
    resources::Meter,
    store::Database,
};
use anyhow::{Result, anyhow};
use serde::Deserialize;
use serde_json::value::RawValue;
#[derive(Deserialize)]
struct Payload {
    #[serde(default)]
    account: Option<String>,
    #[serde(rename = "oldKey", default)]
    old_key: Option<Box<RawValue>>,
}
pub(super) fn process(
    db: &mut Database,
    meter: &mut Meter,
    outer: &Signed,
    account: &DbAccount,
    old: &VerificationKey,
    base: &str,
    response: &mut ResponseData,
) -> Result<()> {
    let inner = match jws::parse(&outer.payload, meter) {
        Ok(inner) => inner,
        Err(jws::Error::Resource(error)) => return Err(error.into()),
        Err(_) => {
            problem(
                response,
                meter,
                "malformed",
                400,
                "invalid inner key-change JWS",
            )?;
            return Ok(());
        }
    };
    if inner.header.nonce.is_some()
        || inner.header.kid.is_some()
        || inner.header.jwk.is_none()
        || inner.header.url != outer.header.url
    {
        problem(
            response,
            meter,
            "malformed",
            400,
            "invalid inner key-change binding",
        )?;
        return Ok(());
    }
    let new = match VerificationKey::from_jwk(inner.header.jwk.as_deref().expect("checked"), meter)
    {
        Ok(key) => key,
        Err(jws::Error::Resource(error)) => return Err(error.into()),
        Err(_) => {
            problem(response, meter, "malformed", 400, "invalid new account key")?;
            return Ok(());
        }
    };
    if let Err(error) = new.verify(&inner, meter) {
        if let jws::Error::Resource(error) = error {
            return Err(error.into());
        }
        problem(
            response,
            meter,
            "malformed",
            400,
            "new key signature failed",
        )?;
        return Ok(());
    }
    meter.charge(
        inner
            .payload
            .len()
            .checked_mul(64)
            .and_then(|n| n.checked_add(4096))
            .ok_or_else(|| anyhow!("key-change capacity"))?,
    )?;
    let payload: Payload = match serde_json::from_slice(&inner.payload) {
        Ok(payload) => payload,
        Err(_) => {
            problem(
                response,
                meter,
                "malformed",
                400,
                "invalid key-change object",
            )?;
            return Ok(());
        }
    };
    if payload.account.as_deref() != outer.header.kid.as_deref() {
        problem(
            response,
            meter,
            "malformed",
            400,
            "account binding mismatch",
        )?;
        return Ok(());
    }
    let Some(raw) = payload.old_key else {
        problem(response, meter, "malformed", 400, "old key missing")?;
        return Ok(());
    };
    let claimed = match VerificationKey::from_jwk(&raw, meter) {
        Ok(key) => key,
        Err(jws::Error::Resource(error)) => return Err(error.into()),
        Err(_) => {
            problem(response, meter, "malformed", 400, "invalid old key")?;
            return Ok(());
        }
    };
    if claimed.thumbprint() != old.thumbprint() {
        problem(response, meter, "malformed", 400, "old key mismatch")?;
        return Ok(());
    }
    let mut key: serde_json::Value =
        serde_json::from_str(inner.header.jwk.as_ref().expect("checked").get())?;
    key.as_object_mut()
        .ok_or_else(|| anyhow!("new key is not an object"))?
        .insert(
            "kid".into(),
            serde_json::Value::String(new.thumbprint().into()),
        );
    let result = db.transaction(meter, |tx| {
        if let Some(id) = tx.index(b"acme_keyID_accountID_index", new.thumbprint().as_bytes())? {
            return Ok(Err(id));
        }
        let mut current = tx
            .get::<DbAccount>(b"acme_accounts", account.id.as_bytes())?
            .ok_or(super::store::Error::Record("account disappeared"))?;
        let indexed = tx.index(b"acme_keyID_accountID_index", old.thumbprint().as_bytes())?;
        if indexed.as_deref() != Some(account.id.as_str()) || current.status != "valid" {
            return Err(super::store::Error::Record(
                "account changed during key rollover",
            ));
        }
        current.key = key;
        tx.put(b"acme_accounts", current.id.as_bytes(), &current)?;
        tx.delete(b"acme_keyID_accountID_index", old.thumbprint().as_bytes())?;
        tx.put_raw(
            b"acme_keyID_accountID_index",
            new.thumbprint().as_bytes(),
            current.id.as_bytes(),
        )?;
        Ok(Ok(current))
    })?;
    match result {
        Ok(account) => {
            meter.charge(base.len() + 4096)?;
            response.location = Some(format!("{base}/account/{}", account.id));
            response.body = account_view(&account, base, meter)?;
        }
        Err(existing) => {
            problem(
                response,
                meter,
                "malformed",
                409,
                "new key already belongs to an account",
            )?;
            response.location = Some(format!("{base}/account/{existing}"));
        }
    }
    Ok(())
}
