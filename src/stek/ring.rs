use super::config::Settings;
use super::go_gob::Persisted;
use anyhow::{Result, anyhow};
use std::time::{Duration, SystemTime};
use zeroize::Zeroizing;

pub(super) fn rotate(
    previous: Option<&Persisted>,
    settings: &Settings,
    now: SystemTime,
) -> Result<Persisted> {
    let keep = previous
        .map_or(0, |previous| previous.keys.len())
        .min(settings.max_keys() - 1);
    // Reserve final capacity before writing a new secret.
    let mut keys = Zeroizing::new(vec![[0; 32]; 1 + keep]);
    aws_lc_rs::rand::fill(&mut keys[0])
        .map_err(|_| anyhow!("unable to generate a session ticket key"))?;
    if let Some(previous) = previous {
        keys[1..].copy_from_slice(&previous.keys[..keep]);
    }
    let next = now
        .checked_add(settings.rotation_interval())
        .ok_or_else(|| anyhow!("session ticket rotation date out of range"))?;
    Ok(Persisted {
        keys,
        last: now,
        next,
    })
}

pub(super) fn bounded_view(
    previous: &Persisted,
    settings: &Settings,
    recompute_next: bool,
) -> Result<Persisted> {
    let next = if recompute_next {
        previous
            .last
            .checked_add(settings.rotation_interval())
            .ok_or_else(|| anyhow!("session ticket rotation date out of range"))?
    } else {
        previous.next
    };
    let keep = previous.keys.len().min(settings.max_keys());
    let mut keys = Zeroizing::new(vec![[0; 32]; keep]);
    keys.copy_from_slice(&previous.keys[..keep]);
    Ok(Persisted {
        keys,
        last: previous.last,
        next,
    })
}

pub(super) fn allowed_at(snapshot: &Persisted, settings: &Settings, now: SystemTime) -> bool {
    // A stalled rotating store never causes indefinite resumption with a
    // stale ring. The old cert still supports an ordinary full handshake.
    let grace = settings
        .rotation_interval()
        .saturating_mul(settings.max_keys().saturating_sub(1) as u32)
        .max(settings.rotation_interval())
        .max(Duration::from_secs(30))
        .min(Duration::from_secs(7 * 86400));
    snapshot
        .next
        .checked_add(grace)
        .is_some_and(|expiry| now < expiry)
}
