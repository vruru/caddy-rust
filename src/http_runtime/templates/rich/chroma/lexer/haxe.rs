use super::{Engine, Error, Result, State};
use std::mem::size_of;

pub(super) struct SavedStack {
    pub values: Vec<String>,
    pub capacity: usize,
    pub identity: u64,
}
impl Engine<'_> {
    pub(super) fn clone_stack(&mut self, values: &[String]) -> Result<Vec<String>> {
        let bytes = values.iter().try_fold(
            values
                .len()
                .checked_mul(size_of::<String>())
                .ok_or(Error::TotalLimit)?,
            |sum, s| sum.checked_add(s.len()).ok_or(Error::TotalLimit),
        )?;
        self.tick(values.len() as u64, bytes)?;
        let mut out = Vec::new();
        out.try_reserve_exact(values.len())
            .map_err(|_| Error::TotalLimit)?;
        for value in values {
            out.push(value.clone());
        }
        Ok(out)
    }
    /// Model writes visible through saved Go slice headers, while retaining a
    /// normal Rust Vec for the current interpreter stack. Only Haxe saves views.
    pub(super) fn prepare_stack_push(&mut self, s: &mut State, name: &str) -> Result<()> {
        let slot = s.stack.len();
        let cap = gotmpl::go_slice_capacity(
            s.stack_capacity,
            slot.checked_add(1).ok_or(Error::TotalLimit)?,
            16,
            true,
        )
        .ok_or(Error::TotalLimit)?;
        if cap != s.stack_capacity {
            s.stack_capacity = cap;
            s.next_stack_identity = s
                .next_stack_identity
                .checked_add(1)
                .ok_or(Error::TotalLimit)?;
            s.stack_identity = s.next_stack_identity;
        } else {
            for saved in &mut s.haxe {
                self.tick(1, 0)?;
                if saved.identity == s.stack_identity
                    && let Some(value) = saved.values.get_mut(slot)
                    && value != name
                {
                    self.tick(1, name.len())?;
                    *value = name.to_owned();
                    s.revision = s.revision.checked_add(1).ok_or(Error::TotalLimit)?;
                }
            }
        }
        Ok(())
    }
    pub(super) fn reset_stack(&mut self, s: &mut State) -> Result<()> {
        let initial = self.clone_stack(std::slice::from_ref(&s.initial))?;
        s.stack = initial;
        s.stack_capacity = 1;
        s.next_stack_identity = s
            .next_stack_identity
            .checked_add(1)
            .ok_or(Error::TotalLimit)?;
        s.stack_identity = s.next_stack_identity;
        Ok(())
    }
    pub(super) fn haxe_mutate(&mut self, s: &mut State) -> Result<()> {
        let groups = s.full_groups.clone();
        match groups
            .get(2)
            .ok_or("missing Haxe preprocessor group")?
            .as_slice()
        {
            b"if" => {
                let values = self.clone_stack(&s.stack)?;
                self.tick(1, size_of::<SavedStack>())?;
                s.haxe.try_reserve_exact(1).map_err(|_| Error::TotalLimit)?;
                s.haxe.push(SavedStack {
                    values,
                    capacity: s.stack_capacity,
                    identity: s.stack_identity,
                });
                s.revision = s.revision.checked_add(1).ok_or(Error::TotalLimit)?;
                self.push_state(s, "preproc-expr")?;
            }
            b"else" | b"elseif" => {
                if let Some(saved) = s.haxe.last() {
                    let values = self.clone_stack(&saved.values)?;
                    s.stack = values;
                    s.stack_capacity = saved.capacity;
                    s.stack_identity = saved.identity;
                }
                if groups[2] == b"elseif" {
                    self.push_state(s, "preproc-expr")?;
                }
            }
            b"end" => {
                if s.haxe.pop().is_some() {
                    s.revision = s.revision.checked_add(1).ok_or(Error::TotalLimit)?;
                }
            }
            b"error" => self.push_state(s, "preproc-error")?,
            _ => {}
        }
        Ok(())
    }
}
