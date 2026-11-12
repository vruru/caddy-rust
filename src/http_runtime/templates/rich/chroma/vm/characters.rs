use super::op::*;
use super::{Result, Runner, Step};

impl Runner<'_, '_> {
    pub(super) fn characters(&mut self) -> Result<Step> {
        match self.operator {
            BOL => {
                if self.left_chars() > 0 && self.char_at(self.text_pos() - 1)? != '\n' as i32 {
                    return Ok(Step::Backtrack);
                }
                self.advance(0)?;
                Ok(Step::Continue)
            }
            EOL => {
                if self.right_chars() > 0 && self.char_at(self.text_pos())? != '\n' as i32 {
                    return Ok(Step::Backtrack);
                }
                self.advance(0)?;
                Ok(Step::Continue)
            }
            BOUNDARY => {
                if !self.is_boundary(self.text_pos(), false) {
                    return Ok(Step::Backtrack);
                }
                self.advance(0)?;
                Ok(Step::Continue)
            }
            NONBOUNDARY => {
                if self.is_boundary(self.text_pos(), false) {
                    return Ok(Step::Backtrack);
                }
                self.advance(0)?;
                Ok(Step::Continue)
            }
            E_C_M_A_BOUNDARY => {
                if !self.is_boundary(self.text_pos(), true) {
                    return Ok(Step::Backtrack);
                }
                self.advance(0)?;
                Ok(Step::Continue)
            }
            NON_E_C_M_A_BOUNDARY => {
                if self.is_boundary(self.text_pos(), true) {
                    return Ok(Step::Backtrack);
                }
                self.advance(0)?;
                Ok(Step::Continue)
            }
            BEGINNING => {
                if self.left_chars() > 0 {
                    return Ok(Step::Backtrack);
                }
                self.advance(0)?;
                Ok(Step::Continue)
            }
            START => {
                if self.text_pos() != self.text_start() {
                    return Ok(Step::Backtrack);
                }
                self.advance(0)?;
                Ok(Step::Continue)
            }
            END_Z => {
                let rchars = self.right_chars();
                if rchars > 1 {
                    return Ok(Step::Backtrack);
                }
                if self.is_re2_or_ecma() {
                    if rchars > 0 {
                        return Ok(Step::Backtrack);
                    }
                } else if rchars == 1 && self.char_at(self.text_pos())? != '\n' as i32 {
                    return Ok(Step::Backtrack);
                }

                self.advance(0)?;
                Ok(Step::Continue)
            }
            END => {
                if self.right_chars() > 0 {
                    return Ok(Step::Backtrack);
                }
                self.advance(0)?;
                Ok(Step::Continue)
            }
            ONE => {
                if self.forward_chars() < 1 || self.forward_char_next()? != self.operand(0)? {
                    return Ok(Step::Backtrack);
                }

                self.advance(1)?;
                Ok(Step::Continue)
            }
            NOTONE => {
                if self.forward_chars() < 1 || self.forward_char_next()? == self.operand(0)? {
                    return Ok(Step::Backtrack);
                }

                self.advance(1)?;
                Ok(Step::Continue)
            }
            SET => {
                if self.forward_chars() < 1 {
                    return Ok(Step::Backtrack);
                }
                let setid = self.operand(0)?;
                let ch = self.forward_char_next()?;
                if !self.set_char_in(setid, ch)? {
                    return Ok(Step::Backtrack);
                }

                self.advance(1)?;
                Ok(Step::Continue)
            }
            MULTI => {
                let stringindex = self.operand(0)?;
                if !self.rune_match(stringindex)? {
                    return Ok(Step::Backtrack);
                }

                self.advance(1)?;
                Ok(Step::Continue)
            }
            REF => {
                let capnum = self.operand(0)?;
                if let Some((start, len)) = self.last_capture(capnum)? {
                    if !self.ref_match(start, len)? {
                        return Ok(Step::Backtrack);
                    }
                } else {
                    if !self.is_ecma() {
                        return Ok(Step::Backtrack);
                    }
                }

                self.advance(1)?;
                Ok(Step::Continue)
            }
            ONEREP => {
                let c = self.operand(1)?;
                if (self.forward_chars()) < c {
                    return Ok(Step::Backtrack);
                }

                let ch = self.operand(0)?;
                for _ in 0..c {
                    if self.forward_char_next()? != ch {
                        return Ok(Step::Backtrack);
                    }
                }

                self.advance(2)?;
                Ok(Step::Continue)
            }
            NOTONEREP => {
                let c = self.operand(1)?;
                if (self.forward_chars()) < c {
                    return Ok(Step::Backtrack);
                }
                let ch = self.operand(0)?;

                for _ in 0..c {
                    if self.forward_char_next()? == ch {
                        return Ok(Step::Backtrack);
                    }
                }

                self.advance(2)?;
                Ok(Step::Continue)
            }
            SETREP => {
                let c = self.operand(1)?;
                if (self.forward_chars()) < c {
                    return Ok(Step::Backtrack);
                }

                let setid = self.operand(0)?;

                for _ in 0..c {
                    let ch = self.forward_char_next()?;
                    if !self.set_char_in(setid, ch)? {
                        return Ok(Step::Backtrack);
                    }
                }

                self.advance(2)?;
                Ok(Step::Continue)
            }
            ONELOOP | ONELOOPATOMIC => {
                let mut c = self.operand(1)?;

                let fc = self.forward_chars();
                if c > fc {
                    c = fc;
                }

                let ch = self.operand(0)?;
                let mut i = c;

                while i > 0 {
                    if self.forward_char_next()? != ch {
                        self.backward_next()?;
                        break;
                    }
                    i -= 1;
                }

                if c > i && self.operator == ONELOOP {
                    self.track_push2(c - i - 1, self.text_pos() - self.bump())?;
                }

                self.advance(2)?;
                Ok(Step::Continue)
            }
            NOTONELOOP | NOTONELOOPATOMIC => {
                let mut c = self.operand(1)?;

                let fc = self.forward_chars();
                if c > fc {
                    c = fc;
                }

                let ch = self.operand(0)?;
                let mut i = c;

                while i > 0 {
                    if self.forward_char_next()? == ch {
                        self.backward_next()?;
                        break;
                    }
                    i -= 1;
                }

                if c > i && self.operator == NOTONELOOP {
                    self.track_push2(c - i - 1, self.text_pos() - self.bump())?;
                }

                self.advance(2)?;
                Ok(Step::Continue)
            }
            SETLOOP | SETLOOPATOMIC => {
                let mut c = self.operand(1)?;

                let fc = self.forward_chars();
                if c > fc {
                    c = fc;
                }

                let setid = self.operand(0)?;
                let mut i = c;

                while i > 0 {
                    let ch = self.forward_char_next()?;
                    if !self.set_char_in(setid, ch)? {
                        self.backward_next()?;
                        break;
                    }
                    i -= 1;
                }

                if c > i && self.operator == SETLOOP {
                    self.track_push2(c - i - 1, self.text_pos() - self.bump())?;
                }

                self.advance(2)?;
                Ok(Step::Continue)
            }
            x if x == (ONELOOP | BACK) || x == (NOTONELOOP | BACK) => {
                self.track_pop_n(2)?;
                let i = self.track_peek()?;
                let pos = self.track_peek_n(1)?;

                self.text_to(pos)?;

                if i > 0 {
                    self.track_push2(i - 1, pos - self.bump())?;
                }

                self.advance(2)?;
                Ok(Step::Continue)
            }
            x if x == (SETLOOP | BACK) => {
                self.track_pop_n(2)?;
                let i = self.track_peek()?;
                let pos = self.track_peek_n(1)?;

                self.text_to(pos)?;

                if i > 0 {
                    self.track_push2(i - 1, pos - self.bump())?;
                }

                self.advance(2)?;
                Ok(Step::Continue)
            }
            ONELAZY | NOTONELAZY => {
                let mut c = self.operand(1)?;

                let fc = self.forward_chars();
                if c > fc {
                    c = fc;
                }

                if c > 0 {
                    self.track_push2(c - 1, self.text_pos())?;
                }

                self.advance(2)?;
                Ok(Step::Continue)
            }
            SETLAZY => {
                let mut c = self.operand(1)?;

                let fc = self.forward_chars();
                if c > fc {
                    c = fc;
                }

                if c > 0 {
                    self.track_push2(c - 1, self.text_pos())?;
                }

                self.advance(2)?;
                Ok(Step::Continue)
            }
            x if x == (ONELAZY | BACK) => {
                self.track_pop_n(2)?;
                let pos = self.track_peek_n(1)?;
                self.text_to(pos)?;

                if self.forward_char_next()? != self.operand(0)? {
                    return Ok(Step::Backtrack);
                }

                let i = self.track_peek()?;

                if i > 0 {
                    self.track_push2(i - 1, pos + self.bump())?;
                }

                self.advance(2)?;
                Ok(Step::Continue)
            }
            x if x == (NOTONELAZY | BACK) => {
                self.track_pop_n(2)?;
                let pos = self.track_peek_n(1)?;
                self.text_to(pos)?;

                if self.forward_char_next()? == self.operand(0)? {
                    return Ok(Step::Backtrack);
                }

                let i = self.track_peek()?;

                if i > 0 {
                    self.track_push2(i - 1, pos + self.bump())?;
                }

                self.advance(2)?;
                Ok(Step::Continue)
            }
            x if x == (SETLAZY | BACK) => {
                self.track_pop_n(2)?;
                let pos = self.track_peek_n(1)?;
                self.text_to(pos)?;

                let setid = self.operand(0)?;
                let ch = self.forward_char_next()?;
                if !self.set_char_in(setid, ch)? {
                    return Ok(Step::Backtrack);
                }

                let i = self.track_peek()?;

                if i > 0 {
                    self.track_push2(i - 1, pos + self.bump())?;
                }

                self.advance(2)?;
                Ok(Step::Continue)
            }
            UPDATE_BUMPALONG => {
                self.update_bumpalong()?;
                self.advance(0)?;
                Ok(Step::Continue)
            }
            _ => Ok(Step::NotHandled),
        }
    }
}
