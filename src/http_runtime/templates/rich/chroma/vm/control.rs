use super::op::*;
use super::{Error, Result, Runner, Step};

impl Runner<'_, '_> {
    pub(super) fn control(&mut self) -> Result<Step> {
        match self.operator {
            STOP => Ok(Step::Stop),

            NOTHING => {
                // noop
                Ok(Step::Backtrack)
            }

            GOTO => {
                let op0 = self.operand(0)?;
                self.go_to(op0)?;
                Ok(Step::Continue)
            }

            TESTREF => {
                let op0 = self.operand(0)?;
                if !self.is_matched(op0) {
                    return Ok(Step::Backtrack);
                }
                self.advance(1)?;
                Ok(Step::Continue)
            }

            LAZYBRANCH => {
                let pos = self.text_pos();
                self.track_push1(pos)?;
                self.advance(1)?;
                Ok(Step::Continue)
            }

            x if x == (LAZYBRANCH | BACK) => {
                self.track_pop()?;
                let peek = self.track_peek()?;
                self.text_to(peek)?;
                let op0 = self.operand(0)?;
                self.go_to(op0)?;
                Ok(Step::Continue)
            }

            SETMARK => {
                let pos = self.text_pos();
                self.stack_push(pos)?;
                self.track_push()?;
                self.advance(0)?;
                Ok(Step::Continue)
            }

            NULLMARK => {
                self.stack_push(-1)?;
                self.track_push()?;
                self.advance(0)?;
                Ok(Step::Continue)
            }

            x if x == (SETMARK | BACK) || x == (NULLMARK | BACK) => {
                self.stack_pop()?;
                Ok(Step::Backtrack)
            }

            GETMARK => {
                self.stack_pop()?;
                let peek1 = self.stack_peek()?;
                self.track_push1(peek1)?;
                let peek2 = self.stack_peek()?;
                self.text_to(peek2)?;
                self.advance(0)?;
                Ok(Step::Continue)
            }

            x if x == (GETMARK | BACK) => {
                self.track_pop()?;
                let peek = self.track_peek()?;
                self.stack_push(peek)?;
                Ok(Step::Backtrack)
            }

            CAPTUREMARK => {
                let op1 = self.operand(1)?;
                if op1 != -1 && !self.is_matched(op1) {
                    return Ok(Step::Backtrack);
                }
                self.stack_pop()?;
                if op1 != -1 {
                    let op0 = self.operand(0)?;
                    let op1 = self.operand(1)?;
                    let peek = self.stack_peek()?;
                    let pos = self.text_pos();
                    self.transfer_capture(op0, op1, peek, pos)?;
                } else {
                    let op0 = self.operand(0)?;
                    let peek = self.stack_peek()?;
                    let pos = self.text_pos();
                    self.capture(op0, peek, pos)?;
                }
                let peek = self.stack_peek()?;
                self.track_push1(peek)?;
                self.advance(2)?;
                Ok(Step::Continue)
            }

            x if x == (CAPTUREMARK | BACK) => {
                self.track_pop()?;
                let peek = self.track_peek()?;
                self.stack_push(peek)?;
                self.uncapture()?;
                let op0 = self.operand(0)?;
                let op1 = self.operand(1)?;
                if op0 != -1 && op1 != -1 {
                    self.uncapture()?;
                }
                Ok(Step::Backtrack)
            }

            BRANCHMARK => {
                self.stack_pop()?;
                let peek = self.stack_peek()?;
                let pos = self.text_pos();
                let matched = pos.checked_sub(peek).ok_or(Error::TotalLimit)?;
                if matched != 0 {
                    let peek = self.stack_peek()?;
                    let pos = self.text_pos();
                    self.track_push2(peek, pos)?;
                    let pos = self.text_pos();
                    self.stack_push(pos)?;
                    let op0 = self.operand(0)?;
                    self.go_to(op0)?;
                } else {
                    let peek = self.stack_peek()?;
                    self.track_push_neg1(peek)?;
                    self.advance(1)?;
                }
                Ok(Step::Continue)
            }

            x if x == (BRANCHMARK | BACK) => {
                self.track_pop_n(2)?;
                self.stack_pop()?;
                let peek1 = self.track_peek_n(1)?;
                self.text_to(peek1)?;
                let peek = self.track_peek()?;
                self.track_push_neg1(peek)?;
                self.advance(1)?;
                Ok(Step::Continue)
            }

            x if x == (BRANCHMARK | BACK2) => {
                self.track_pop()?;
                let peek = self.track_peek()?;
                self.stack_push(peek)?;
                Ok(Step::Backtrack)
            }

            LAZYBRANCHMARK => {
                self.stack_pop()?;
                let old_mark_pos = self.stack_peek()?;
                let pos = self.text_pos();
                if pos != old_mark_pos {
                    if old_mark_pos != -1 {
                        let pos = self.text_pos();
                        self.track_push2(old_mark_pos, pos)?;
                    } else {
                        let pos = self.text_pos();
                        self.track_push2(pos, pos)?;
                    }
                } else {
                    self.track_push_neg2(old_mark_pos, 0)?;
                }
                self.advance(1)?;
                Ok(Step::Continue)
            }

            x if x == (LAZYBRANCHMARK | BACK) => {
                self.track_pop_n(2)?;
                let pos = self.track_peek_n(1)?;
                let peek = self.track_peek()?;
                self.track_push_neg2(peek, 1)?;
                self.stack_push(pos)?;
                self.text_to(pos)?;
                let op0 = self.operand(0)?;
                self.go_to(op0)?;
                Ok(Step::Continue)
            }

            x if x == (LAZYBRANCHMARK | BACK2) => {
                self.track_pop_n(2)?;
                let old_mark = self.track_peek()?;
                let needs_pop = self.track_peek_n(1)?;
                if needs_pop != 0 {
                    self.stack_pop()?;
                }
                self.stack_push(old_mark)?;
                Ok(Step::Backtrack)
            }

            SETCOUNT => {
                let pos = self.text_pos();
                let op0 = self.operand(0)?;
                self.stack_push2(pos, op0)?;
                self.track_push()?;
                self.advance(1)?;
                Ok(Step::Continue)
            }

            NULLCOUNT => {
                let op0 = self.operand(0)?;
                self.stack_push2(-1, op0)?;
                self.track_push()?;
                self.advance(1)?;
                Ok(Step::Continue)
            }

            x if x == (SETCOUNT | BACK) => {
                self.stack_pop_n(2)?;
                Ok(Step::Backtrack)
            }

            x if x == (NULLCOUNT | BACK) => {
                self.stack_pop_n(2)?;
                Ok(Step::Backtrack)
            }

            BRANCHCOUNT => {
                self.stack_pop_n(2)?;
                let mark = self.stack_peek()?;
                let count = self.stack_peek_n(1)?;
                let pos = self.text_pos();
                let matched = pos.checked_sub(mark).ok_or(Error::TotalLimit)?;
                let op1 = self.operand(1)?;
                if count >= op1 || (matched == 0 && count >= 0) {
                    self.track_push_neg2(mark, count)?;
                    self.advance(2)?;
                } else {
                    self.track_push1(mark)?;
                    let pos = self.text_pos();
                    self.stack_push2(pos, count.checked_add(1).ok_or(Error::TotalLimit)?)?;
                    let op0 = self.operand(0)?;
                    self.go_to(op0)?;
                }
                Ok(Step::Continue)
            }

            x if x == (BRANCHCOUNT | BACK) => {
                self.track_pop()?;
                self.stack_pop_n(2)?;
                let count = self.stack_peek_n(1)?;
                if count > 0 {
                    let mark = self.stack_peek()?;
                    self.text_to(mark)?;
                    let peek = self.track_peek()?;
                    let count = self.stack_peek_n(1)?;
                    self.track_push_neg2(peek, count.checked_sub(1).ok_or(Error::TotalLimit)?)?;
                    self.advance(2)?;
                    return Ok(Step::Continue);
                }
                let peek = self.track_peek()?;
                let count = self.stack_peek_n(1)?;
                self.stack_push2(peek, count.checked_sub(1).ok_or(Error::TotalLimit)?)?;
                Ok(Step::Backtrack)
            }

            x if x == (BRANCHCOUNT | BACK2) => {
                self.track_pop_n(2)?;
                let peek = self.track_peek()?;
                let peek1 = self.track_peek_n(1)?;
                self.stack_push2(peek, peek1)?;
                Ok(Step::Backtrack)
            }

            LAZYBRANCHCOUNT => {
                self.stack_pop_n(2)?;
                let mark = self.stack_peek()?;
                let count = self.stack_peek_n(1)?;
                if count < 0 {
                    self.track_push_neg1(mark)?;
                    let pos = self.text_pos();
                    self.stack_push2(pos, count.checked_add(1).ok_or(Error::TotalLimit)?)?;
                    let op0 = self.operand(0)?;
                    self.go_to(op0)?;
                } else {
                    let pos = self.text_pos();
                    self.track_push3(mark, count, pos)?;
                    self.advance(2)?;
                }
                Ok(Step::Continue)
            }

            x if x == (LAZYBRANCHCOUNT | BACK) => {
                self.track_pop_n(3)?;
                let mark = self.track_peek()?;
                let textpos = self.track_peek_n(2)?;
                let count = self.track_peek_n(1)?;
                let op1 = self.operand(1)?;
                if count < op1 && textpos != mark {
                    self.text_to(textpos)?;
                    let new_count = self
                        .track_peek_n(1)?
                        .checked_add(1)
                        .ok_or(Error::TotalLimit)?;
                    self.stack_push2(textpos, new_count)?;
                    self.track_push_neg1(mark)?;
                    let op0 = self.operand(0)?;
                    self.go_to(op0)?;
                    Ok(Step::Continue)
                } else {
                    let peek = self.track_peek()?;
                    let count = self.track_peek_n(1)?;
                    self.stack_push2(peek, count)?;
                    Ok(Step::Backtrack)
                }
            }

            x if x == (LAZYBRANCHCOUNT | BACK2) => {
                self.track_pop()?;
                self.stack_pop_n(2)?;
                let peek = self.track_peek()?;
                let count = self.stack_peek_n(1)?;
                self.stack_push2(peek, count.checked_sub(1).ok_or(Error::TotalLimit)?)?;
                Ok(Step::Backtrack)
            }

            SETJUMP => {
                let tp = self.track_pos();
                let cp = self.crawl_pos();
                self.stack_push2(tp, cp)?;
                self.track_push()?;
                self.advance(0)?;
                Ok(Step::Continue)
            }

            x if x == (SETJUMP | BACK) => {
                self.stack_pop_n(2)?;
                Ok(Step::Backtrack)
            }

            BACKJUMP => {
                self.stack_pop_n(2)?;
                let tp = self.stack_peek()?;
                self.track_to(tp)?;
                let cp_target = self.stack_peek_n(1)?;
                while self.crawl_pos() != cp_target {
                    self.uncapture()?;
                }
                Ok(Step::Backtrack)
            }

            FOREJUMP => {
                self.stack_pop_n(2)?;
                let tp = self.stack_peek()?;
                self.track_to(tp)?;
                let cp = self.stack_peek_n(1)?;
                self.track_push1(cp)?;
                self.advance(0)?;
                Ok(Step::Continue)
            }

            x if x == (FOREJUMP | BACK) => {
                self.track_pop()?;
                let cp_target = self.track_peek()?;
                while self.crawl_pos() != cp_target {
                    self.uncapture()?;
                }
                Ok(Step::Backtrack)
            }

            _ => Ok(Step::NotHandled),
        }
    }
}
