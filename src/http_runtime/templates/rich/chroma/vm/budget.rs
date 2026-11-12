use super::{Error, Result};
use gotmpl::{BudgetAccount, BudgetedBytes};

/// Allocation ownership within the caller's existing template meter.
/// `held` is local to this exclusive owner, never a snapshot of the shared pool.
pub struct Budget {
    account: BudgetAccount,
    held: usize,
}
impl Budget {
    pub fn with_shared(account: BudgetAccount) -> Self { Self { account, held: 0 } }
    pub fn held(&self) -> usize { self.held }
    pub fn charge(&mut self, work: u64, bytes: usize) -> Result<()> {
        let work = usize::try_from(work).map_err(|_| Error::TotalLimit)?;
        self.account.check().map_err(Error::Template)?;
        self.account.charge_work(work).map_err(Error::Template)?;
        let next = self.held.checked_add(bytes).ok_or(Error::TotalLimit)?;
        self.account.reserve(bytes).map_err(Error::Template)?;
        self.held = next;
        Ok(())
    }
    pub fn release(&mut self, bytes: usize) -> Result<()> {
        let next = self.held.checked_sub(bytes).ok_or("Chroma ownership underflow")?;
        self.account.release(bytes).map_err(Error::Template)?;
        self.held = next;
        Ok(())
    }
    pub fn transfer_output(&mut self, bytes: Vec<u8>) -> Result<BudgetedBytes> {
        let next = self.held.checked_sub(bytes.capacity()).ok_or("unreserved Chroma output")?;
        let output = BudgetedBytes::from_account(bytes, &self.account).map_err(Error::Template)?;
        self.held = next;
        Ok(output)
    }
}
impl Drop for Budget {
    fn drop(&mut self) {
        let result = self.account.release(self.held);
        debug_assert!(result.is_ok(), "Chroma allocation ownership imbalance");
        self.held = 0;
    }
}

/// Kept after the owning runner's buffers so they are destroyed before refund.
pub struct Scope<'a> { budget: &'a mut Budget, own: usize }
impl<'a> Scope<'a> {
    pub fn new(budget: &'a mut Budget) -> Self { Self { budget, own: 0 } }
    pub fn held(&self)->usize { self.own }
    pub fn charge(&mut self,work:u64,bytes:usize)->Result<()> {
        let next=self.own.checked_add(bytes).ok_or(Error::TotalLimit)?;
        self.budget.charge(work,bytes)?;self.own=next;Ok(())
    }
    pub fn release(&mut self,bytes:usize)->Result<()> {
        let next=self.own.checked_sub(bytes).ok_or("Chroma scope cannot release its parent's reservation")?;
        self.budget.release(bytes)?;self.own=next;Ok(())
    }
}
impl Drop for Scope<'_> {
    fn drop(&mut self) {
        let result = self.release(self.own);
        debug_assert!(result.is_ok(), "Chroma nested allocation refund failed");
    }
}
