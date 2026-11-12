use super::{Database, ParameterKind, Program, Result, op::*};
fn ranges(values: &[(i32, i32)]) -> Result<()> {
    let mut end = -1;
    for &(start, last) in values {
        if start < 0 || start > last || last > 0x10ffff || start <= end {
            return Err("invalid generated Unicode range table".into());
        }
        end = last;
    }
    Ok(())
}
fn width(op: i32) -> Result<usize> {
    Ok(match op {
        NOTHING | BOL | EOL | BOUNDARY | NONBOUNDARY | E_C_M_A_BOUNDARY | NON_E_C_M_A_BOUNDARY
        | BEGINNING | START | END_Z | END | NULLMARK | SETMARK | GETMARK | SETJUMP | BACKJUMP
        | FOREJUMP | STOP | UPDATE_BUMPALONG => 1,
        ONE | NOTONE | MULTI | REF | TESTREF | GOTO | NULLCOUNT | SETCOUNT | LAZYBRANCH
        | BRANCHMARK | LAZYBRANCHMARK | PRUNE | SET => 2,
        CAPTUREMARK | BRANCHCOUNT | LAZYBRANCHCOUNT | ONEREP | NOTONEREP | ONELOOP | NOTONELOOP
        | ONELAZY | NOTONELAZY | SETLAZY | SETREP | SETLOOP | ONELOOPATOMIC | NOTONELOOPATOMIC
        | SETLOOPATOMIC => 3,
        _ => return Err("unknown generated regex opcode".into()),
    })
}
fn index(value: i32, len: usize) -> Result<usize> {
    usize::try_from(value)
        .ok()
        .filter(|x| *x < len)
        .ok_or_else(|| "invalid generated regex index".into())
}
impl Program {
    fn validate(&mut self, sets: usize) -> Result<()> {
        self.validated = false;
        self.parameter_kind = None;
        self.parameter_slots.clear();
        self.conditional = self.pattern.contains("(?(");
        if self.codes.is_empty()
            || self.codes.len() > i32::MAX as usize
            || self.capsize == 0
            || self.capsize > i32::MAX as usize
        {
            return Err("invalid regex program dimensions".into());
        }
        if self.options & !(1 | 2 | 4 | 16 | 32 | 64 | 256 | 512 | 1024) != 0
            || self.options & 64 != 0
        {
            return Err("unsupported generated outer regex options".into());
        }
        if self.caps.get(&0) != Some(&0) || self.caps.len() != self.capsize {
            return Err("invalid capture group mapping".into());
        }
        if self.min_required > i32::MAX as usize || self.first_set.is_some_and(|n| n >= sets) {
            return Err("invalid regex first-character optimization".into());
        }
        let mut seen = vec![false; self.capsize];
        for (&number, &slot) in &self.caps {
            if number < 0 || slot >= seen.len() || std::mem::replace(&mut seen[slot], true) {
                return Err("invalid capture group mapping".into());
            }
        }
        if !self.caplist.is_empty() && self.caplist.len() != self.capsize {
            return Err("invalid capture group name list".into());
        }
        for number in self.capnames.values() {
            if !self.caps.contains_key(number) {
                return Err("invalid named capture mapping".into());
            }
        }
        for &set in &self.sets {
            if set >= sets {
                return Err("invalid global character set index".into());
            }
        }
        for string in &self.strings {
            if string.iter().any(|x| *x < 0 || *x > 0x10ffff) {
                return Err("invalid generated regex rune string".into());
            }
        }
        self.starts = vec![false; self.codes.len()];
        let mut pc = 0;
        while pc < self.codes.len() {
            let raw = self.codes[pc];
            if raw < 0 || raw & !(MASK | RTL | CI) != 0 {
                return Err("invalid precompiled opcode modifier".into());
            }
            let n = width(raw & MASK)?;
            let next = pc
                .checked_add(n)
                .filter(|n| *n <= self.codes.len())
                .ok_or("truncated generated regex instruction")?;
            self.starts[pc] = true;
            pc = next;
        }
        pc = 0;
        while pc < self.codes.len() {
            let op = self.codes[pc] & MASK;
            let n = width(op)?;
            let a = if n > 1 { self.codes[pc + 1] } else { 0 };
            let b = if n > 2 { self.codes[pc + 2] } else { 0 };
            match op {
                GOTO | LAZYBRANCH | BRANCHMARK | LAZYBRANCHMARK | BRANCHCOUNT | LAZYBRANCHCOUNT => {
                    let target = index(a, self.codes.len())?;
                    if !self.starts[target] {
                        return Err("regex jump targets an operand".into());
                    }
                }
                ONE | NOTONE | ONEREP | NOTONEREP | ONELOOP | NOTONELOOP | ONELAZY | NOTONELAZY
                | ONELOOPATOMIC | NOTONELOOPATOMIC => {
                    if !(0..=0x10ffff).contains(&a) {
                        return Err("invalid generated regex literal".into());
                    }
                }
                SET | SETREP | SETLOOP | SETLAZY | SETLOOPATOMIC => {
                    index(a, self.sets.len())?;
                }
                MULTI => {
                    index(a, self.strings.len())?;
                }
                REF | TESTREF => {
                    index(a, self.capsize)?;
                }
                CAPTUREMARK => {
                    if a < -1 || b < -1 || (a == -1 && b == -1) {
                        return Err("invalid generated capture instruction".into());
                    }
                    if a >= 0 {
                        index(a, self.capsize)?;
                    }
                    if b >= 0 {
                        index(b, self.capsize)?;
                    }
                }
                _ => {}
            }
            if matches!(
                op,
                ONEREP
                    | NOTONEREP
                    | ONELOOP
                    | NOTONELOOP
                    | ONELAZY
                    | NOTONELAZY
                    | ONELOOPATOMIC
                    | NOTONELOOPATOMIC
                    | SETREP
                    | SETLOOP
                    | SETLAZY
                    | SETLOOPATOMIC
                    | BRANCHCOUNT
                    | LAZYBRANCHCOUNT
            ) && b < 0
            {
                return Err("negative generated repetition limit".into());
            }
            if op != STOP && op != NOTHING && op != GOTO && pc + n >= self.codes.len() {
                return Err("regex program falls off its end".into());
            }
            pc += n;
        }
        self.validated = true;
        Ok(())
    }
}
impl Database {
    pub fn validate(&mut self) -> Result<()> {
        if self.unicode_version != "17.0.0" || self.word.is_empty() || self.ecma_word.is_empty() {
            return Err("missing or mismatched generated Unicode tables".into());
        }
        for table in self.sets.iter().chain([&self.word, &self.ecma_word]) {
            ranges(table)?;
        }
        let mut last = -1;
        for &(key, value) in &self.lower {
            if key <= last || !(0..=0x10ffff).contains(&key) || !(0..=0x10ffff).contains(&value) {
                return Err("invalid generated Unicode lower table".into());
            }
            last = key;
        }
        for program in &mut self.programs {
            program.validate(self.sets.len())?;
        }
        for (name, &index) in &self.dynamic_programs {
            let program = self
                .programs
                .get_mut(index)
                .ok_or("invalid parameter template index")?;
            let (kind, pattern, wanted, capcount) = match name.as_str() {
                "literal" => (
                    ParameterKind::Literal,
                    concat!(r"(?<!(?<!\\)\\)", "\u{e000}\u{e001}"),
                    vec![vec![0xe000, 0xe001]],
                    1,
                ),
                "substitution" => (
                    ParameterKind::Substitution,
                    concat!("(", "\u{e000}\u{e001}", r")((?:\\\\|\\/|.)*?)(", "\u{e000}\u{e001}", ")"),
                    vec![vec![0xe000, 0xe001]],
                    4,
                ),
                "pod" => (
                    ParameterKind::Pod,
                    concat!("\u{e002}\u{e003}", r"=end\s+", "\u{e004}\u{e005}"),
                    vec![
                        vec![0xe002, 0xe003, 61, 101, 110, 100],
                        vec![0xe004, 0xe005],
                    ],
                    1,
                ),
                "placeholder" | "formatter" => continue,
                _ => return Err("unknown parameter template".into()),
            };
            if program.pattern != pattern || program.options != 0 || program.capsize != capcount {
                return Err("mismatched parameter template definition".into());
            }
            for literal in wanted {
                let mut slots = program
                    .strings
                    .iter()
                    .enumerate()
                    .filter(|(_, value)| *value == &literal);
                let slot = slots
                    .next()
                    .map(|(i, _)| i)
                    .ok_or("missing parameter literal")?;
                if slots.next().is_some() {
                    return Err("ambiguous parameter literal".into());
                }
                let mut references = 0;
                for pc in program
                    .starts
                    .iter()
                    .enumerate()
                    .filter_map(|(pc, is_start)| is_start.then_some(pc))
                {
                    let raw = program.codes[pc];
                    if raw & MASK == MULTI && program.codes[pc + 1] as usize == slot {
                        if raw & CI != 0 {
                            return Err("case-insensitive parameter Multi is unsupported".into());
                        }
                        references += 1;
                    }
                }
                if references == 0 {
                    return Err("parameter slot is not a Multi operand".into());
                }
                program.parameter_slots.push(slot);
            }
            program.parameter_kind = Some(kind);
        }
        Ok(())
    }
}
