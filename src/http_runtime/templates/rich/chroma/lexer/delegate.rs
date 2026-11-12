use super::{Engine, Error, Options, Result, Token};
use std::vec::Vec;

#[derive(Debug)]
struct Insertion {
    start: i64,
    end: i64,
    tokens: Vec<Token>,
}

impl Engine<'_> {
    pub(super) fn delegate(
        &mut self,
        root: usize,
        language: usize,
        input: &[u8],
        options: Options,
        depth: usize,
    ) -> Result<Vec<Token>> {
        let lang_opts = self.clone_options(&options)?;
        let tokens = self.lex_coalesced(language, input, lang_opts, depth)?;
        let mut others: Vec<u8> = Vec::new();
        let mut insertions: Vec<Insertion> = Vec::new();
        let mut offset: i64 = 0;
        let mut last_kind: Option<i32> = None;

        for token in tokens {
            let kind = token.kind;
            let length = i64::try_from(token.text.len()).map_err(|_| Error::TotalLimit)?;
            if kind == -12 {
                if last_kind.is_some()
                    && last_kind != Some(-12)
                    && let Some(insert) = insertions.last_mut()
                {
                    insert.end = offset;
                }
                self.append_bytes(&mut others, &token.text)?;
            } else {
                if last_kind.is_none() || last_kind == Some(-12) {
                    self.tick(1, std::mem::size_of::<Insertion>())?;
                    insertions
                        .try_reserve_exact(1)
                        .map_err(|_| Error::TotalLimit)?;
                    insertions.push(Insertion {
                        start: offset,
                        end: 0,
                        tokens: Vec::new(),
                    });
                }
                let insert = insertions.last_mut().ok_or(Error::TotalLimit)?;
                self.push_existing(&mut insert.tokens, token)?;
            }
            last_kind = Some(kind);
            offset = offset.checked_add(length).ok_or(Error::TotalLimit)?;
        }

        if insertions.is_empty() {
            return self.lex_id(root, input, options, depth);
        }
        let root_tokens = self.lex_coalesced(root, &others, options, depth)?;
        let mut out: Vec<Token> = Vec::new();
        offset = 0; // Reset offset for output text position

        let mut t_iter = root_tokens.into_iter();
        let mut i_iter = insertions.into_iter();

        let mut t: Option<Token> = t_iter.next();
        let mut i: Option<Insertion> = i_iter.next();

        while t.is_some() || i.is_some() {
            let t_len = t.as_ref().map(|tk| tk.text.len() as i64).unwrap_or(0);

            let take_insertion = match (&t, &i) {
                (None, _) => true, // t is EOF
                (Some(_), Some(ins)) => {
                    let sum = offset.checked_add(t_len).ok_or(Error::TotalLimit)?;
                    ins.start < sum
                }
                (Some(_), None) => false, // t exists, i is None
            };

            if take_insertion {
                let ins = i.take().ok_or(Error::TotalLimit)?;

                let l: Option<Token>;
                let r: Option<Token>;

                if let Some(current_t) = t.take() {
                    let diff = ins.start.checked_sub(offset).ok_or(Error::TotalLimit)?;
                    (l, r) = self.split_token(Some(current_t), diff)?;
                } else {
                    l = None;
                    r = None;
                }
                if let Some(l_tok) = l {
                    let l_len = l_tok.text.len() as i64;
                    self.push_existing(&mut out, l_tok)?;
                    offset = offset.checked_add(l_len).ok_or(Error::TotalLimit)?;
                }
                self.append_tokens(&mut out, ins.tokens)?;
                let delta = ins.end.checked_sub(ins.start).ok_or(Error::TotalLimit)?;
                offset = offset.checked_add(delta).ok_or(Error::TotalLimit)?;
                if r.is_none() {
                    t = t_iter.next();
                } else {
                    t = r;
                }

                i = i_iter.next();
            } else {
                if let Some(tok) = t.take() {
                    let tok_len = tok.text.len() as i64;
                    self.push_existing(&mut out, tok)?;
                    offset = offset.checked_add(tok_len).ok_or(Error::TotalLimit)?;
                }
                t = t_iter.next();
            }
        }

        Ok(out)
    }
}
