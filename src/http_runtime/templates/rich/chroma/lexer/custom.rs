use super::{Engine, Error, Options, Result, State, Token};
use serde_json::Value;
impl Engine<'_> {
    pub(super) fn custom_emit(
        &mut self,
        desc: &Value,
        groups: &[Vec<u8>],
        s: &mut State,
        out: &mut Vec<Token>,
        depth: usize,
    ) -> Result<()> {
        match desc.get("type").and_then(Value::as_str) {
            Some("chroma.localOpsUsingLexerEmitter") => {
                let child = desc["Lexer"]["id"]
                    .as_u64()
                    .and_then(|n| usize::try_from(n).ok())
                    .ok_or("missing bound lexer")?;
                self.tick(1, 28)?;
                let tokens = self.lex_id(
                    child,
                    groups.first().ok_or("missing bound lexer input")?,
                    Options {
                        state: "root".into(),
                        nested: true,
                        ensure_lf: false,
                    },
                    depth + 1,
                )?;
                self.append_tokens(out, tokens)
            }
            Some("chroma.localOpsNamedGroupEmitter") => {
                let emitters = desc["Emitters"]
                    .as_object()
                    .ok_or("missing named group emitters")?;
                let registry = self.registry;
                let program = &registry.db.programs[s.program];
                let named = super::raku_emit::NamedView::new(
                    program,
                    s.named_groups.clone(),
                    s.named_extra.clone(),
                );
                let count = s
                    .named_groups
                    .len()
                    .checked_add(s.named_extra.len())
                    .ok_or(Error::TotalLimit)?;
                if count == 1 {
                    if let Some(emitter) = emitters.get("0") {
                        self.emit(emitter, groups, s, out, depth + 1)?;
                    } else {
                        self.push_token(-11, groups.first().ok_or("missing named root")?, out)?;
                    }
                } else {
                    for number in 1..count {
                        self.tick(1, 0)?;
                        let name = program
                            .caps
                            .get(&(i32::try_from(number).map_err(|_| Error::TotalLimit)?))
                            .and_then(|&slot| program.caplist.get(slot))
                            .map_or("", String::as_str);
                        let group = named.get(name);
                        if let Some(emitter) = emitters.get(name) {
                            if !emitter.is_null() {
                                self.tick(
                                    group.len() as u64,
                                    group.len() + std::mem::size_of::<Vec<u8>>(),
                                )?;
                                let singleton = [group.to_vec()];
                                self.emit(emitter, &singleton, s, out, depth + 1)?;
                            }
                        } else {
                            self.push_token(-11, group, out)?;
                        }
                    }
                }
                Ok(())
            }
            Some("lexers.localOpsRakuEmitter") => {
                let class = desc["TokenClass"]
                    .as_i64()
                    .and_then(|x| i32::try_from(x).ok())
                    .ok_or("invalid colon emitter class")?;
                self.raku_colon(class, s, out, depth)
            }
            Some("chroma.EmitterFunc") => match desc["func"].as_str() {
                Some("github.com/alecthomas/chroma/v2/lexers.quote") => {
                    self.raku_quote(s, out, depth)
                }
                Some("github.com/alecthomas/chroma/v2/lexers.podCode") => {
                    self.raku_pod_code(s, out, depth)
                }
                Some("github.com/alecthomas/chroma/v2/lexers.podConfig") => {
                    self.raku_pod_config(groups.first().ok_or("missing pod config")?, s, out, depth)
                }
                Some("github.com/alecthomas/chroma/v2/lexers.httpContentBlock") => {
                    self.push_token(7000, groups.first().ok_or("missing HTTP content")?, out)
                }
                Some("github.com/alecthomas/chroma/v2/lexers.httpHeaderBlock") => {
                    if groups.len() != 7 {
                        return Err("invalid HTTP header groups".into());
                    }
                    for (group, kind) in
                        groups[1..].iter().zip([2000, 8000, 4000, 8000, 3000, 8000])
                    {
                        self.push_token(kind, group, out)?;
                    }
                    Ok(())
                }
                Some("github.com/alecthomas/chroma/v2/lexers.httpContinuousHeaderBlock") => {
                    if groups.len() != 4 {
                        return Err("invalid HTTP continuation groups".into());
                    }
                    for (group, kind) in groups[1..].iter().zip([8000, 3000, 8000]) {
                        self.push_token(kind, group, out)?;
                    }
                    Ok(())
                }
                _ => Err(Error::Invalid(format!(
                    "Chroma callback not yet ported: {desc}"
                ))),
            },
            _ => Err(Error::Invalid(format!(
                "Chroma callback not yet ported: {desc}"
            ))),
        }
    }
    pub(super) fn custom_mutate(
        &mut self,
        desc: &Value,
        s: &mut State,
        _depth: usize,
    ) -> Result<()> {
        if desc["type"] == "lexers.localOpsRakuMutator" {
            match desc["Kind"].as_str() {
                Some("findBrackets") => {
                    return self.find_raku_brackets(
                        s,
                        desc["TokenClass"]
                            .as_u64()
                            .ok_or("invalid Raku bracket class")?,
                    );
                }
                Some("replaceRule") => {
                    let config = self.replacement(&desc["Rule"])?;
                    return self.replace_rule(s, config);
                }
                Some("popRule") => {
                    let config = self.replacement(&desc["Rule"])?;
                    return self.restore_rule(s, &config);
                }
                _ => {}
            }
        }
        if desc["func"] == "github.com/alecthomas/chroma/v2/lexers.haxePreProcMutator" {
            return self.haxe_mutate(s);
        }
        Err(Error::Invalid(format!(
            "Chroma mutator not yet ported: {desc}"
        )))
    }
}
