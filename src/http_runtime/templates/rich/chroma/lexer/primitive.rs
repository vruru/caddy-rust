use super::{Engine, Error, Options, Result, State, Token};
use serde_json::Value;

fn bad() -> Error {
    Error::Invalid("invalid Chroma descriptor".to_owned())
}

impl Engine<'_> {
    pub(super) fn emit(
        &mut self,
        desc: &Value,
        groups: &[Vec<u8>],
        s: &mut State,
        out: &mut Vec<Token>,
        depth: usize,
    ) -> Result<()> {
        self.tick(1, 0)?;
        if depth > 250 {
            return Err(Error::TotalLimit);
        }

        match desc {
            Value::Null => Ok(()),
            Value::Number(n) => {
                let i = n.as_i64().ok_or_else(bad)?;
                let kind = i32::try_from(i).map_err(|_| bad())?;
                if groups.is_empty() {
                    return Err(bad());
                }
                self.push_token(kind, &groups[0], out)?;
                Ok(())
            }
            Value::Object(obj) => {
                let type_val = obj.get("type").ok_or_else(bad)?;
                let type_str = type_val.as_str().ok_or_else(bad)?;

                match type_str {
                    "chroma.byGroupsEmitter" => {
                        let emitters_val = obj.get("Emitters").ok_or_else(bad)?;
                        let emitters_arr = emitters_val.as_array().ok_or_else(bad)?;
                        if emitters_arr.len() != groups.len().saturating_sub(1) {
                            if groups.is_empty() {
                                return Err(bad());
                            }
                            self.push_token(-11, &groups[0], out)?;
                            return Ok(());
                        }
                        for (i, emitter) in emitters_arr.iter().enumerate() {
                            let group = &groups[i + 1];
                            if emitter.is_null() {
                                continue;
                            }

                            self.emit(emitter, std::slice::from_ref(group), s, out, depth + 1)?;
                        }
                        Ok(())
                    }
                    "chroma.usingEmitter" => {
                        let lexer_name_val = obj.get("Lexer").ok_or_else(bad)?;
                        let lexer_name_str = lexer_name_val.as_str().ok_or_else(bad)?;

                        let child = self.lookup(lexer_name_str.as_bytes())?.ok_or_else(bad)?;

                        if groups.is_empty() {
                            return Err(bad());
                        }

                        self.tick(0, 28)?;
                        let opts = Options {
                            state: "root".to_owned(),
                            nested: true,
                            ensure_lf: false,
                        };

                        let tokens = self.lex_id(child, &groups[0], opts, depth + 1)?;
                        self.append_tokens(out, tokens)?;
                        Ok(())
                    }
                    "chroma.usingSelfEmitter" => {
                        let state_name_val = obj.get("State").ok_or_else(bad)?;
                        let state_name_str = state_name_val.as_str().ok_or_else(bad)?;

                        let child = s.lexer;

                        if groups.is_empty() {
                            return Err(bad());
                        }
                        let state_len = state_name_str.len();
                        self.tick(1, state_len + 24)?;
                        let state_owned = state_name_str.to_owned();

                        let opts = Options {
                            state: state_owned,
                            nested: true,
                            ensure_lf: false,
                        };

                        let tokens = self.lex_id(child, &groups[0], opts, depth + 1)?;
                        self.append_tokens(out, tokens)?;
                        Ok(())
                    }
                    "chroma.usingByGroup" => {
                        let sublexer_name_group_val =
                            obj.get("SublexerNameGroup").ok_or_else(bad)?;
                        let code_group_val = obj.get("CodeGroup").ok_or_else(bad)?;
                        let emitters_val = obj.get("Emitters").ok_or_else(bad)?;

                        let sublexer_name_group =
                            sublexer_name_group_val.as_u64().ok_or_else(bad)?;
                        let code_group = code_group_val.as_u64().ok_or_else(bad)?;
                        let emitters_arr = emitters_val.as_array().ok_or_else(bad)?;
                        if emitters_arr.len() != groups.len().saturating_sub(1) {
                            return Err(bad());
                        }
                        let sublexer_name_idx =
                            usize::try_from(sublexer_name_group).map_err(|_| bad())?;
                        if sublexer_name_idx >= groups.len() {
                            return Err(bad());
                        }
                        let sublexer_name_bytes = &groups[sublexer_name_idx];
                        let sublexer = self.lookup(sublexer_name_bytes)?;

                        let code_group_idx = usize::try_from(code_group).map_err(|_| bad())?;
                        for (i, emitter) in emitters_arr.iter().enumerate() {
                            let group = &groups[i + 1];
                            if let Some(sublexer) = sublexer
                                && code_group_idx > 0
                                && i == code_group_idx - 1
                            {
                                self.tick(0, 28)?;
                                let opts = Options::default();
                                let tokens = self.lex_id(sublexer, group, opts, depth + 1)?;
                                self.append_tokens(out, tokens)?;
                            } else {
                                if emitter.is_null() {
                                    continue;
                                }
                                self.emit(emitter, std::slice::from_ref(group), s, out, depth + 1)?;
                            }
                        }
                        Ok(())
                    }
                    _ => self.custom_emit(desc, groups, s, out, depth),
                }
            }
            _ => Err(bad()),
        }
    }

    pub(super) fn mutate(&mut self, desc: &Value, s: &mut State, depth: usize) -> Result<()> {
        self.tick(1, 0)?;
        if depth > 250 {
            return Err(Error::TotalLimit);
        }

        match desc {
            Value::Null => Ok(()),
            Value::Number(_) => Err(bad()),
            Value::Object(obj) => {
                let type_val = obj.get("type").ok_or_else(bad)?;
                let type_str = type_val.as_str().ok_or_else(bad)?;

                match type_str {
                    "chroma.pushMutator" => {
                        let states_val = obj.get("States").ok_or_else(bad)?;
                        let states_arr = states_val.as_array().ok_or_else(bad)?;

                        if states_arr.is_empty() {
                            let current_len = s.current.len();
                            self.tick(1, current_len + 24)?;
                            let current_clone = s.current.clone();
                            self.push_state(s, &current_clone)?;
                            return Ok(());
                        }

                        for state_val in states_arr {
                            let state_str = state_val.as_str().ok_or_else(bad)?;
                            if state_str == "#pop" {
                                if s.stack.is_empty() {
                                    return Err(bad());
                                }
                                s.stack.pop();
                            } else {
                                self.push_state(s, state_str)?;
                            }
                        }
                        Ok(())
                    }
                    "chroma.popMutator" => {
                        let depth_val = obj.get("Depth").ok_or_else(bad)?;
                        let depth_num = depth_val.as_u64().ok_or_else(bad)?;
                        let d = usize::try_from(depth_num).map_err(|_| bad())?;

                        if s.stack.is_empty() {
                            return Err(bad());
                        }
                        if d > s.stack.len() {
                            return Err(bad());
                        }
                        s.stack.truncate(s.stack.len() - d);
                        Ok(())
                    }
                    "chroma.multiMutator" => {
                        let mutators_val = obj.get("Mutators").ok_or_else(bad)?;
                        let mutators_arr = mutators_val.as_array().ok_or_else(bad)?;

                        for mutator in mutators_arr {
                            self.mutate(mutator, s, depth + 1)?;
                        }
                        Ok(())
                    }
                    _ => self.custom_mutate(desc, s, depth),
                }
            }
            _ => Err(bad()),
        }
    }
}
