use super::{Engine, Error, Options, Result, Token};
impl Engine<'_> {
    pub(super) fn clone_options(&mut self, options: &Options) -> Result<Options> {
        self.tick(0, options.state.len() + 24)?;
        Ok(Options {
            state: options.state.clone(),
            nested: options.nested,
            ensure_lf: options.ensure_lf,
        })
    }
    pub(super) fn lex_coalesced(
        &mut self,
        id: usize,
        input: &[u8],
        options: Options,
        depth: usize,
    ) -> Result<Vec<Token>> {
        let tokens = self.lex_id(id, input, options, depth)?;
        self.coalesce(tokens)
    }
    pub(super) fn push_existing(&mut self,out:&mut Vec<Token>,token:Token)->Result<()> {
        self.tick(1,0)?;self.grow_vec(out,out.len().checked_add(1).ok_or(Error::TotalLimit)?)?;
        out.push(token);Ok(())
    }
    pub(super) fn append_bytes(&mut self,out:&mut Vec<u8>,bytes:&[u8])->Result<()> {
        self.tick(bytes.len().div_ceil(16) as u64+1,0)?;
        self.grow_vec(out,out.len().checked_add(bytes.len()).ok_or(Error::TotalLimit)?)?;
        out.extend_from_slice(bytes);Ok(())
    }
    pub(super) fn split_token(
        &mut self,
        token: Option<Token>,
        offset: i64,
    ) -> Result<(Option<Token>, Option<Token>)> {
        let Some(mut token) = token else {
            return Ok((None, None));
        };
        let offset = usize::try_from(offset)
            .ok()
            .filter(|n| *n <= token.text.len())
            .ok_or("invalid Chroma delegate byte offset")?;
        if offset == 0 {
            return Ok((None, Some(token)));
        }
        if offset == token.text.len() {
            return Ok((Some(token), None));
        }
        let mut right = Vec::new();
        self.append_bytes(&mut right, &token.text[offset..])?;
        token.text.truncate(offset);
        let kind = token.kind;
        Ok((Some(token), Some(Token { kind, text: right })))
    }
    pub(super) fn wrapped(
        &mut self,
        id: usize,
        input: &[u8],
        options: Options,
        depth: usize,
    ) -> Result<Vec<Token>> {
        let registry = self.registry;
        let lexer = registry.db.lexers.get(id).ok_or("invalid wrapped lexer")?;
        let child = *lexer
            .children
            .first()
            .ok_or("missing wrapped lexer child")?;
        match lexer.kind.as_str() {
            "*chroma.remappingLexer" => {
                let mut tokens = self.lex_id(child, input, options, depth + 1)?;
                for token in &mut tokens {
                    self.tick(1, 0)?;
                    if let Some(table) = lexer.mapping_lookup.get(&token.kind) {
                        let exact = std::str::from_utf8(&token.text)
                            .ok()
                            .and_then(|text| table.get(text));
                        if let Some(&kind) = exact.or_else(|| table.get("")) {
                            token.kind = kind;
                        }
                    }
                }
                Ok(tokens)
            }
            "*chroma.delegatingLexer" => {
                let language = *lexer.children.get(1).ok_or("missing language lexer")?;
                self.delegate(child, language, input, options, depth + 1)
            }
            "*lexers.markdownLexer" => {
                let mut split = None;
                if input.starts_with(b"---\n") || input.starts_with(b"---\r\n") {
                    let first = input
                        .iter()
                        .position(|b| *b == b'\n')
                        .ok_or("missing frontmatter delimiter")?;
                    let mut pos = first + 1;
                    while pos < input.len() {
                        self.tick(1, 0)?;
                        let Some(end) = input[pos..]
                            .iter()
                            .position(|b| *b == b'\n')
                            .map(|n| pos + n)
                        else {
                            break;
                        };
                        let line = input[pos..end]
                            .strip_suffix(b"\r")
                            .unwrap_or(&input[pos..end]);
                        if line == b"---" {
                            split = Some(end + 1);
                            break;
                        }
                        pos = end + 1;
                    }
                }
                if let Some(split) = split
                    && let Some(yaml) = self.lookup(b"YAML")?
                {
                    let yaml_options = self.clone_options(&options)?;
                    let mut tokens = self.lex_id(yaml, &input[..split], yaml_options, depth + 1)?;
                    let markdown = self.lex_id(child, &input[split..], options, depth + 1)?;
                    self.append_tokens(&mut tokens, markdown)?;
                    Ok(tokens)
                } else {
                    self.lex_id(child, input, options, depth + 1)
                }
            }
            "*lexers.httpBodyContentTyper" => self.http_body(child, input, options, depth + 1),
            _ => Err("unsupported generated Chroma wrapper".into()),
        }
    }
    pub fn mime_type(&mut self, name: &str) -> Result<Option<usize>> {
        let registry = self.registry;
        let mut best = None;
        let mut priority = f32::NEG_INFINITY;
        for &id in &registry.db.registry_order {
            self.tick(1, 0)?;
            let config = &registry.db.lexers[id].config;
            if config.mime_types.iter().any(|x| x == name) {
                let current = if config.priority == 0.0 {
                    1.0
                } else {
                    config.priority
                };
                if current > priority {
                    best = Some(id);
                    priority = current;
                }
            }
        }
        Ok(best)
    }
    fn http_body(
        &mut self,
        child: usize,
        input: &[u8],
        options: Options,
        depth: usize,
    ) -> Result<Vec<Token>> {
        let tokens = self.lex_id(child, input, options, depth)?;
        let mut content_type = String::new();
        let mut is_content_type = false;
        let mut out = Vec::new();
        for mut token in tokens {
            if token.kind == 2000 && token.text.eq_ignore_ascii_case(b"content-type") {
                is_content_type = true;
            } else if token.kind == 3000 && is_content_type {
                is_content_type = false;
                let value = std::str::from_utf8(&token.text)
                    .map_err(|_| "invalid UTF8 content type token")?
                    .trim();
                let value = if let Some(at) = value.find(';').filter(|n| *n > 0) {
                    value[..at].trim()
                } else {
                    value
                };
                self.tick(0, value.len())?;
                content_type = value.to_owned();
            } else if token.kind == 7000 && !content_type.is_empty() {
                let mut lexer = self.mime_type(&content_type)?;
                if lexer.is_none() && content_type.contains('+') {
                    let start = content_type.find('/').map_or(0, |n| n + 1);
                    let end = content_type.rfind('+').ok_or("missing MIME suffix")? + 1;
                    self.tick(0, content_type.len())?;
                    content_type = format!("{}{}", &content_type[..start], &content_type[end..]);
                    lexer = self.mime_type(&content_type)?;
                }
                if let Some(lexer) = lexer {
                    self.tick(0, 28)?;
                    let nested = self.lex_id(lexer, &token.text, Options::default(), depth + 1)?;
                    self.append_tokens(&mut out, nested)?;
                    continue;
                } else {
                    token.kind = 8000;
                }
            }
            self.push_existing(&mut out, token)?;
        }
        Ok(out)
    }
}
