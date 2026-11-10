// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::{Result, anyhow};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

use super::budget::{Budget, Cost};
use crate::caddyfile_lexer::Token;
use crate::caddyfile_parser::Dispenser;

pub(super) type Definitions = BTreeMap<String, Map<String, Value>>;
pub(super) type Extracted = (Option<Map<String, Value>>, Vec<Token>);

/// The handler wrapper removes one optional matcher token before unmarshalling.
pub(super) fn extract(tokens: &[Token], definitions: &Definitions) -> Result<Extracted> {
    let mut d = Dispenser::new(tokens.to_vec());
    if !d.next() {
        return Err(d.arg_err());
    }
    if !d.next_arg() {
        return Ok((None, tokens.to_vec()));
    }
    let text = d.val();
    let matcher = if text == "*" {
        None
    } else if text.starts_with('/') {
        let mut map = Map::new();
        map.insert("path".into(), Value::Array(vec![text.into()]));
        Some(map)
    } else if text.starts_with('@') {
        Some(
            definitions
                .get(text)
                .ok_or_else(|| d.error(format!("unrecognized matcher name: {text}")))?
                .clone(),
        )
    } else {
        return Ok((None, tokens.to_vec()));
    };
    Ok((matcher, d.delete().to_vec()))
}

/// parse_definition parses named matcher definitions.
pub(super) fn parse_definition(
    tokens: &[Token],
    definitions: &mut Definitions,
    budget: &mut Budget,
) -> Result<Cost> {
    let reservation = super::site::reserve_helper(tokens, budget)?;
    let mut d = Dispenser::new(tokens.to_vec());
    if !d.next() {
        return Err(anyhow!("expected token"));
    }
    let definition_name = d.val().to_string();
    if definitions.contains_key(&definition_name) {
        return Err(anyhow!(
            "matcher is defined more than once: {}",
            definition_name
        ));
    }

    let mut local_map = Map::new();

    // Check for shorthand expression matcher
    if d.next_arg() {
        let tok = d.token();
        if tok.quoted() {
            // Construct expression shorthand: ["expression", <quoted_token>]
            let mut expr_tokens = vec![tok.clone(), tok];
            // Modify text of the first token to be "expression"
            expr_tokens[0].text = "expression".to_string();

            // The callback is super::matcher_atoms::parse.
            match matcher("expression", &expr_tokens, &definition_name, budget)? {
                Some(val) => {
                    local_map.insert("expression".to_string(), val);
                }
                None => {
                    return Err(anyhow!("unsupported matcher: expression"));
                }
            }
            let cost = budget.finish_map(reservation, &local_map)?;
            definitions.insert(definition_name, local_map);
            return Ok(cost);
        }
        d.prev();
    }

    // Collect tokens by matcher name
    let mut tokens_by_name: BTreeMap<String, Vec<Token>> = BTreeMap::new();
    let initial_nesting = d.nesting();

    // Iterate over args and blocks
    while d.next_arg() || d.next_block(initial_nesting) {
        let matcher_name = d.val().to_string();
        let segment = d.next_segment();
        tokens_by_name
            .entry(matcher_name)
            .and_modify(|v| v.extend_from_slice(&segment))
            .or_insert(segment);
    }

    // Parse each collected matcher
    for (matcher_name, toks) in tokens_by_name {
        // Call super::matcher_atoms::parse
        // If None, explicit Err.
        match matcher(&matcher_name, &toks, &definition_name, budget)? {
            Some(val) => {
                local_map.insert(matcher_name, val);
            }
            None => {
                return Err(anyhow!("unsupported matcher: {}", matcher_name));
            }
        }
    }

    let cost = budget.finish_map(reservation, &local_map)?;
    definitions.insert(definition_name, local_map);
    Ok(cost)
}

fn matcher(
    name: &str,
    tokens: &[Token],
    definition_name: &str,
    budget: &mut Budget,
) -> Result<Option<Value>> {
    if name == "not" {
        return budget.nested(|budget| parse_not(tokens, budget)).map(Some);
    }
    let reservation = super::site::reserve_helper(tokens, budget)?;
    let value = if name == "url_pattern" {
        Some(super::matcher_urlpattern::parse(tokens)?)
    } else if let Some(v) = super::matcher_atoms::parse(name, tokens)? {
        Some(v)
    } else if let Some(v) = super::matcher_more::parse(
        name,
        tokens,
        definition_name.strip_prefix('@').unwrap_or(definition_name),
    )? {
        Some(v)
    } else if let Some(v) = super::matcher_regexp::parse(
        name,
        tokens,
        definition_name.strip_prefix('@').unwrap_or(definition_name),
    )? {
        Some(v)
    } else if name == "file" {
        Some(super::matcher_file::parse(tokens)?)
    } else {
        None
    };
    if let Some(value) = &value {
        budget.finish_value(reservation, value)?;
    }
    Ok(value)
}
fn parse_not(tokens: &[Token], budget: &mut Budget) -> Result<Value> {
    let reservation = super::site::reserve_helper(tokens, budget)?;
    let mut d = Dispenser::new(tokens.to_vec());
    let mut sets = Vec::new();
    while d.next() {
        let mut grouped: BTreeMap<String, Vec<Token>> = BTreeMap::new();
        let nesting = d.nesting();
        while d.next_arg() || d.next_block(nesting) {
            if d.token().quoted() {
                let mut expression = d.token();
                expression.text = "expression".into();
                grouped
                    .entry("expression".into())
                    .or_default()
                    .extend([expression, d.token()]);
                continue;
            }
            let name = d.val().to_owned();
            grouped.entry(name).or_default().extend(d.next_segment());
        }
        let mut map = Map::new();
        for (name, tokens) in grouped {
            let value = matcher(&name, &tokens, "", budget)?
                .ok_or_else(|| anyhow!("unsupported matcher: {name}"))?;
            map.insert(name, value);
        }
        sets.push(Value::Object(map));
    }
    let value = Value::Array(sets);
    budget.finish_value(reservation, &value)?;
    Ok(value)
}
