// Copyright 2015 Matthew Holt and The Caddy Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//! The Caddyfile import graph is cumulative for one parse, not a call stack.
use anyhow::{Result, bail};
use std::collections::{HashMap, HashSet};

#[derive(Default)]
pub(crate) struct ImportGraph {
    nodes: HashSet<String>,
    edges: HashMap<String, Vec<String>>,
}
impl ImportGraph {
    pub(crate) fn add_node(&mut self, name: &str) {
        self.nodes.insert(name.to_owned());
    }
    pub(crate) fn add_nodes(&mut self, names: &[String]) {
        for name in names {
            self.add_node(name);
        }
    }
    pub(crate) fn remove_nodes(&mut self, names: &[String]) {
        for name in names {
            self.nodes.remove(name);
            self.edges.remove(name);
            for targets in self.edges.values_mut() {
                targets.retain(|target| target != name);
            }
        }
    }
    pub(crate) fn add_edges(&mut self, from: &str, targets: &[String]) -> Result<()> {
        for to in targets {
            if !self.nodes.contains(from) || !self.nodes.contains(to) {
                bail!("one of the nodes does not exist");
            }
            if self.will_cycle(to, from) {
                bail!("a cycle of imports exists between {from} and {to}");
            }
            let list = self.edges.entry(from.to_owned()).or_default();
            if !list.contains(to) {
                list.push(to.to_owned());
            }
        }
        Ok(())
    }
    fn will_cycle(&self, from: &str, to: &str) -> bool {
        if from == to {
            return true;
        }
        let mut seen = HashSet::new();
        let mut todo = vec![from];
        while let Some(node) = todo.pop() {
            if !seen.insert(node) {
                continue;
            }
            if let Some(targets) = self.edges.get(node) {
                for target in targets {
                    if target == to {
                        return true;
                    }
                    todo.push(target);
                }
            }
        }
        false
    }
}
