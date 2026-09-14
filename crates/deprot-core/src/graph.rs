//! A pure dependency-graph model and the graph analytics deprot layers on top of scoring:
//! **blast radius** (how many of your packages transitively depend on a given one) and
//! **leverage** (which single risky package, if fixed, removes the most risk from the project).
//!
//! Like the rest of `deprot-core` this is zero-I/O and deterministic: a manifest/lockfile parser
//! builds the [`DepGraph`], and these methods reason about it without touching the network.

use crate::facts::Ecosystem;

/// One resolved node in the dependency tree — a concrete package at a concrete version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepNode {
    /// Registry name of the package.
    pub name: String,
    /// The exact resolved version (from the lockfile).
    pub version: String,
    /// Ecosystem the package belongs to.
    pub ecosystem: Ecosystem,
    /// Whether this is a direct dependency of the project (vs. pulled in transitively).
    pub direct: bool,
}

/// A resolved dependency graph. `edges[i]` holds the indices of the nodes that node `i` depends
/// on (forward adjacency).
#[derive(Debug, Clone, Default)]
pub struct DepGraph {
    nodes: Vec<DepNode>,
    edges: Vec<Vec<usize>>,
}

impl DepGraph {
    /// An empty graph.
    pub fn new() -> Self {
        DepGraph::default()
    }

    /// Add a node, returning its index.
    pub fn add_node(&mut self, node: DepNode) -> usize {
        let idx = self.nodes.len();
        self.nodes.push(node);
        self.edges.push(Vec::new());
        idx
    }

    /// Record that `from` depends on `to`.
    pub fn add_edge(&mut self, from: usize, to: usize) {
        if from < self.edges.len() && to < self.nodes.len() && from != to {
            let e = &mut self.edges[from];
            if !e.contains(&to) {
                e.push(to);
            }
        }
    }

    /// All nodes, in insertion order.
    pub fn nodes(&self) -> &[DepNode] {
        &self.nodes
    }

    /// All nodes, mutably — used by lockfile parsers that only learn a node's `direct` status after
    /// the whole file is read (e.g. bundler lists direct gems in a trailing `DEPENDENCIES` section).
    pub fn nodes_mut(&mut self) -> &mut [DepNode] {
        &mut self.nodes
    }

    /// Number of nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the graph has no nodes.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Number of direct dependencies.
    pub fn direct_count(&self) -> usize {
        self.nodes.iter().filter(|n| n.direct).count()
    }

    /// Reverse adjacency: `rev[i]` = indices of nodes that directly depend on node `i`.
    fn reverse(&self) -> Vec<Vec<usize>> {
        let mut rev = vec![Vec::new(); self.nodes.len()];
        for (from, tos) in self.edges.iter().enumerate() {
            for &to in tos {
                rev[to].push(from);
            }
        }
        rev
    }

    /// Blast radius of every node: the count of *distinct* other nodes that transitively depend on
    /// it. Computed for the whole graph in one pass (shared reverse adjacency).
    pub fn blast_radii(&self) -> Vec<usize> {
        let rev = self.reverse();
        let n = self.nodes.len();
        let mut out = vec![0usize; n];
        for start in 0..n {
            let mut seen = vec![false; n];
            seen[start] = true;
            let mut stack = vec![start];
            let mut count = 0;
            while let Some(u) = stack.pop() {
                for &p in &rev[u] {
                    if !seen[p] {
                        seen[p] = true;
                        count += 1;
                        stack.push(p);
                    }
                }
            }
            out[start] = count;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, direct: bool) -> DepNode {
        DepNode {
            name: name.into(),
            version: "1.0.0".into(),
            ecosystem: Ecosystem::Cargo,
            direct,
        }
    }

    #[test]
    fn blast_radius_counts_transitive_dependents() {
        // app -> lib -> leaf ; app -> leaf
        let mut g = DepGraph::new();
        let app = g.add_node(node("app", true));
        let lib = g.add_node(node("lib", false));
        let leaf = g.add_node(node("leaf", false));
        g.add_edge(app, lib);
        g.add_edge(lib, leaf);
        g.add_edge(app, leaf);

        let radii = g.blast_radii();
        assert_eq!(radii[app], 0, "nothing depends on the app");
        assert_eq!(radii[lib], 1, "only app depends on lib");
        assert_eq!(radii[leaf], 2, "both app and lib depend on leaf");
    }

    #[test]
    fn duplicate_and_self_edges_are_ignored() {
        let mut g = DepGraph::new();
        let a = g.add_node(node("a", true));
        let b = g.add_node(node("b", false));
        g.add_edge(a, b);
        g.add_edge(a, b); // dup
        g.add_edge(a, a); // self
        assert_eq!(g.blast_radii()[b], 1);
    }
}
