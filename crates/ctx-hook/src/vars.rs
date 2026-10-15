//! The environment as the policy sees it.
//!
//! The hook can only see its own environment, not that of the persistent shell
//! the command will run in, so a check on it is a tripwire for an unusual setup,
//! not a guarantee. It is behind this type so tests and the offline replay can
//! supply a fixed one (`std::env::set_var` is unsafe and would be racy anyway).

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum Vars {
    Process,
    Fixed(HashMap<String, String>),
}

impl Vars {
    /// A fixed environment with exactly these variables.
    pub fn fixed(pairs: &[(&str, &str)]) -> Self {
        Vars::Fixed(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        )
    }

    pub fn get(&self, name: &str) -> Option<String> {
        match self {
            Vars::Process => std::env::var_os(name).map(|v| v.to_string_lossy().into_owned()),
            Vars::Fixed(map) => map.get(name).cloned(),
        }
    }

    /// Set at all, even to the empty string: several of these variables mean
    /// something to the shell or the tool merely by existing.
    pub fn is_set(&self, name: &str) -> bool {
        match self {
            Vars::Process => std::env::var_os(name).is_some(),
            Vars::Fixed(map) => map.contains_key(name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_vars_know_only_what_they_were_given() {
        let v = Vars::fixed(&[("A", "1"), ("EMPTY", "")]);
        assert_eq!(v.get("A").as_deref(), Some("1"));
        assert!(v.is_set("EMPTY"));
        assert!(!v.is_set("B"));
        assert_eq!(v.get("B"), None);
    }
}
