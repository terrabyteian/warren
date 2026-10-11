//! The OpenAPI description lists exactly the routes the control plane serves.

use std::collections::BTreeSet;

use warren_policy::yaml::{self, Node, Value};

fn field<'a>(node: &'a Node, key: &str) -> Option<&'a Node> {
    match &node.value {
        Value::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

#[test]
fn openapi_matches_the_routes() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/api/openapi.yaml");
    let text = std::fs::read_to_string(path).unwrap();
    let docs = yaml::parse_documents(&text).unwrap_or_else(|e| panic!("openapi.yaml: {e}"));
    let spec = &docs[0];
    let Some(Node {
        value: Value::Map(paths),
        ..
    }) = field(spec, "paths")
    else {
        panic!("no paths");
    };
    let mut documented = BTreeSet::new();
    for (path, item) in paths {
        let Value::Map(methods) = &item.value else {
            panic!("{path} is not a mapping")
        };
        for (method, _) in methods {
            documented.insert((method.to_ascii_uppercase(), path.clone()));
        }
    }
    let served: BTreeSet<(String, String)> = warren_control::api::ROUTES
        .iter()
        .chain(warren_control::admin::ROUTES)
        .map(|(m, p)| ((*m).to_owned(), (*p).to_owned()))
        .collect();
    let missing: Vec<_> = served.difference(&documented).collect();
    let extra: Vec<_> = documented.difference(&served).collect();
    assert!(missing.is_empty(), "served but not documented: {missing:?}");
    assert!(extra.is_empty(), "documented but not served: {extra:?}");
}
