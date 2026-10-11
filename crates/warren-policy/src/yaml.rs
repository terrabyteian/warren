//! A strict YAML reader that keeps line numbers, so every compiled policy can
//! point back to the line a person wrote (`@source`), and every error can say
//! where it is.
//!
//! The policy surface needs only mappings, sequences and scalars, so the
//! reader refuses the parts of YAML that make documents hard to review:
//! anchors and aliases, tags, non-scalar keys and duplicate keys.

use std::fmt;

use saphyr_parser::{Event, Parser, ScalarStyle};

/// A YAML value with its position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// The value.
    pub value: Value,
    /// 1-based line of the value's first character.
    pub line: usize,
}

/// A YAML value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// A scalar, with whether it was written plain (unquoted). Plain scalars
    /// may be read as numbers, booleans or null; quoted ones are always
    /// strings.
    Scalar {
        /// The scalar's text.
        text: String,
        /// Whether it was unquoted.
        plain: bool,
    },
    /// A sequence.
    Seq(Vec<Node>),
    /// A mapping, in document order. Keys are unique scalars.
    Map(Vec<(String, Node)>),
}

/// A syntax error, or a YAML feature the policy surface does not accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YamlError {
    /// 1-based line.
    pub line: usize,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for YamlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl Node {
    /// Whether this is a null: an empty plain scalar, `~` or `null`.
    pub fn is_null(&self) -> bool {
        matches!(&self.value, Value::Scalar { text, plain: true } if matches!(text.as_str(), "" | "~" | "null" | "Null" | "NULL"))
    }

    /// A short description of the kind of value, for error messages.
    pub fn kind(&self) -> &'static str {
        match &self.value {
            _ if self.is_null() => "null",
            Value::Scalar { .. } => "a scalar",
            Value::Seq(_) => "a list",
            Value::Map(_) => "a mapping",
        }
    }
}

enum Frame {
    Seq {
        line: usize,
        items: Vec<Node>,
    },
    Map {
        line: usize,
        entries: Vec<(String, Node)>,
        key: Option<(String, usize)>,
    },
}

/// Parses every document in `text`. A file may hold several documents
/// separated by `---`; empty documents are dropped.
pub fn parse_documents(text: &str) -> Result<Vec<Node>, YamlError> {
    let mut parser = Parser::new_from_str(text);
    let mut docs = Vec::new();
    let mut stack: Vec<Frame> = Vec::new();
    let mut doc: Option<Node> = None;
    while let Some(next) = parser.next_event() {
        let (event, span) = next.map_err(|e| YamlError {
            line: e.marker().line(),
            message: e.info().to_owned(),
        })?;
        let line = span.start.line();
        let refuse = |message: &str| {
            Err(YamlError {
                line,
                message: message.to_owned(),
            })
        };
        match event {
            Event::StreamStart | Event::StreamEnd | Event::Nothing => {}
            Event::DocumentStart(_) => doc = None,
            Event::DocumentEnd => {
                if let Some(node) = doc.take()
                    && !node.is_null()
                {
                    docs.push(node);
                }
            }
            Event::Alias(_) => return refuse("YAML aliases are not supported"),
            Event::Scalar(text, style, anchor, tag) => {
                if anchor != 0 {
                    return refuse("YAML anchors are not supported");
                }
                if tag.is_some() {
                    return refuse("YAML tags are not supported");
                }
                let node = Node {
                    value: Value::Scalar {
                        text: text.into_owned(),
                        plain: style == ScalarStyle::Plain,
                    },
                    line,
                };
                push(&mut stack, &mut doc, node)?;
            }
            Event::SequenceStart(anchor, tag) | Event::MappingStart(anchor, tag)
                if anchor != 0 || tag.is_some() =>
            {
                return refuse("YAML anchors and tags are not supported");
            }
            Event::SequenceStart(..) => stack.push(Frame::Seq {
                line,
                items: Vec::new(),
            }),
            Event::MappingStart(..) => stack.push(Frame::Map {
                line,
                entries: Vec::new(),
                key: None,
            }),
            Event::SequenceEnd | Event::MappingEnd => {
                let node = match stack.pop() {
                    Some(Frame::Seq { line, items }) => Node {
                        value: Value::Seq(items),
                        line,
                    },
                    Some(Frame::Map {
                        line,
                        entries,
                        key: None,
                    }) => Node {
                        value: Value::Map(entries),
                        line,
                    },
                    _ => return refuse("unbalanced YAML structure"),
                };
                push(&mut stack, &mut doc, node)?;
            }
        }
    }
    Ok(docs)
}

fn push(stack: &mut [Frame], doc: &mut Option<Node>, node: Node) -> Result<(), YamlError> {
    match stack.last_mut() {
        None => *doc = Some(node),
        Some(Frame::Seq { items, .. }) => items.push(node),
        Some(Frame::Map { entries, key, .. }) => match key.take() {
            Some((k, line)) => {
                if entries.iter().any(|(existing, _)| *existing == k) {
                    return Err(YamlError {
                        line,
                        message: format!("duplicate key {k:?}"),
                    });
                }
                entries.push((k, node));
            }
            None => match node.value {
                Value::Scalar { text, .. } => *key = Some((text, node.line)),
                _ => {
                    return Err(YamlError {
                        line: node.line,
                        message: "mapping keys must be plain strings".into(),
                    });
                }
            },
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(text: &str, plain: bool, line: usize) -> Node {
        Node {
            value: Value::Scalar {
                text: text.into(),
                plain,
            },
            line,
        }
    }

    #[test]
    fn documents_with_lines() {
        let docs =
            parse_documents("a: 1\nb:\n  - x\n  - \"443\"\n---\n# comment\n\n---\nc: {d: true}\n")
                .unwrap();
        assert_eq!(docs.len(), 2);
        let Value::Map(entries) = &docs[0].value else {
            panic!()
        };
        assert_eq!(entries[0], ("a".into(), scalar("1", true, 1)));
        let Value::Seq(items) = &entries[1].1.value else {
            panic!()
        };
        assert_eq!(items[0], scalar("x", true, 3));
        assert_eq!(items[1], scalar("443", false, 4));
        assert_eq!(docs[1].line, 9);
    }

    #[test]
    fn refused_features() {
        for (text, line) in [
            ("a: &x 1\nb: *x\n", 1),
            ("a: !!str 1\n", 1),
            ("a: 1\na: 2\n", 2),
            ("? [a]\n: 1\n", 1),
            ("a: [1\n", 2),
        ] {
            let e = parse_documents(text).unwrap_err();
            assert_eq!(e.line, line, "{text:?}: {e}");
        }
    }

    #[test]
    fn nulls() {
        let docs = parse_documents("a:\nb: ~\nc: null\nd: 'null'\n").unwrap();
        let Value::Map(entries) = &docs[0].value else {
            panic!()
        };
        assert!(entries[0].1.is_null() && entries[1].1.is_null() && entries[2].1.is_null());
        assert!(!entries[3].1.is_null());
    }
}
