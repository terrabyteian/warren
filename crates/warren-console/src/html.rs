//! Markup that is escaped by default.
//!
//! Pages are built with [`html!`](crate::html!), which takes a literal
//! template and positional arguments. Every argument is escaped unless it
//! is already [`Html`], so text from users, the IdP, devices or audit
//! records can never become markup. Templates use positional `{}` only:
//! an inline capture such as `{name}` would bypass escaping, so the macro
//! makes one a compile error.

use std::fmt::{self, Write};

/// Markup known to be safe: made only from literal templates and escaped
/// values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Html(String);

impl Html {
    /// Empty markup.
    pub fn new() -> Html {
        Html(String::new())
    }

    /// Text, escaped.
    pub fn text(s: &str) -> Html {
        let mut out = String::with_capacity(s.len());
        escape_into(&mut out, s);
        Html(out)
    }

    /// The markup.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The markup, owned.
    pub fn into_string(self) -> String {
        self.0
    }

    /// Appends more markup.
    pub fn push(&mut self, more: Html) {
        self.0.push_str(&more.0);
    }

    /// Whether there is no markup.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Wraps the output of a template whose arguments were all escaped.
    /// Only [`html!`](crate::html!) calls this.
    #[doc(hidden)]
    pub fn __from_template(s: String) -> Html {
        Html(s)
    }
}

impl FromIterator<Html> for Html {
    fn from_iter<I: IntoIterator<Item = Html>>(iter: I) -> Html {
        let mut out = Html::new();
        for h in iter {
            out.push(h);
        }
        out
    }
}

/// Escapes `s` for HTML text and attribute values.
pub fn escape_into(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
}

/// A value that can appear in a template.
pub trait Render {
    /// Writes the value: escaped text, or markup as it is.
    fn render(&self, out: &mut String);
}

impl Render for Html {
    fn render(&self, out: &mut String) {
        out.push_str(&self.0);
    }
}

impl Render for str {
    fn render(&self, out: &mut String) {
        escape_into(out, self);
    }
}

impl Render for String {
    fn render(&self, out: &mut String) {
        escape_into(out, self);
    }
}

impl<T: Render + ?Sized> Render for &T {
    fn render(&self, out: &mut String) {
        (**self).render(out);
    }
}

impl<T: Render> Render for Option<T> {
    fn render(&self, out: &mut String) {
        if let Some(v) = self {
            v.render(out);
        }
    }
}

macro_rules! render_number {
    ($($t:ty),*) => {$(
        impl Render for $t {
            fn render(&self, out: &mut String) {
                let _ = write!(out, "{self}");
            }
        }
    )*};
}

render_number!(u8, u16, u32, u64, usize, i32, i64);

/// Displays a [`Render`] value. Only [`html!`](crate::html!) uses this.
#[doc(hidden)]
pub struct Escaped<'a, T: Render + ?Sized>(pub &'a T);

impl<T: Render + ?Sized> fmt::Display for Escaped<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        self.0.render(&mut s);
        f.write_str(&s)
    }
}

/// Fills a literal template with positional arguments, escaping each one
/// that is not already [`Html`].
///
/// The template passes through `concat!`, and `format!` cannot capture
/// variables from a template another macro expanded, so an inline capture
/// that would skip escaping does not compile:
///
/// ```compile_fail
/// let name = "<script>";
/// let _ = warren_console::html!("<b>{name}</b>");
/// ```
#[macro_export]
macro_rules! html {
    ($template:literal $(, $arg:expr)* $(,)?) => {
        $crate::html::Html::__from_template(::std::format!(
            ::std::concat!($template) $(, $crate::html::Escaped(&$arg))*
        ))
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn arguments_are_escaped_and_markup_is_not() {
        let name = "<script>alert('x')</script>&";
        let inner = crate::html!("<b>{}</b>", name);
        let page = crate::html!("<p title=\"{}\">{}</p>", "a\"b", inner);
        assert_eq!(
            page.as_str(),
            "<p title=\"a&quot;b\"><b>&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&amp;</b></p>"
        );
        assert_eq!(crate::html!("{}", 42u64).as_str(), "42");
        assert_eq!(crate::html!("[{}]", None::<&str>).as_str(), "[]");
    }
}
