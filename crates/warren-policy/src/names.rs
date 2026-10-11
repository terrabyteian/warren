//! Host-name patterns and address ranges, with the matching rules of
//! docs/policy.md sections 2 and 3. The compiler uses them to check scopes
//! and claims; enforcement points use the same code at run time.

use std::fmt;
use std::net::IpAddr;

/// A domain in a scope or an app destination: an exact name, or a single
/// leading wildcard `*.` followed by a domain, which matches names with one
/// or more labels in its place. `*.svc.cluster.local` matches
/// `grafana.observability.svc.cluster.local` but not `svc.cluster.local`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DomainPattern {
    /// An exact name.
    Exact(String),
    /// `*.` followed by this base domain.
    Wildcard(String),
}

impl fmt::Display for DomainPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainPattern::Exact(d) => f.write_str(d),
            DomainPattern::Wildcard(d) => write!(f, "*.{d}"),
        }
    }
}

/// Whether `name` is a DNS host name warren accepts: lowercase letters,
/// digits and hyphens in labels of 1 to 63 characters that neither start
/// nor end with a hyphen, at most 253 characters, no trailing dot.
pub fn is_host_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            let b = label.as_bytes();
            !b.is_empty()
                && b.len() <= 63
                && b.iter()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
                && b[0] != b'-'
                && b[b.len() - 1] != b'-'
        })
}

impl DomainPattern {
    /// Parses a pattern. Upper-case letters are folded to lower case; DNS
    /// names are case-insensitive.
    pub fn parse(text: &str) -> Result<DomainPattern, String> {
        let lower = text.to_ascii_lowercase();
        let (wildcard, base) = match lower.strip_prefix("*.") {
            Some(base) => (true, base),
            None => (false, lower.as_str()),
        };
        if !is_host_name(base) {
            return Err(format!(
                "{text:?} is not a host name or a single leading wildcard (*.example.com)"
            ));
        }
        Ok(if wildcard {
            DomainPattern::Wildcard(base.to_owned())
        } else {
            DomainPattern::Exact(base.to_owned())
        })
    }

    /// Whether the pattern matches the host name `name`.
    pub fn matches(&self, name: &str) -> bool {
        match self {
            DomainPattern::Exact(d) => d == name,
            DomainPattern::Wildcard(base) => name
                .strip_suffix(base.as_str())
                .and_then(|prefix| prefix.strip_suffix('.'))
                .is_some_and(|labels| !labels.is_empty()),
        }
    }

    /// Whether every name `other` matches is also matched by `self`.
    pub fn covers(&self, other: &DomainPattern) -> bool {
        match (self, other) {
            (_, DomainPattern::Exact(name)) => self.matches(name),
            (DomainPattern::Exact(_), DomainPattern::Wildcard(_)) => false,
            (DomainPattern::Wildcard(a), DomainPattern::Wildcard(b)) => a == b || self.matches(b),
        }
    }

    /// Whether some name is matched by both patterns.
    pub fn overlaps(&self, other: &DomainPattern) -> bool {
        self.covers(other) || other.covers(self)
    }

    /// How specific the pattern is, for choosing a name's owning app: an
    /// exact name beats any wildcard, and a wildcard with more labels beats
    /// one with fewer (docs/policy.md section 3).
    pub fn specificity(&self) -> (bool, usize) {
        match self {
            DomainPattern::Exact(d) => (true, d.split('.').count()),
            DomainPattern::Wildcard(d) => (false, d.split('.').count()),
        }
    }

    /// The name split DNS claims for this pattern: the name itself, or a
    /// wildcard's base domain.
    pub fn dns_suffix(&self) -> &str {
        match self {
            DomainPattern::Exact(d) | DomainPattern::Wildcard(d) => d,
        }
    }
}

/// Among `patterns`, the index of the most specific one matching `name`.
/// Ties cannot happen between the claims of different apps, because the
/// compiler rejects identical claims.
pub fn most_specific_match<'a>(
    name: &str,
    patterns: impl IntoIterator<Item = &'a DomainPattern>,
) -> Option<usize> {
    patterns
        .into_iter()
        .enumerate()
        .filter(|(_, p)| p.matches(name))
        .max_by_key(|(_, p)| p.specificity())
        .map(|(i, _)| i)
}

/// An IPv4 or IPv6 address range in CIDR notation. A bare address is a
/// single-address range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl Cidr {
    /// Parses `addr/prefix` or a bare address. Host bits must be zero, so
    /// every range has one spelling.
    pub fn parse(text: &str) -> Result<Cidr, String> {
        let (addr_text, prefix) = match text.split_once('/') {
            Some((a, p)) => (
                a,
                Some(
                    p.parse::<u8>()
                        .map_err(|_| format!("{text:?} has an invalid prefix length"))?,
                ),
            ),
            None => (text, None),
        };
        let addr: IpAddr = addr_text
            .parse()
            .map_err(|_| format!("{text:?} is not an IP address or CIDR range"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            return Err(format!("{text:?} has a prefix longer than {max} bits"));
        }
        let cidr = Cidr { addr, prefix };
        if cidr.network() != addr {
            return Err(format!(
                "{text:?} has host bits set; the range is {}",
                Cidr {
                    addr: cidr.network(),
                    prefix
                }
            ));
        }
        Ok(cidr)
    }

    /// The prefix length.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// The first address of the range.
    pub fn network(&self) -> IpAddr {
        match self.addr {
            IpAddr::V4(a) => {
                let bits = u32::from(a);
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(self.prefix))
                };
                IpAddr::V4((bits & mask).into())
            }
            IpAddr::V6(a) => {
                let bits = u128::from(a);
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(self.prefix))
                };
                IpAddr::V6((bits & mask).into())
            }
        }
    }

    /// Whether the range contains `addr`.
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.addr, addr) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                Cidr {
                    addr,
                    prefix: self.prefix,
                }
                .network()
                    == self.addr
            }
            _ => false,
        }
    }

    /// Whether `other` lies entirely inside this range.
    pub fn covers(&self, other: &Cidr) -> bool {
        other.prefix >= self.prefix && self.contains(other.addr)
    }

    /// Whether the two ranges share an address.
    pub fn overlaps(&self, other: &Cidr) -> bool {
        self.covers(other) || other.covers(self)
    }

    /// Whether this is an IPv4 range.
    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    /// The `n`th address of the range, if the range has that many.
    pub fn nth(&self, n: u128) -> Option<IpAddr> {
        let host_bits = u32::from(if self.is_ipv4() { 32 } else { 128 } - self.prefix);
        if host_bits < 128 && n >= (1u128 << host_bits) {
            return None;
        }
        Some(match self.addr {
            IpAddr::V4(a) => IpAddr::V4((u32::from(a) + u32::try_from(n).ok()?).into()),
            IpAddr::V6(a) => IpAddr::V6((u128::from(a) + n).into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> DomainPattern {
        DomainPattern::parse(s).unwrap()
    }

    #[test]
    fn wildcard_matching_follows_the_policy_doc() {
        let w = d("*.svc.cluster.local");
        assert!(w.matches("grafana.observability.svc.cluster.local"));
        assert!(w.matches("a.svc.cluster.local"));
        assert!(!w.matches("svc.cluster.local"));
        assert!(!w.matches("xsvc.cluster.local"));
        assert!(d("nas.example.internal").matches("nas.example.internal"));
        assert_eq!(d("Grafana.Lab.Example.com"), d("grafana.lab.example.com"));
    }

    #[test]
    fn invalid_patterns_are_rejected() {
        for bad in [
            "", "*", "*.", "a.*.b", "**.a", "a..b", "-a.b", "a.b.", "a_b.c", "*.*.a",
        ] {
            assert!(DomainPattern::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn covering_and_specificity() {
        let broad = d("*.example.com");
        let lab = d("*.lab.example.com");
        let host = d("grafana.lab.example.com");
        assert!(broad.covers(&lab) && broad.covers(&host) && lab.covers(&host));
        assert!(!lab.covers(&broad) && !host.covers(&lab));
        assert!(broad.covers(&broad));
        assert!(!d("a.example.com").overlaps(&d("b.example.com")));
        let patterns = [broad, lab, host];
        assert_eq!(
            most_specific_match("grafana.lab.example.com", &patterns),
            Some(2)
        );
        assert_eq!(most_specific_match("x.lab.example.com", &patterns), Some(1));
        assert_eq!(most_specific_match("x.example.com", &patterns), Some(0));
        assert_eq!(most_specific_match("example.com", &patterns), None);
    }

    #[test]
    fn cidrs() {
        let c = Cidr::parse("10.20.0.0/16").unwrap();
        assert!(c.contains("10.20.255.1".parse().unwrap()));
        assert!(!c.contains("10.21.0.1".parse().unwrap()));
        assert!(!c.contains("::1".parse().unwrap()));
        assert!(c.covers(&Cidr::parse("10.20.0.0/24").unwrap()));
        assert!(c.covers(&Cidr::parse("10.20.3.4").unwrap()));
        assert!(!Cidr::parse("10.20.0.0/24").unwrap().covers(&c));
        assert!(Cidr::parse("10.20.0.5/16").is_err());
        assert!(Cidr::parse("10.20.0.0/33").is_err());
        assert!(Cidr::parse("10.20.0.0/x").is_err());
        let v6 = Cidr::parse("fd00:20::/48").unwrap();
        assert!(v6.contains("fd00:20:0:1::5".parse().unwrap()));
        assert_eq!(v6.to_string(), "fd00:20::/48");
        assert!(
            Cidr::parse("0.0.0.0/0")
                .unwrap()
                .contains("1.2.3.4".parse().unwrap())
        );
    }

    #[test]
    fn nth_address() {
        let c = Cidr::parse("100.96.0.0/30").unwrap();
        assert_eq!(c.nth(3), Some("100.96.0.3".parse().unwrap()));
        assert_eq!(c.nth(4), None);
        let v6 = Cidr::parse("fd77::/64").unwrap();
        assert_eq!(v6.nth(5), Some("fd77::5".parse().unwrap()));
        assert_eq!(
            Cidr::parse("::/0").unwrap().nth(1),
            Some("::1".parse().unwrap())
        );
    }
}
