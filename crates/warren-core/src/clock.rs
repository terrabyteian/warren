//! Wall-clock time as warren uses it: Unix seconds and milliseconds, RFC 3339
//! and the X.509 time encodings, all in UTC.
//!
//! Certificates, posture statements, grants and audit records all carry
//! absolute times, so every component reads the clock the same way.

use std::time::{SystemTime, UNIX_EPOCH};

/// The current time in whole Unix seconds.
pub fn now_secs() -> i64 {
    now_millis().div_euclid(1000)
}

/// The current time in Unix milliseconds.
pub fn now_millis() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_millis()).unwrap_or(i64::MAX),
    }
}

/// A calendar date and time of day in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Civil {
    /// Year, for example 2026.
    pub year: i64,
    /// Month, 1 to 12.
    pub month: u32,
    /// Day of the month, 1 to 31.
    pub day: u32,
    /// Hour, 0 to 23.
    pub hour: u32,
    /// Minute, 0 to 59.
    pub minute: u32,
    /// Second, 0 to 59.
    pub second: u32,
}

impl Civil {
    /// The UTC calendar time of a Unix timestamp in seconds.
    pub fn from_unix(secs: i64) -> Civil {
        let days = secs.div_euclid(86_400);
        let rem = secs.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        // rem is in [0, 86400), so these conversions cannot truncate.
        let rem = rem as u32;
        Civil {
            year,
            month,
            day,
            hour: rem / 3600,
            minute: rem % 3600 / 60,
            second: rem % 60,
        }
    }

    /// The Unix timestamp in seconds, or `None` if a field is out of range.
    pub fn to_unix(self) -> Option<i64> {
        if !(1..=12).contains(&self.month)
            || self.day < 1
            || self.day > days_in_month(self.year, self.month)
            || self.hour > 23
            || self.minute > 59
            || self.second > 59
        {
            return None;
        }
        let days = days_from_civil(self.year, self.month, self.day);
        Some(
            days * 86_400
                + i64::from(self.hour) * 3600
                + i64::from(self.minute) * 60
                + i64::from(self.second),
        )
    }
}

/// Formats a Unix timestamp in seconds as RFC 3339 in UTC, for example
/// `2026-10-11T08:30:00Z`.
pub fn rfc3339(secs: i64) -> String {
    let c = Civil::from_unix(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        c.year, c.month, c.day, c.hour, c.minute, c.second
    )
}

/// The day of the week of a Unix timestamp in UTC, 0 for Sunday to 6 for
/// Saturday, and the minute of that day: together they give the
/// minute-of-week that schedule conditions compare against.
pub fn utc_minute_of_week(secs: i64) -> i64 {
    let days = secs.div_euclid(86_400);
    // 1970-01-01 was a Thursday (day 4 counting from Sunday).
    let weekday = (days + 4).rem_euclid(7);
    weekday * 1440 + secs.rem_euclid(86_400) / 60
}

/// Encodes a Unix timestamp as an X.509 `Time` (RFC 5280 section 4.1.2.5):
/// UTCTime through 2049, GeneralizedTime from 2050, with the tag and length
/// included.
pub fn der_time(secs: i64) -> Vec<u8> {
    let c = Civil::from_unix(secs);
    let (tag, text) = if (1950..2050).contains(&c.year) {
        (
            0x17,
            format!(
                "{:02}{:02}{:02}{:02}{:02}{:02}Z",
                c.year % 100,
                c.month,
                c.day,
                c.hour,
                c.minute,
                c.second
            ),
        )
    } else {
        (
            0x18,
            format!(
                "{:04}{:02}{:02}{:02}{:02}{:02}Z",
                c.year, c.month, c.day, c.hour, c.minute, c.second
            ),
        )
    };
    let mut out = Vec::with_capacity(text.len() + 2);
    out.push(tag);
    // Both encodings are at most 15 bytes, well inside short-form length.
    out.push(text.len() as u8);
    out.extend_from_slice(text.as_bytes());
    out
}

/// Decodes the contents of an X.509 `Time` given its tag (0x17 UTCTime or
/// 0x18 GeneralizedTime) into Unix seconds. Only the forms RFC 5280 allows
/// are accepted: seconds present, `Z` suffix, no fractions.
pub fn parse_der_time(tag: u8, contents: &[u8]) -> Option<i64> {
    let text = std::str::from_utf8(contents).ok()?;
    let digits = text.strip_suffix('Z')?;
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let num = |s: &str| s.parse::<u32>().ok();
    let (year, rest) = match (tag, digits.len()) {
        (0x17, 12) => {
            let yy = i64::from(num(&digits[..2])?);
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &digits[2..])
        }
        (0x18, 14) => (i64::from(num(&digits[..4])?), &digits[4..]),
        _ => return None,
    };
    Civil {
        year,
        month: num(&rest[0..2])?,
        day: num(&rest[2..4])?,
        hour: num(&rest[4..6])?,
        minute: num(&rest[6..8])?,
        second: num(&rest[8..10])?,
    }
    .to_unix()
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(y) => 29,
        2 => 28,
        _ => 0,
    }
}

// Days since 1970-01-01 to a proleptic Gregorian date, and back. These are
// the well-known era-based conversions (H. Hinnant, "chrono-Compatible
// Low-Level Date Algorithms").
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from(if m > 2 { m - 3 } else { m + 9 });
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_instants_round_trip() {
        for (secs, text) in [
            (0, "1970-01-01T00:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (1_791_715_800, "2026-10-11T10:50:00Z"),
            (2_524_608_000, "2050-01-01T00:00:00Z"),
            (-86_400, "1969-12-31T00:00:00Z"),
        ] {
            assert_eq!(rfc3339(secs), text);
            assert_eq!(Civil::from_unix(secs).to_unix(), Some(secs));
        }
    }

    #[test]
    fn every_day_for_four_centuries_round_trips() {
        let start = days_from_civil(1900, 1, 1);
        for day in start..start + 146_097 {
            let (y, m, d) = civil_from_days(day);
            assert_eq!(days_from_civil(y, m, d), day);
            assert!(d >= 1 && d <= days_in_month(y, m));
        }
    }

    #[test]
    fn der_time_switches_to_generalized_time_in_2050() {
        assert_eq!(der_time(1_791_715_800), b"\x17\x0d261011105000Z".to_vec());
        assert_eq!(der_time(2_524_608_000), b"\x18\x0f20500101000000Z".to_vec());
        for secs in [0, 1_791_715_800, 2_524_607_999, 2_524_608_000] {
            let der = der_time(secs);
            assert_eq!(parse_der_time(der[0], &der[2..]), Some(secs));
        }
    }

    #[test]
    fn malformed_der_times_are_rejected() {
        assert_eq!(parse_der_time(0x17, b"2610111050Z"), None);
        assert_eq!(parse_der_time(0x17, b"261011105000"), None);
        assert_eq!(parse_der_time(0x17, b"261311105000Z"), None);
        assert_eq!(parse_der_time(0x17, b"260230105000Z"), None);
        assert_eq!(parse_der_time(0x18, b"20261011105000.5Z"), None);
        assert_eq!(parse_der_time(0x04, b"261011105000Z"), None);
    }

    #[test]
    fn minute_of_week_counts_from_sunday() {
        // 2026-10-11 is a Sunday; 10:50 is minute 650 of it.
        assert_eq!(utc_minute_of_week(1_791_715_800), 650);
        // Monday 08:00 UTC, the example in docs/policy.md.
        assert_eq!(
            utc_minute_of_week(1_791_715_800 - 650 * 60 + 1440 * 60 + 480 * 60),
            1920
        );
    }
}
