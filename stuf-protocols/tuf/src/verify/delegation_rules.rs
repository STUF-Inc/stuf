//! Shared TUF delegation path matching.
//!
//! This module deliberately uses no std, alloc, Vec or heap storage.

/// Match '*' and '?' inside individual path components.
/// Wildcards cannot cross a '/' separator.
///
/// The exact pattern grammar must be checked against TUF
/// conformance fixtures before production use.
pub(crate) fn matches_path_pattern(pattern: &str, path: &str) -> bool {
    let mut patterns = pattern.split('/');
    let mut components = path.split('/');

    loop {
        match (patterns.next(), components.next()) {
            (Some(p), Some(t)) if matches_component(p, t) => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}

fn matches_component(pattern: &str, text: &str) -> bool {
    let mut p = pattern;
    let mut t = text;
    let mut star_pattern: Option<&str> = None;
    let mut star_text: Option<&str> = None;

    while !t.is_empty() {
        if let Some(rest) = p.strip_prefix('*') {
            star_pattern = Some(rest);
            star_text = Some(t);
            p = rest;
            continue;
        }

        if let Some(pc) = p.chars().next() {
            let tc = t.chars().next().unwrap();

            if pc == '?' || pc == tc {
                p = &p[pc.len_utf8()..];
                t = &t[tc.len_utf8()..];
                continue;
            }
        }

        if let (Some(after_star), Some(previous_text)) = (star_pattern, star_text) {
            if previous_text.is_empty() {
                return false;
            }

            let ch = previous_text.chars().next().unwrap();
            let rest = &previous_text[ch.len_utf8()..];
            star_text = Some(rest);
            p = after_star;
            t = rest;
        } else {
            return false;
        }
    }

    p.chars().all(|ch| ch == '*')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_and_wildcard_matches() {
        assert!(matches_path_pattern("sensors/*", "sensors/temperature.bin"));
        assert!(!matches_path_pattern(
            "sensors/*",
            "sensors/subdir/firmware.bin"
        ));
        assert!(matches_path_pattern("fw-?.bin", "fw-a.bin"));
        assert!(!matches_path_pattern("fw-?.bin", "fw-ab.bin"));
    }

    #[test]
    fn repeated_stars_and_unicode() {
        assert!(matches_path_pattern("a*b*c", "axbyc"));
        assert!(matches_path_pattern("a**c", "abc"));
        assert!(matches_path_pattern("*.bin", ".bin"));
        assert!(matches_path_pattern("?.bin", "é.bin"));
        assert!(!matches_path_pattern("?.bin", "éé.bin"));
        assert!(!matches_path_pattern("a/b", "a/b/c"));
    }
}
