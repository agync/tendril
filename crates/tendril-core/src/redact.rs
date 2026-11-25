//! Redaction of operator input before it reaches an error message, a log line or an exception.
//!
//! Hints, relay URLs and pairing URIs can carry credentials (`user:pass@`), tokens in the path
//! or query, and pairing codes. Errors print only what these helpers return:
//!
//! - [`redact_url`]: `scheme://host[:port]` and nothing after the authority.
//! - [`redact_hint`]: one endpoint hint; anything that does not parse as a URL or a plain
//!   `provider:host:port` hint becomes [`REDACTED`].
//! - [`redact_text`]: a free-text scrubber for messages built elsewhere. A URL ends only at
//!   whitespace or a quote and keeps only a known scheme and its authority; text glued in
//!   front of it is redacted. A quote starts a value that is redacted to the end of the line.
//! - [`redact_json_error`]: the category and position of a JSON error, never its input.
//! - [`redact_host`]: a bare host name or IP literal.
//!
//! Pairing codes (`TND-` in any case, or two or more `XXXX` groups in a `-` joined run, with or
//! without a prefix) never pass any helper. A host outside the plain DNS, IPv4 and IPv6
//! character set and any token holding a backslash are redacted whole.

use url::Url;

/// The placeholder for a removed value.
pub const REDACTED: &str = "<redacted>";

/// `scheme://host[:port]` of `url`; [`REDACTED`] when the host fails [`redact_host`] or the
/// path holds an `@` (a backslash or other separator may have moved userinfo into the host).
/// Userinfo, path, query and fragment are never emitted.
#[must_use]
pub fn redact_url(url: &Url) -> String {
    let Some(host) = url.host_str().filter(|h| is_plain_host(h)) else {
        return REDACTED.to_owned();
    };
    if url.path().contains('@')
        || url.query().is_some_and(|q| q.contains('@'))
        || url.fragment().is_some_and(|f| f.contains('@'))
    {
        return REDACTED.to_owned();
    }
    match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    }
}

/// [`redact_url`] of `raw` parsed with `url::Url`; [`REDACTED`] when it does not parse or holds
/// a backslash (which the parser reads as `/` and so as the end of the authority).
#[must_use]
pub fn redact_url_str(raw: &str) -> String {
    if raw.contains('\\') {
        return REDACTED.to_owned();
    }
    Url::parse(raw.trim()).map_or_else(|_| REDACTED.to_owned(), |u| redact_url(&u))
}

/// `host` when it is a plain DNS name, IPv4 literal or bracketed IPv6 literal (ASCII letters,
/// digits, `.`, `-`, and `:` `[` `]` for IPv6) and not shaped like a pairing code; otherwise
/// [`REDACTED`].
#[must_use]
pub fn redact_host(host: &str) -> String {
    if is_plain_host(host) {
        host.to_owned()
    } else {
        REDACTED.to_owned()
    }
}

fn is_plain_host(host: &str) -> bool {
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
        && !contains_code(host)
}

/// A printable form of one endpoint hint.
///
/// A URL hint (`scheme://...`) keeps `scheme://host[:port]`. A scheme-less hint keeps
/// `provider:host:port` only when the rest is a plain host and port; otherwise only the
/// provider prefix survives (`local:<redacted>`). Hints with `@` or `?` outside a URL, and
/// anything shaped like a pairing code, become [`REDACTED`] whole.
#[must_use]
pub fn redact_hint(hint: &str) -> String {
    let hint = hint.trim();
    if contains_code(hint) {
        return REDACTED.to_owned();
    }
    if hint.contains("://") {
        return redact_url_str(hint);
    }
    if hint.contains(['@', '?']) {
        return REDACTED.to_owned();
    }
    match hint.split_once(':') {
        Some((provider, rest)) if is_provider(provider) => {
            if is_host_port(rest) {
                format!("{provider}:{rest}")
            } else {
                format!("{provider}:{REDACTED}")
            }
        }
        _ => REDACTED.to_owned(),
    }
}

/// Scrubs free text line by line: URLs keep only their authority; pairing codes and tokens
/// with `@`, `\`, a query or a `%` escape are masked; and a quote (`'`, `"` or `` ` ``)
/// starts a value redacted to the end of its line.
#[must_use]
pub fn redact_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let (body, newline) = match line.strip_suffix('\n') {
            Some(b) => (b, "\n"),
            None => (line, ""),
        };
        redact_line(body, &mut out);
        out.push_str(newline);
    }
    out
}

/// `invalid JSON (<category>) at line L column C`: never the offending input.
#[must_use]
pub fn redact_json_error(err: &serde_json::Error) -> String {
    let category = match err.classify() {
        serde_json::error::Category::Io => "io",
        serde_json::error::Category::Syntax => "syntax",
        serde_json::error::Category::Data => "data",
        serde_json::error::Category::Eof => "eof",
    };
    format!(
        "invalid JSON ({category}) at line {} column {}",
        err.line(),
        err.column()
    )
}

fn redact_line(line: &str, out: &mut String) {
    let (head, quoted) = match line.find(['\'', '"', '`']) {
        Some(i) => (&line[..i], Some(&line[i..=i])),
        None => (line, None),
    };
    let mut rest = head;
    while !rest.is_empty() {
        let ws = rest.len() - rest.trim_start().len();
        out.push_str(&rest[..ws]);
        rest = &rest[ws..];
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        redact_token(&rest[..end], out);
        rest = &rest[end..];
    }
    if let Some(q) = quoted {
        out.push_str(q);
        out.push_str(REDACTED);
    }
}

fn redact_token(token: &str, out: &mut String) {
    if token.contains('\\') {
        out.push_str(REDACTED);
        return;
    }
    if let Some(sep) = token.find("://") {
        let start = token[..sep]
            .char_indices()
            .rev()
            .find(|&(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-')))
            .map_or(0, |(i, c)| i + c.len_utf8());
        let (lead, url) = token.split_at(start);
        let scheme = &url[..sep - start];
        if !is_known_scheme(scheme) {
            // The scheme run may be glued to a secret (`s3cretHttps://`).
            out.push_str(REDACTED);
            return;
        }
        // Only opening brackets survive in front of a URL; anything else may be a value.
        if lead.chars().all(|c| matches!(c, '(' | '[' | '<' | '{')) {
            out.push_str(lead);
        } else {
            out.push_str(REDACTED);
        }
        out.push_str(&redact_url_str(url));
        return;
    }
    let bare = token.trim_end_matches(['.', ',', ';', ':', ')', ']', '}', '!']);
    let query = bare.find('?').is_some_and(|i| i + 1 < bare.len());
    // A `%` other than a trailing percent sign is an escape or an IPv6 zone id.
    let escaped = bare.trim_end_matches('%').contains('%');
    if contains_code(token) || token.contains('@') || query || escaped {
        out.push_str(REDACTED);
    } else {
        out.push_str(token);
    }
}

/// `true` when `s` holds a pairing code: `TND-` in any case, or two or more consecutive
/// four-character alphanumeric groups anywhere in a `-` joined run (`tok-ABCD-EFGH` too).
fn contains_code(s: &str) -> bool {
    if s.to_ascii_lowercase().contains("tnd-") {
        return true;
    }
    s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .any(has_code_groups)
}

fn has_code_groups(word: &str) -> bool {
    let mut run = 0;
    for group in word.split('-') {
        if group.len() == 4 && group.bytes().all(|b| b.is_ascii_alphanumeric()) {
            run += 1;
            if run >= 2 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// URL schemes that hints, relay and wake endpoints use; any other scheme run in free text
/// is redacted with its token.
fn is_known_scheme(scheme: &str) -> bool {
    const SCHEMES: [&str; 13] = [
        "http",
        "https",
        "ws",
        "wss",
        "broker+ws",
        "broker+wss",
        "overlay",
        "iroh",
        "tcp",
        "udp",
        "quic",
        "wt",
        "tendril",
    ];
    SCHEMES.iter().any(|s| s.eq_ignore_ascii_case(scheme))
}

fn is_provider(s: &str) -> bool {
    const PROVIDERS: &[&str] = &["direct", "local", "overlay", "relay", "broker", "p2p"];
    PROVIDERS.contains(&s)
}

/// `host:port` with a plain DNS name or IPv4 host, or `[v6]:port`.
fn is_host_port(s: &str) -> bool {
    let Some((host, port)) = s.rsplit_once(':') else {
        return false;
    };
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if let Some(v6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return !v6.is_empty()
            && v6
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.');
    }
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean(out: &str, secrets: &[&str]) {
        for s in secrets {
            assert!(
                !out.to_ascii_lowercase().contains(&s.to_ascii_lowercase()),
                "{s:?} leaked in {out:?}"
            );
        }
    }

    #[test]
    fn urls_keep_only_scheme_host_and_port() {
        let cases = [
            ("https://user:pw;x@host/", "https://host"),
            ("https://u:p@h,x", REDACTED),
            (
                "wss://u:s3cret@relay:8443/v1/relay?tok=a",
                "wss://relay:8443",
            ),
            ("http://[::1]:9/x#frag", "http://[::1]:9"),
            ("not a url", REDACTED),
            ("mailto:someone", REDACTED),
            ("https://TND-ABCD-EFGH.example/", REDACTED),
        ];
        for (raw, want) in cases {
            assert_eq!(redact_url_str(raw), want, "{raw}");
        }
        clean(
            &redact_url_str("https://user:pw;x@host/"),
            &["user", "pw", ";x"],
        );
    }

    #[test]
    fn hints_never_pass_credentials_paths_or_codes() {
        let cases = [
            ("direct:192.168.1.5:9100", "direct:192.168.1.5:9100"),
            ("direct:[fd00::5]:9100", "direct:[fd00::5]:9100"),
            ("overlay://100.64.0.2:9100", "overlay://100.64.0.2:9100"),
            (
                "wss://u:s3cret@relay.example/v1/relay?tok=x#pub",
                "wss://relay.example",
            ),
            ("local:/run/app/sock", "local:<redacted>"),
            ("direct:user:pw@host:9100", REDACTED),
            ("direct:host:9100?token=x", REDACTED),
            (
                "wt://192.168.1.10:4433/secret?certhash=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "wt://192.168.1.10:4433",
            ),
            (
                "wt://[::1]:4433/?certhash=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "wt://[::1]:4433",
            ),
            ("wt://TND-ABCD-EFGH:4433/", REDACTED),
            ("tnd-abcd-efgh", REDACTED),
            ("direct:TnD-ABCD-EFGH-JKLM:1", REDACTED),
            ("ABCD-EFGH-JKLM", REDACTED),
            ("x's3cr3t", REDACTED),
            ("s3cretuser:pa55word", REDACTED),
            ("s3cretuser:host:9100", REDACTED),
            ("p2p:peer-id-xyz", "p2p:<redacted>"),
        ];
        for (raw, want) in cases {
            assert_eq!(redact_hint(raw), want, "{raw}");
        }
    }

    #[test]
    fn preparsed_url_with_at_in_query_or_fragment_is_redacted() {
        for raw in [
            "wss://host/?a=b@c",
            "wss://host/#f@g",
            "wss://host/p?x=u:p@h",
        ] {
            let url = Url::parse(raw).expect("parses");
            assert_eq!(redact_url(&url), REDACTED, "{raw}");
        }
    }

    #[test]
    fn text_scrubber_ends_urls_only_at_whitespace_or_quotes() {
        let msg = "dial https://user:pw;x@host/ and https://u:p@h,x failed";
        let out = redact_text(msg);
        assert_eq!(out, "dial https://host and <redacted> failed");

        let out = redact_text("relay wss://u:s3cret@relay/v1/relay?tok=a b closed");
        clean(&out, &["s3cret", "u:", "tok", "/v1"]);
        assert!(out.starts_with("relay wss://relay "), "{out}");

        let out = redact_text("bad code tnd-abcd-efgh-jklm, retry\nnext TND-ABCD-EFGH");
        clean(&out, &["abcd", "efgh", "jklm"]);
        assert_eq!(out, "bad code <redacted> retry\nnext <redacted>");

        let out = redact_text("invalid endpoint x's3cr3t' trailing\nline two");
        clean(&out, &["s3cr3t", "trailing"]);
        assert_eq!(out, "invalid endpoint x'<redacted>\nline two");

        let out = redact_text("unknown parameter \"a,b;c=secret\" in uri");
        clean(&out, &["a,b;c", "secret", "in uri"]);

        let out = redact_text("token user:pw@host:9100 and q=x?tok=1 ok?");
        clean(&out, &["pw", "tok=1"]);
        assert!(out.ends_with(" ok?"), "{out}");

        let out = redact_text("(https://u:p@host:1/p?q),next");
        assert_eq!(out, "(https://host:1");

        let wt_out = redact_text(
            "dial wt://192.168.1.10:4433/secret?certhash=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA failed",
        );
        assert_eq!(wt_out, "dial wt://192.168.1.10:4433 failed");
    }

    #[test]
    fn text_before_a_url_in_one_token_is_redacted() {
        for (msg, secrets) in [
            ("tok=s3cret:https://h/", &["s3cret", "tok"][..]),
            ("a?k=v https://h/", &["k=v"][..]),
            ("key:s3cret@https://h/x", &["s3cret", "key"][..]),
            ("s3cretHttps://h/", &["s3cret"][..]),
            ("x=1;https://u:p@h/", &["x=1", "u:p"][..]),
        ] {
            let out = redact_text(msg);
            clean(&out, secrets);
        }
        assert_eq!(redact_text("tok=s3cret:https://h/"), "<redacted>https://h");
        assert_eq!(redact_text("[https://h:9/p]"), "[https://h:9");
    }

    #[test]
    fn percent_encoded_and_mixed_case_code_hosts_are_redacted() {
        for raw in [
            "x://TND%2DABCD%2DEFGH",
            "x://tNd%2dabcd%2defgh",
            "wss://%54ND-ABCD-EFGH/",
            "https://TnD-AbCd-EfGh/",
            "overlay://abcd%2Defgh:9100",
        ] {
            assert_eq!(redact_url_str(raw), REDACTED, "{raw}");
            assert_eq!(redact_hint(raw), REDACTED, "{raw}");
            clean(
                &redact_text(&format!("dial {raw} now")),
                &["abcd", "%2d", "%54"],
            );
        }
    }

    #[test]
    fn multibyte_text_before_a_scheme_never_panics() {
        for (msg, secrets) in [
            ("\u{2014}https://host/x", &["/x"][..]),
            ("\u{201c}https://u:p@host\u{201d}", &["u:p"][..]),
            ("\u{e9}https://host", &[][..]),
            (
                "\u{1f600}s3cret\u{e9}https://u:pw@host/",
                &["s3cret", "pw"][..],
            ),
        ] {
            let out = redact_text(msg);
            clean(&out, secrets);
        }
        assert_eq!(redact_text("\u{e9}https://host"), "<redacted>https://host");
    }

    /// Adversarial inputs: every helper must return without panicking and without any secret
    /// substring, as the whole input and glued into free text.
    #[test]
    fn adversarial_inputs_never_leak_or_panic() {
        let cases: &[(&str, &[&str])] = &[
            // WHATWG reads `\` as `/` for special schemes: the userinfo becomes the host.
            (
                "https://s3cret_user\\pass@relay.example/",
                &["s3cret", "pass"],
            ),
            (
                "https://s3cretuser\\pa55@relay.example/",
                &["s3cret", "pa55"],
            ),
            ("wss://relay.example\\s3cret@evil/", &["s3cret", "evil"]),
            ("x\\s3cret", &["s3cret"]),
            // Characters URL hosts allow but a host never needs.
            (
                "(https://u:p@host),token=s3cret",
                &["s3cret", "token", "u:p"],
            ),
            ("https://host;token=s3cret", &["s3cret", "token"]),
            ("iroh://node;secret=1", &["secret", "node;"]),
            ("https://h,s3cret/", &["s3cret"]),
            ("https://h=s3cret:9/", &["s3cret"]),
            ("https://(s3cret)/", &["s3cret"]),
            ("wss://relay!s3cret$/", &["s3cret"]),
            ("https://relay_s3cret.example/", &["s3cret"]),
            // Unicode glued in front of the scheme.
            ("\u{e9}s3cret\u{e9}https://u:pw@host/", &["s3cret", "pw"]),
            ("\u{201c}https://u:s3cret@host\u{201d}", &["s3cret"]),
            ("s3cret\u{2014}https://host", &["s3cret"]),
            // Pairing codes behind a prefix.
            ("tok-ABCD-EFGH", &["abcd", "efgh"]),
            ("code-ABCD-EFGH-JKLM", &["abcd", "efgh", "jklm"]),
            ("x-y-abcd-efgh-z", &["abcd", "efgh"]),
            ("https://x-abcd-efgh.example/", &["abcd", "efgh"]),
            ("direct:pre-ABCD-EFGH:9100", &["abcd", "efgh"]),
            // IPv6 literals with zone ids.
            ("http://[fe80::1%25s3cret]:9/", &["s3cret"]),
            ("http://[fe80::1%s3cret]:9/", &["s3cret"]),
            ("direct:[fe80::1%s3cret]:9100", &["s3cret"]),
            ("[fe80::1%s3cret]:9100", &["s3cret"]),
            // `@` inside the password.
            ("https://u:pa@ss3cret@host/", &["ss3cret", "pa@"]),
            ("wss://user@s3cret@relay/", &["s3cret", "user"]),
            ("direct:u:p@s3cret@host:1", &["s3cret"]),
            // Percent-encoded everything.
            (
                "https://%73%33%63%72%65%74:%70%77@host/%73%33",
                &["%73", "%70", "s3cret"],
            ),
            ("iroh://%73%33%63%72%65%74", &["%73", "s3cret"]),
            ("wss://h/%2F%2Fs3cret%40x", &["s3cret", "%2f"]),
            ("direct:%73%33cret:9100", &["%73", "s3cret"]),
            ("https://%40s3cret@host/", &["%40", "s3cret"]),
        ];
        for (raw, secrets) in cases {
            for out in [
                redact_text(raw),
                redact_text(&format!("dial {raw} failed")),
                redact_text(&format!("dial ({raw}), retry")),
                redact_hint(raw),
                redact_url_str(raw),
            ] {
                clean(&out, secrets);
            }
            if let Ok(url) = Url::parse(raw) {
                clean(&redact_url(&url), secrets);
            }
        }
    }

    #[test]
    fn hosts_outside_the_plain_charset_are_redacted() {
        assert_eq!(redact_host("relay.example"), "relay.example");
        assert_eq!(redact_host("[fd00::5]"), "[fd00::5]");
        assert_eq!(redact_host("10.0.0.5"), "10.0.0.5");
        for host in [
            "",
            "a;b",
            "h,x",
            "s3cret_user",
            "x%41",
            "tok-ABCD-EFGH",
            "\u{e9}",
        ] {
            assert_eq!(redact_host(host), REDACTED, "{host}");
        }
    }

    #[test]
    fn json_errors_report_position_only() {
        let err = serde_json::from_str::<Vec<u32>>("[\"s3cr3t-value\"]").unwrap_err();
        let out = redact_json_error(&err);
        clean(&out, &["s3cr3t"]);
        assert_eq!(out, "invalid JSON (data) at line 1 column 15");
    }
}
