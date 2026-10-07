//! WHATWG URL rules shared by bootstrap redirect URIs and application origins.

use url::Url;

use crate::capture::utf16_len;

const MAX_URL_LENGTH: usize = 2_048;
const LOOPBACK_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "[::1]"];

fn parse(value: &str) -> Option<Url> {
    if utf16_len(value) > MAX_URL_LENGTH {
        return None;
    }
    Url::parse(value).ok()
}

/// JavaScript `URL.search` and `URL.hash` read an empty component as `""`.
fn has_query_or_fragment(url: &Url) -> bool {
    !url.query().unwrap_or("").is_empty() || !url.fragment().unwrap_or("").is_empty()
}

fn has_credentials(url: &Url) -> bool {
    !url.username().is_empty() || !url.password().unwrap_or("").is_empty()
}

/// `captureCanonicalHttpsUrl` with a path allowed: rejects non-canonical
/// input, never rewrites it.
pub(crate) fn canonical_https_url(value: &str) -> Option<&str> {
    let parsed = parse(value)?;
    let loopback = parsed.scheme() == "http"
        && parsed.host_str().is_some_and(|host| {
            let host = if host == "::1" { "[::1]" } else { host };
            LOOPBACK_HOSTS.contains(&host)
        });
    if (parsed.scheme() != "https" && !loopback)
        || has_credentials(&parsed)
        || has_query_or_fragment(&parsed)
    {
        return None;
    }
    let origin = parsed.origin().ascii_serialization();
    let canonical = if parsed.path() == "/" {
        origin
    } else {
        format!("{origin}{}", parsed.path())
    };
    (value == canonical && !canonical.ends_with('/')).then_some(value)
}

/// The grant application `origin`: an http(s) origin, normalized as `URL.origin`.
pub(crate) fn http_origin(value: &str) -> Option<String> {
    let parsed = parse(value)?;
    if (parsed.scheme() != "https" && parsed.scheme() != "http")
        || has_credentials(&parsed)
        || parsed.path() != "/"
        || has_query_or_fragment(&parsed)
    {
        return None;
    }
    let origin = parsed.origin().ascii_serialization();
    (origin != "null").then_some(origin)
}
