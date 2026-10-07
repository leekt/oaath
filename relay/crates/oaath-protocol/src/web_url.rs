//! WHATWG URL rules for application origins.

use url::Url;

use crate::capture::utf16_len;

const MAX_URL_LENGTH: usize = 2_048;

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
