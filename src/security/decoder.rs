use std::collections::{HashSet, VecDeque};

use base64::{Engine as _, engine::general_purpose};
use percent_encoding::percent_decode_str;
use serde_json::Value;
use unicode_normalization::UnicodeNormalization;

use crate::config::DecodingConfig;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TextCandidate {
    pub path: String,
    pub text: String,
    pub decoded: bool,
}

pub fn extract_text_candidates(arguments: &Value, decoding: &DecodingConfig) -> Vec<TextCandidate> {
    let mut out = Vec::new();
    walk_value(arguments, "$", decoding, &mut out);
    out
}

fn walk_value(value: &Value, path: &str, decoding: &DecodingConfig, out: &mut Vec<TextCandidate>) {
    match value {
        Value::String(text) => {
            for candidate in decode_variants(text, decoding) {
                out.push(TextCandidate {
                    path: path.to_owned(),
                    text: candidate.0,
                    decoded: candidate.1,
                });
            }
        }
        Value::Array(values) => {
            for (idx, item) in values.iter().enumerate() {
                let next_path = format!("{path}[{idx}]");
                walk_value(item, &next_path, decoding, out);
            }
        }
        Value::Object(map) => {
            for (key, val) in map {
                let next_path = format!("{path}.{key}");
                walk_value(val, &next_path, decoding, out);
            }
        }
        _ => {}
    }
}

fn decode_variants(source: &str, decoding: &DecodingConfig) -> Vec<(String, bool)> {
    let normalized = source.nfkc().collect::<String>();

    let mut queue = VecDeque::new();
    queue.push_back((normalized, 0usize, false));

    let mut visited = HashSet::new();
    let mut output = Vec::new();

    while let Some((value, depth, decoded)) = queue.pop_front() {
        if value.len() > decoding.max_decode_bytes {
            continue;
        }
        if !visited.insert(value.clone()) {
            continue;
        }

        output.push((value.clone(), decoded));

        if depth >= decoding.max_decode_depth {
            continue;
        }

        if let Some(next) = json_unescape(&value) {
            queue.push_back((next, depth + 1, true));
        }

        if let Some(next) = url_decode(&value) {
            queue.push_back((next, depth + 1, true));
        }

        if let Some(next) = decode_base64(&value, decoding.max_decode_bytes) {
            queue.push_back((next, depth + 1, true));
        }
    }

    output
}

fn json_unescape(input: &str) -> Option<String> {
    if !input.contains('\\') {
        return None;
    }

    let quoted = serde_json::to_string(input).ok()?;
    let unescaped = serde_json::from_str::<String>(&quoted).ok()?;
    let converted = decode_json_escape_sequences(&unescaped)?;
    if converted == input {
        None
    } else {
        Some(converted)
    }
}

fn decode_json_escape_sequences(input: &str) -> Option<String> {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut changed = false;

    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }

        let Some(next) = chars.next() else {
            out.push(ch);
            continue;
        };

        changed = true;
        match next {
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'b' => out.push('\u{0008}'),
            'f' => out.push('\u{000C}'),
            '\\' => out.push('\\'),
            '/' => out.push('/'),
            '"' => out.push('"'),
            'u' => {
                let code = take_hex4(&mut chars)?;
                let scalar = u16::from_str_radix(&code, 16).ok()?;
                let c = char::from_u32(u32::from(scalar))?;
                out.push(c);
            }
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }

    if changed { Some(out) } else { None }
}

fn take_hex4(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<String> {
    let mut hex = String::with_capacity(4);
    for _ in 0..4 {
        let c = chars.next()?;
        if !c.is_ascii_hexdigit() {
            return None;
        }
        hex.push(c);
    }
    Some(hex)
}

fn url_decode(input: &str) -> Option<String> {
    if !input.contains('%') {
        return None;
    }
    let decoded = percent_decode_str(input).decode_utf8().ok()?.to_string();
    if decoded == input {
        None
    } else {
        Some(decoded)
    }
}

fn decode_base64(input: &str, max_decode_bytes: usize) -> Option<String> {
    if input.len() < 16 || input.len() > max_decode_bytes {
        return None;
    }
    if !input
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | '-' | '_'))
    {
        return None;
    }

    let candidates = [
        general_purpose::STANDARD.decode(input),
        general_purpose::STANDARD_NO_PAD.decode(input),
        general_purpose::URL_SAFE.decode(input),
        general_purpose::URL_SAFE_NO_PAD.decode(input),
    ];

    for decoded in candidates.into_iter().flatten() {
        if decoded.is_empty() || decoded.len() > max_decode_bytes {
            continue;
        }
        let Ok(text) = String::from_utf8(decoded) else {
            continue;
        };

        let printable_count = text
            .chars()
            .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
            .count();
        let ratio = printable_count as f64 / text.chars().count().max(1) as f64;
        if ratio < 0.8 {
            continue;
        }

        return Some(text);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_base64_and_url_variants() {
        let input = json!({
            "raw": "hello%20world",
            "encoded": "QUtJQTEyMzQ1Njc4OTBBQkNERQ=="
        });
        let cfg = DecodingConfig {
            max_decode_depth: 3,
            max_decode_bytes: 1024,
        };
        let items = extract_text_candidates(&input, &cfg);
        let texts: HashSet<_> = items.iter().map(|c| c.text.as_str()).collect();
        assert!(texts.contains("hello world"));
        assert!(texts.contains("AKIA1234567890ABCDE"));
    }
}
